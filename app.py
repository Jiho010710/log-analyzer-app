import streamlit as st
import pandas as pd
from transformers import pipeline
import torch  # 추가: dtype 사용 위해
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import json
import io
import subprocess
import warnings
from evtx import PyEvtxParser
import xmltodict

warnings.filterwarnings("ignore")

# LLM 요약기 (dtype=torch.float32로 수정)
@st.cache_resource
def load_summarizer():
    return pipeline("summarization", model="eenzeenee/t5-small-korean-summarization", device="cpu", truncation=True, dtype=torch.float32)

summarizer = load_summarizer()

# ES 연결 (호스트/사용자 입력, 비밀번호는 secrets 사용)
st.sidebar.title("ES 설정")
es_host = st.sidebar.text_input("ES 호스트", "http://3.38.65.230:9200")
es_user = st.sidebar.text_input("ES 사용자", "elastic")
es_pass = st.secrets.get("ES_PASSWORD", "")  # Streamlit secrets에서 불러옴 (설정 안 하면 빈 문자열)

if not es_pass:
    st.sidebar.error("ES_PASSWORD secrets를 설정하세요. 앱 설정 > Secrets에서 추가.")
    st.stop()

es = Elasticsearch(hosts=[es_host], basic_auth=(es_user, es_pass), request_timeout=30)

# 앱 타이틀
st.title("로그 분석 파이프라인 웹 앱 (POC)")

# 1. 로그 연동 (EVTX 업로드 & ES 인덱싱)
evtx_file = st.file_uploader("EVTX 로그 업로드", type="evtx")
if evtx_file and st.button("ES에 인덱싱"):
    with st.spinner("EVTX 파싱 & 인덱싱 중..."):
        parser = PyEvtxParser(evtx_file)
        for record in parser.records_json():
            log_data = json.loads(record['data'])
            event = xmltodict.parse(log_data['Event'])['Event']
            es.index(index=".internal.alerts-security.alerts*", body=event)
    st.success("인덱싱 완료!")

# 2. Custom Rule 필터링 (ES 쿼리)
st.subheader("Custom Rule 필터링")
query_days = st.number_input("시간 범위 (일)", value=90)
query_size = st.number_input("가져올 로그 수", value=100, max_value=10000)
if st.button("로그 가져오기"):
    query = {
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{query_days}d"}}}]}},
        "size": query_size
    }
    try:
        res = es.search(index=".internal.alerts-security.alerts*", body=query)
        logs = [hit['_source'] for hit in res['hits']['hits']]
        df = pd.DataFrame(logs)
        st.success(f"총 {len(df)}개 로그 가져옴")
        st.dataframe(df.head())
    except Exception as e:
        st.error(f"ES 쿼리 에러: {e}")

# 3. ML 필터
if 'df' in locals() and st.button("ML 필터링"):
    # GrantedAccess 변환
    def hex_to_int(value):
        if pd.isna(value) or str(value).strip() in ['-', '']:
            return 0
        try:
            value_str = str(value).strip()
            return int(value_str, 16) if value_str.startswith('0x') else int(value_str)
        except ValueError:
            return 0

    features = []
    if 'winlog.event_id' in df.columns: features.append('winlog.event_id')
    if 'winlog.event_data.GrantedAccess' in df.columns: features.append('winlog.event_data.GrantedAccess')
    if 'kibana.alert.risk_score' in df.columns: features.append('kibana.alert.risk_score')

    if not features:
        st.error("숫자 피처 없음")
    else:
        for col in features:
            if col == 'winlog.event_data.GrantedAccess':
                df[col] = df[col].apply(hex_to_int)
            else:
                df[col] = pd.to_numeric(df[col], errors='coerce')
        df_features = df[features].fillna(0)

        model = IsolationForest(contamination='auto', random_state=42)
        scores = model.fit_predict(df_features)
        df['ml_score'] = (1 - scores) / 2

        def remap_level(row):
            severity = row.get('kibana.alert.severity', 'low').lower()
            if row['ml_score'] > 0.7 or severity in ['high', 'critical']:
                return 'high'
            elif 0.3 < row['ml_score'] <= 0.7 or severity == 'medium':
                return 'medium'
            else:
                return 'low'
        df['new_level'] = df.apply(remap_level, axis=1)
        st.success("ML 필터 완료!")
        st.dataframe(df)
        df.to_csv('ml_filtered_logs.csv', index=False, encoding='utf-8-sig')

# 4. SBOM 취약점 스캔
st.subheader("SBOM 취약점 스캔")
sbom_target = st.text_input("SBOM 대상 (e.g., ubuntu:latest)", "ubuntu:latest")
if st.button("SBOM 스캔"):
    with st.spinner("Trivy 스캔 중..."):
        try:
            sbom_output = subprocess.run(["trivy", "image", "--format", "json", sbom_target], capture_output=True, text=True)
            vulns = json.loads(sbom_output.stdout)
            vulns_str = json.dumps(vulns.get('Results', [{}])[0].get('Vulnerabilities', 'No vulnerabilities found'), ensure_ascii=False)
            st.json(vulns)
            if 'df' in locals():
                df['vulns'] = vulns_str
        except Exception as e:
            st.error(f"Trivy 에러: {e}. Trivy 설치 확인하세요.")

# 5. LLM 요약 & PDF
if 'df' in locals() and st.button("LLM 요약 & PDF 생성"):
    with st.spinner("요약 중..."):
        for index, row in df.iterrows():
            level = row['new_level']
            log_text = row.get('message', str(row))
            action = '관찰' if level == 'low' else '경고' if level == 'medium' else '격리'
            vulns_str = row.get('vulns', 'No vulnerabilities found')
            prompt = f"이 로그를 간결하게 요약하고, 잠재적 위협, 취약점 분석, 그리고 대응 방안을 제안하세요: {log_text}. 취약점: {vulns_str}. 레벨: {level} - 액션: {action}."
            input_length = len(prompt.split())
            effective_max = max(50, min(200, input_length // 2))
            summary = summarizer(prompt, max_length=effective_max, min_length=50, do_sample=False, max_new_tokens=None)[0]['summary_text']
            df.at[index, 'summary'] = summary

    st.success("요약 완료!")
    st.dataframe(df)

    # PDF 생성
    pdf_buffer = io.BytesIO()
    font_path = './gulim.ttc'  # repo에 업로드된 폰트 사용
    pdfmetrics.registerFont(TTFont('Gulim', font_path))

    doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontName='Gulim', fontSize=10, wordWrap='CJK')

    elements = [Paragraph("로그 분석 보고서", styles['Title'])]

    data = [['로그 ID', '메시지 (짧게)', '레벨 | ML Score', '요약']]
    for index, row in df.iterrows():
        msg_short = Paragraph(row.get('message', 'N/A')[:50] + '...', body_style)
        level_score = Paragraph(f"{row['new_level']} | {row['ml_score']}", body_style)
        summary_para = Paragraph(row['summary'], body_style)
        data.append([Paragraph(str(index), body_style), msg_short, level_score, summary_para])

    col_widths = [50, 150, 100, 300]
    table = Table(data, colWidths=col_widths)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Gulim'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(table)
    doc.build(elements)

    pdf_buffer.seek(0)
    st.download_button("PDF 다운로드", pdf_buffer, file_name="report.pdf", mime="application/pdf")
