import streamlit as st
import pandas as pd
from openai import OpenAI  # GPT 사용
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

# GPT 설정 (API 키 secrets 사용)
openai_client = OpenAI(api_key=st.secrets["OPENAI_API_KEY"])

# ES 연결 (사용자 입력 호스트/인증, form으로 감싸서 오류 방지)
with st.sidebar.form(key="es_config_form"):
    st.title("ES 설정")
    es_host = st.text_input("ES 호스트", "http://3.38.65.230:9200")
    es_user = st.text_input("ES 사용자", "elastic")
    es_pass = st.text_input("ES 비밀번호", type="password")  # 기본값 제거, type=password
    submit_es = st.form_submit_button("ES 연결")

if submit_es:
    es = Elasticsearch(hosts=[es_host], basic_auth=(es_user, es_pass), request_timeout=120)  # 타임아웃 증가
    st.session_state.es = es  # 세션에 ES 연결 저장
    st.sidebar.success("ES 연결 완료!")

# ES 연결 확인 (세션에서 불러옴)
if 'es' not in st.session_state:
    st.sidebar.info("ES 설정을 입력하고 연결하세요.")
    st.stop()
es = st.session_state.es

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
        st.session_state.df = pd.DataFrame(logs) # 세션에 저장
        # 간단 출력: 필요한 컬럼만 (new_level 없으면 생략)
        columns_to_show = []
        if 'new_level' in st.session_state.df.columns: columns_to_show.append('new_level')
        if 'message' in st.session_state.df.columns: columns_to_show.append('message')
        if 'winlog.user.name' in st.session_state.df.columns: columns_to_show.append('winlog.user.name')
        if 'ml_score' in st.session_state.df.columns: columns_to_show.append('ml_score')
        simplified_df = st.session_state.df[columns_to_show] if columns_to_show else st.session_state.df.head()
        simplified_df['winlog.user.name'] = simplified_df.get('winlog.user.name', 'N/A')
        st.success(f"총 {len(st.session_state.df)}개 로그 가져옴")
        st.dataframe(simplified_df) # 간단 테이블 표시
    except Exception as e:
        st.error(f"ES 쿼리 에러: {e}")

# 3. ML 필터 (전체 df 넘김, 의심(high/medium)만 출력)
if 'df' in st.session_state and st.button("ML 필터링"):
    df = st.session_state.df.copy() # 세션에서 복사
    try:
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
            raise ValueError("숫자 피처 없음 – 데이터 컬럼 확인하세요 (winlog.event_id 등).")
        for col in features:
            if col == 'winlog.event_data.GrantedAccess':
                df[col] = df[col].apply(hex_to_int)
            else:
                df[col] = pd.to_numeric(df[col], errors='coerce')
        df_features = df[features].fillna(0)
        model = IsolationForest(contamination='auto', random_state=42)
        scores = model.fit_predict(df_features)
        df['ml_score'] = ((1 - scores) / 2) * 9 + 1  # 1~10점으로 스케일링
        def remap_level(row):
            severity = row.get('kibana.alert.severity', 'low').lower()
            if row['ml_score'] > 7 or severity in ['high', 'critical']:
                return 'high'
            elif 3 < row['ml_score'] <= 7 or severity == 'medium':
                return 'medium'
            else:
                return 'low'
        df['new_level'] = df.apply(remap_level, axis=1)
        st.session_state.df = df # 업데이트 저장
        st.success("ML 필터 완료!")
      
        # 의심(high/medium)만 출력
        suspicious_df = df[df['new_level'].isin(['medium', 'high'])]
        simplified_df = suspicious_df[['new_level', 'message', 'winlog.user.name', 'ml_score']] if 'winlog.user.name' in suspicious_df.columns else suspicious_df[['new_level', 'message', 'ml_score']]
        simplified_df['winlog.user.name'] = simplified_df.get('winlog.user.name', 'N/A') # 사용자 없으면 N/A
        st.dataframe(simplified_df) # 간단 테이블 표시
        df.to_csv('ml_filtered_logs.csv', index=False, encoding='utf-8-sig')
    except Exception as e:
        st.error(f"ML 필터링 에러: {e}. 데이터 컬럼 확인하거나 쿼리 범위 좁혀보세요.")

# 4. SBOM 취약점 스캔 (Syft + Grype, 의심 로그 기반)
st.subheader("SBOM 취약점 스캔")
sbom_target = st.text_input("SBOM 대상 (e.g., ubuntu:latest)", "ubuntu:latest")
if st.button("SBOM 스캔"):
    with st.spinner("Syft & Grype 스캔 중..."):
        try:
            # Syft로 SBOM 생성
            subprocess.run(["syft", "scan", sbom_target, "-o", "spdx-json=sbom.json"], check=True)
            # Grype로 취약점 스캔
            grype_output = subprocess.run(["grype", "sbom:sbom.json", "-o", "json"], capture_output=True, text=True)
            vulns = json.loads(grype_output.stdout)
            vulns_str = json.dumps(vulns.get('matches', 'No vulnerabilities found'), ensure_ascii=False)
            st.json(vulns)
            if 'df' in st.session_state:
                df = st.session_state.df
                df['vulns'] = vulns_str
                st.session_state.df = df # 업데이트 저장
        except Exception as e:
            st.error(f"SBOM 에러: {e}. Syft/Grype 설치 확인하세요.")

# 5. LLM 요약 & PDF (GPT 사용, 의심 로그 기반 보고서)
if 'df' in st.session_state and st.button("LLM 요약 & PDF 생성"):
    df = st.session_state.df.copy() # 복사 사용
    suspicious_df = df[df['new_level'].isin(['medium', 'high'])]  # 의심 로그만
    with st.spinner("요약 중..."):
        for index, row in suspicious_df.iterrows():
            level = row['new_level']
            log_text = row.get('message', str(row))
            action = '관찰' if level == 'low' else '경고' if level == 'medium' else '격리'
            vulns_str = row.get('vulns', 'No vulnerabilities found')
            prompt = f"이 로그를 간결하게 요약하고, 잠재적 위협, 취약점 분석, 그리고 대응 방안을 제안하세요: {log_text}. 취약점: {vulns_str}. 레벨: {level} - 액션: {action}."
            response = openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}]
            )
            summary = response.choices[0].message.content
            suspicious_df.at[index, 'summary'] = summary

    st.session_state.df = suspicious_df  # 의심 로그만 업데이트 (전체 df 대신)
    st.success("요약 완료!")
    # 간단 출력: new_level, message, 사용자, ml_score, summary
    simplified_df = suspicious_df[['new_level', 'message', 'winlog.user.name', 'ml_score', 'summary']] if 'winlog.user.name' in suspicious_df.columns else suspicious_df[['new_level', 'message', 'ml_score', 'summary']]
    simplified_df['winlog.user.name'] = simplified_df.get('winlog.user.name', 'N/A') # 사용자 없으면 N/A
    st.dataframe(simplified_df) # 간단 테이블 표시
    # PDF 생성 (의심 로그 기반 보고서)
    pdf_buffer = io.BytesIO()
    font_path = './gulim.ttc' # repo에 업로드된 폰트 사용
    pdfmetrics.registerFont(TTFont('Gulim', font_path))
    doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontName='Gulim', fontSize=10, wordWrap='CJK')
    elements = [Paragraph("로그 분석 보고서 (의심 로그만)", styles['Title'])]
    data = [['로그 ID', '메시지 (짧게)', '레벨 | ML Score', '요약']]
    for index, row in suspicious_df.iterrows():
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
