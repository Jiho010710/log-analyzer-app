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

# 사이드바에 추가 옵션 (있어보이게: 로그 검색 필터)
with st.sidebar:
    st.title("추가 옵션")
    search_term = st.text_input("로그 검색 (메시지 내 키워드)", "")
    min_ml_score = st.slider("최소 ML 점수 필터", 0.0, 10.0, 0.0)

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

# 2. 모든 로그 가져오기 (시간 범위 없이, 최대 10000개 가져오고 페이징 처리)
st.subheader("로그 가져오기")
if st.button("모든 로그 가져오기"):
    query = {
        "query": {"match_all": {}},
        "size": 10000,  # 최대 크기
        "sort": [{"@timestamp": {"order": "desc"}}]  # 최근 순 정렬
    }
    try:
        res = es.search(index=".internal.alerts-security.alerts*", body=query)
        logs = [hit['_source'] for hit in res['hits']['hits']]
        df = pd.DataFrame(logs)
        
        # 초기 level 설정 (kibana.alert.severity가 있으면 사용, 없으면 'low'로)
        if 'kibana.alert.severity' in df.columns:
            df['level'] = df['kibana.alert.severity'].str.lower()
        else:
            df['level'] = 'low'
        
        st.session_state.df = df  # 세션에 저장
        st.session_state.filtered_df = df.copy()  # 초기 필터링 df
        st.session_state.page = 0  # 페이징 초기화
        st.success(f"총 {len(df)}개 로그 가져옴")
    except Exception as e:
        st.error(f"ES 쿼리 에러: {e}")

# 페이징 함수 (한 페이지 30개)
def display_paginated_df(df, page_size=30):
    if 'page' not in st.session_state:
        st.session_state.page = 0
    
    if len(df) == 0:
        st.info("표시할 로그가 없습니다.")
        return
    
    # 추가 필터 적용 (사이드바 검색)
    if search_term and 'message' in df.columns:
        df = df[df['message'].str.contains(search_term, case=False, na=False)]
    if 'ml_score' in df.columns:
        df = df[df['ml_score'] >= min_ml_score]
    
    # 페이징 컨트롤
    total_pages = (len(df) - 1) // page_size + 1
    col1, col2, col3 = st.columns([1, 3, 1])
    with col1:
        if st.button("이전 페이지", key="prev_page") and st.session_state.page > 0:
            st.session_state.page -= 1
    with col3:
        if st.button("다음 페이지", key="next_page") and st.session_state.page < total_pages - 1:
            st.session_state.page += 1
    with col2:
        st.write(f"페이지 {st.session_state.page + 1} / {total_pages}")
    
    # 현재 페이지 데이터
    start = st.session_state.page * page_size
    end = start + page_size
    page_df = df.iloc[start:end]
    
    # 표시 컬럼 선택 (더 있어보이게: 추가 컬럼)
    columns_to_show = []
    if 'level' in page_df.columns: columns_to_show.append('level')
    if 'new_level' in page_df.columns: columns_to_show.append('new_level')
    if '@timestamp' in page_df.columns: columns_to_show.append('@timestamp')  # 타임스탬프 추가
    if 'message' in page_df.columns: columns_to_show.append('message')
    if 'winlog.user.name' in page_df.columns: columns_to_show.append('winlog.user.name')
    if 'ml_score' in page_df.columns: columns_to_show.append('ml_score')
    if 'summary' in page_df.columns: columns_to_show.append('summary')
    
    simplified_df = page_df[columns_to_show] if columns_to_show else page_df
    simplified_df['winlog.user.name'] = simplified_df.get('winlog.user.name', 'N/A')
    st.dataframe(simplified_df, use_container_width=True)  # 더 넓게 표시

# 3. 레벨별 필터링 버튼 (LOW/MEDIUM/HIGH)
if 'df' in st.session_state:
    st.subheader("레벨별 로그 보기")
    col1, col2, col3 = st.columns(3)
    level_column = 'new_level' if 'new_level' in st.session_state.df.columns else 'level'  # ML 후 new_level 사용
    
    with col1:
        if st.button("LOW"):
            filtered_df = st.session_state.df[st.session_state.df[level_column] == 'low']
            st.session_state.filtered_df = filtered_df
            st.session_state.page = 0
    
    with col2:
        if st.button("MEDIUM"):
            filtered_df = st.session_state.df[st.session_state.df[level_column] == 'medium']
            st.session_state.filtered_df = filtered_df
            st.session_state.page = 0
    
    with col3:
        if st.button("HIGH"):
            filtered_df = st.session_state.df[st.session_state.df[level_column] == 'high']
            st.session_state.filtered_df = filtered_df
            st.session_state.page = 0
    
    # 전체 로그 보기 버튼
    if st.button("전체 로그 보기"):
        st.session_state.filtered_df = st.session_state.df.copy()
        st.session_state.page = 0

# 4. ML 필터링 (MEDIUM/HIGH만 대상, 체크박스나 버튼으로 선택)
if 'df' in st.session_state:
    st.subheader("의심 로그 ML 분석")
    # MEDIUM/HIGH 로그만 필터링 (level이 low인 건 완전히 제외)
    level_column = 'new_level' if 'new_level' in st.session_state.df.columns else 'level'
    medium_high_df = st.session_state.df[st.session_state.df[level_column].isin(['medium', 'high', 'critical'])]
    if len(medium_high_df) > 0:
        # 보기 쉽게 format_func 개선: level, timestamp, message, user
        def format_log(x):
            row = medium_high_df.loc[x]
            level = row.get(level_column, 'N/A').upper()
            timestamp = row.get('@timestamp', 'N/A')
            message = row.get('message', 'N/A')[:50] + '...'
            user = row.get('winlog.user.name', 'N/A')
            return f"{level} | {timestamp} | 사용자: {user} | {message}"
        
        # 멀티셀렉트 (더 자세한 포맷)
        selected_indices = st.multiselect(
            "ML 분석할 의심 로그 선택 (MEDIUM/HIGH만)",
            options=medium_high_df.index.tolist(),
            format_func=format_log
        )
        
        if st.button("선택 로그 ML 분석"):
            if not selected_indices:
                st.warning("로그를 선택하세요.")
            else:
                try:
                    df_selected = st.session_state.df.loc[selected_indices].copy()
                    
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
                    if 'winlog.event_id' in df_selected.columns: features.append('winlog.event_id')
                    if 'winlog.event_data.GrantedAccess' in df_selected.columns: features.append('winlog.event_data.GrantedAccess')
                    if 'kibana.alert.risk_score' in df_selected.columns: features.append('kibana.alert.risk_score')
                    if not features:
                        raise ValueError("숫자 피처 없음 – 데이터 컬럼 확인하세요 (winlog.event_id 등).")
                    
                    for col in features:
                        if col == 'winlog.event_data.GrantedAccess':
                            df_selected[col] = df_selected[col].apply(hex_to_int)
                        else:
                            df_selected[col] = pd.to_numeric(df_selected[col], errors='coerce')
                    
                    df_features = df_selected[features].fillna(0)
                    model = IsolationForest(contamination='auto', random_state=42)
                    scores = model.fit_predict(df_features)
                    df_selected['ml_score'] = ((1 - scores) / 2) * 9 + 1  # 1~10점
                    
                    # new_level 재매핑
                    def remap_level(row):
                        severity = row.get('kibana.alert.severity', 'low').lower()
                        if row['ml_score'] > 7 or severity in ['high', 'critical']:
                            return 'high'
                        elif 3 < row['ml_score'] <= 7 or severity == 'medium':
                            return 'medium'
                        else:
                            return 'low'
                    
                    df_selected['new_level'] = df_selected.apply(remap_level, axis=1)
                    
                    # 원본 df 업데이트
                    for idx in selected_indices:
                        st.session_state.df.at[idx, 'ml_score'] = df_selected.at[idx, 'ml_score']
                        st.session_state.df.at[idx, 'new_level'] = df_selected.at[idx, 'new_level']
                    
                    st.success("ML 분석 완료! (선택 로그만)")
                    st.session_state.filtered_df = st.session_state.df  # 전체 df로 업데이트해서 보여줌
                except Exception as e:
                    st.error(f"ML 필터링 에러: {e}. 데이터 컬럼 확인하거나 선택 로그 확인하세요.")
        
        # 추가: MEDIUM/HIGH 로그 미리보기 테이블 (있어보이게)
        with st.expander("MEDIUM/HIGH 로그 미리보기"):
            display_paginated_df(medium_high_df)
    else:
        st.info("MEDIUM 또는 HIGH 레벨 로그가 없습니다.")

# 5. LLM 요약 & PDF (ML 점수 7 이상인 로그만 자동 대상)
if 'df' in st.session_state and st.button("LLM 요약 & PDF 생성 (ML 7점 이상 로그만)"):
    # ML 점수 7 이상 로그 필터링
    high_score_df = st.session_state.df[st.session_state.df['ml_score'] > 7].copy()
    if len(high_score_df) == 0:
        st.warning("ML 점수 7점 이상 로그가 없습니다.")
    else:
        with st.spinner("요약 중..."):
            for index, row in high_score_df.iterrows():
                level = row.get('new_level', row.get('level', 'low'))
                log_text = row.get('message', str(row))
                action = '관찰' if level == 'low' else '경고' if level == 'medium' else '격리'
                vulns_str = row.get('vulns', 'No vulnerabilities found')
                prompt = f"이 로그를 간결하게 요약하고, 잠재적 위협, 취약점 분석, 그리고 대응 방안을 제안하세요: {log_text}. 취약점: {vulns_str}. 레벨: {level} - 액션: {action}."
                response = openai_client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}]
                )
                summary = response.choices[0].message.content
                high_score_df.at[index, 'summary'] = summary
        
        # 원본 df 업데이트
        for idx in high_score_df.index:
            st.session_state.df.at[idx, 'summary'] = high_score_df.at[idx, 'summary']
        
        st.success("요약 완료! (ML 7점 이상 로그만)")
        st.session_state.filtered_df = high_score_df  # high_score_df로 업데이트해서 보여줌
        
        # PDF 생성
        pdf_buffer = io.BytesIO()
        font_path = './gulim.ttc'  # repo에 업로드된 폰트 사용
        pdfmetrics.registerFont(TTFont('Gulim', font_path))
        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        body_style = ParagraphStyle('Body', parent=styles['Normal'], fontName='Gulim', fontSize=10, wordWrap='CJK')
        elements = [Paragraph("로그 분석 보고서 (ML 7점 이상)", styles['Title'])]
        data = [['로그 ID', '메시지 (짧게)', '레벨 | ML Score', '요약']]
        for index, row in high_score_df.iterrows():
            msg_short = Paragraph(row.get('message', 'N/A')[:50] + '...', body_style)
            level_score = Paragraph(f"{row.get('new_level', row.get('level'))} | {row['ml_score']}", body_style)
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
        st.download_button("PDF 다운로드", pdf_buffer, file_name="high_score_report.pdf", mime="application/pdf")

# 최종 표시 로직 (여기서 한 번만 호출)
if 'filtered_df' in st.session_state:
    display_paginated_df(st.session_state.filtered_df)

# 추가: 로그 통계 차트 (있어보이게)
if 'df' in st.session_state and len(st.session_state.df) > 0:
    with st.expander("로그 통계"):
        level_counts = st.session_state.df[level_column].value_counts()
        st.bar_chart(level_counts)
        if 'ml_score' in st.session_state.df.columns:
            st.subheader("ML 점수 분포")
            st.hist_chart(st.session_state.df['ml_score'].dropna())
