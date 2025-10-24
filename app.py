import streamlit as st
import pandas as pd
import numpy as np
from openai import OpenAI  # GPT 사용
from elasticsearch import Elasticsearch
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
from datetime import datetime, timedelta
import altair as alt  # 대시보드 시각화 추가
warnings.filterwarnings("ignore")

# 커스텀 CSS로 Kibana/Wazuh 스타일 UI/UX 개선 (깔끔한 테마, 다크 모드)
st.markdown("""
    <style>
    .main {background-color: #1e1e1e; color: #ffffff;}
    .stButton > button {background-color: #4CAF50; color: white; border-radius: 5px;}
    .stExpander {border: 1px solid #333; border-radius: 5px; background-color: #2a2a2a;}
    .stMetric {font-size: 1.2em; color: #ffffff;}
    .high-risk {color: #ff4b4b; font-weight: bold;}
    .medium-risk {color: #ffb74d;}
    .low-risk {color: #81c784;}
    .stSidebar {background-color: #121212;}
    .stDataFrame {background-color: #2a2a2a; color: #ffffff;}
    </style>
    """, unsafe_allow_html=True)

st.set_page_config(layout="wide", page_title="SCP Shield", page_icon="🛡️")

# GPT 설정 (API 키 secrets 사용)
openai_client = OpenAI(api_key=st.secrets["OPENAI_API_KEY"])

# ES 연결 (사용자 입력 호스트/인증, form으로 감싸서 오류 방지)
with st.sidebar.form(key="es_config_form"):
    st.title("ES 설정")
    es_host = st.text_input("ES 호스트", "http://3.38.65.230:9200")
    es_user = st.text_input("ES 사용자", "elastic")
    es_pass = st.text_input("ES 비밀번호", type="password")
    submit_es = st.form_submit_button("ES 연결")

if submit_es:
    try:
        es = Elasticsearch(hosts=[es_host], basic_auth=(es_user, es_pass), request_timeout=120)
        st.session_state.es = es
        st.sidebar.success("ES 연결 완료!")
    except Exception as e:
        st.sidebar.error(f"ES 연결 에러: {e}")

# ES 연결 확인 (세션에서 불러옴)
if 'es' not in st.session_state:
    st.sidebar.info("ES 설정을 입력하고 연결하세요.")
    st.stop()
es = st.session_state.es

# 앱 타이틀
st.title("SCP Shield 🛡️")

# 사이드바에 추가 옵션 (있어보이게: 로그 검색 필터 등)
with st.sidebar:
    st.title("추가 옵션")
    search_term = st.text_input("로그 검색 (메시지 내 키워드)", "")
    event_id_filter = st.text_input("Event ID 필터", "")  # 추가: Event ID 필터

# 페이징 함수 (한 페이지 30개, key_prefix로 중복 키 방지)
def display_paginated_df(df, page_size=30, key_prefix="main"):
    if f'page_{key_prefix}' not in st.session_state:
        st.session_state[f'page_{key_prefix}'] = 0
    
    if len(df) == 0:
        st.info("표시할 로그가 없습니다.")
        return
    
    # 추가 필터 적용 (사이드바 검색)
    if search_term and 'message' in df.columns:
        df = df[df['message'].str.contains(search_term, case=False, na=False)]
    
    # 페이징 컨트롤
    total_pages = (len(df) - 1) // page_size + 1
    col1, col2, col3 = st.columns([1, 3, 1])
    with col1:
        if st.button("이전 페이지", key=f"prev_page_{key_prefix}") and st.session_state[f'page_{key_prefix}'] > 0:
            st.session_state[f'page_{key_prefix}'] -= 1
    with col3:
        if st.button("다음 페이지", key=f"next_page_{key_prefix}") and st.session_state[f'page_{key_prefix}'] < total_pages - 1:
            st.session_state[f'page_{key_prefix}'] += 1
    with col2:
        st.write(f"페이지 {st.session_state[f'page_{key_prefix}'] + 1} / {total_pages}")
    
    # 현재 페이지 데이터
    start = st.session_state[f'page_{key_prefix}'] * page_size
    end = start + page_size
    page_df = df.iloc[start:end]
    
    # 표시 컬럼 선택 (더 있어보이게: 추가 컬럼)
    columns_to_show = []
    if 'level' in page_df.columns: columns_to_show.append('level')
    if 'new_level' in page_df.columns: columns_to_show.append('new_level')
    if '@timestamp' in page_df.columns: columns_to_show.append('@timestamp') # 타임스탬프 추가
    if 'message' in page_df.columns: columns_to_show.append('message')
    if 'winlog.user.name' in page_df.columns: columns_to_show.append('winlog.user.name')
    if 'summary' in page_df.columns: columns_to_show.append('summary')
    
    simplified_df = page_df[columns_to_show] if columns_to_show else page_df
    simplified_df['winlog.user.name'] = simplified_df.get('winlog.user.name', 'N/A')
    st.dataframe(simplified_df, use_container_width=True) # 더 넓게 표시

# 로그 트리 구조 함수 (계층적 보기, event_id 그룹화)
def display_log_tree(df):
    if 'winlog.event_id' in df.columns:
        grouped = df.groupby('winlog.event_id')
        for event_id, group in grouped:
            with st.expander(f"🗂 Event ID: {event_id} ({len(group)} logs)"):
                for idx, row in group.iterrows():
                    level = row.get('level', 'N/A')
                    level_class = 'high-risk' if level == 'high' else 'medium-risk' if level == 'medium' else 'low-risk'
                    st.markdown(f"<div class='{level_class}'>- Timestamp: {row.get('@timestamp', 'N/A')}</div>", unsafe_allow_html=True)
                    st.markdown(f"  Message: {row.get('message', 'N/A')}")
                    st.markdown(f"  User: {row.get('winlog.user.name', 'N/A')}")
                    st.markdown("---")
    else:
        st.info("트리 구조를 위한 Event ID 컬럼이 없습니다. 일반 테이블로 표시합니다.")
        display_paginated_df(df)

# 탭 구조 추가 (Kibana처럼: Dashboard, Logs, Reports)
tab1, tab2, tab4 = st.tabs(["대시보드", "로그 조회", "보고서 생성"])

with tab1: # 대시보드 탭 (Wazuh/Kibana 스타일 시각화 추가)
    st.header("로그 대시보드")
    if 'df' in st.session_state and len(st.session_state.df) > 0:
        df = st.session_state.df.copy()
        
        # 시간별 로그 수 차트 (Altair 사용)
        if '@timestamp' in df.columns:
            df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
            df['hour'] = df['@timestamp'].dt.hour
            time_chart = alt.Chart(df).mark_bar().encode(
                x='hour:O',
                y='count()',
                color='level',
                tooltip=['hour', 'count()', 'level']
            ).properties(title="시간별 로그 분포").interactive()
            st.altair_chart(time_chart, use_container_width=True)
        
        # 레벨 분포 Pie Chart (Altair 사용)
        level_counts = df['level'].value_counts().reset_index()
        level_counts.columns = ['level', 'count']
        pie_chart = alt.Chart(level_counts).mark_arc().encode(
            theta='count',
            color='level',
            tooltip=['level', 'count']
        ).properties(title="로그 레벨 분포").interactive()
        st.altair_chart(pie_chart, use_container_width=True)
        
        # Top 5 Users/Events (표 형식)
        col_users, col_events = st.columns(2)
        with col_users:
            if 'winlog.user.name' in df.columns:
                top_users = df['winlog.user.name'].value_counts().head(5).reset_index()
                top_users.columns = ['User', 'Count']
                st.subheader("Top 5 Users")
                st.table(top_users)
        
        with col_events:
            if 'winlog.event_id' in df.columns:
                top_events = df['winlog.event_id'].value_counts().head(5).reset_index()
                top_events.columns = ['Event ID', 'Count']
                st.subheader("Top 5 Events")
                st.table(top_events)

with tab2: # 로그 조회 탭
    st.header("로그 조회")
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
    # 2. 모든 로그 가져오기
    if st.button("모든 로그 가져오기"):
        query = {
            "query": {"match_all": {}},
            "size": 10000, # 최대 크기
            "sort": [{"@timestamp": {"order": "desc"}}] # 최근 순 정렬
        }
        try:
            res = es.search(index=".internal.alerts-security.alerts*", body=query)
            logs = [hit['_source'] for hit in res['hits']['hits']]
            df = pd.DataFrame(logs)
           
            # 초기 level 설정
            if 'kibana.alert.severity' in df.columns:
                df['level'] = df['kibana.alert.severity'].str.lower()
            else:
                df['level'] = 'low'
           
            st.session_state.df = df
            st.session_state.filtered_df = df.copy()
            st.session_state.page_logs = 0 # 페이징 초기화
            st.success(f"총 {len(df)}개 로그 가져옴")
        except Exception as e:
            st.error(f"ES 쿼리 에러: {e}")
    # 레벨별 필터링 버튼 (LOW/MEDIUM/HIGH)
    if 'df' in st.session_state:
        col1, col2, col3 = st.columns(3)
        level_column = 'new_level' if 'new_level' in st.session_state.df.columns else 'level'
       
        with col1:
            if st.button("LOW"):
                filtered_df = st.session_state.df[st.session_state.df[level_column] == 'low']
                st.session_state.filtered_df = filtered_df
                st.session_state.page_logs = 0 # 로그 탭 페이징 초기화
       
        with col2:
            if st.button("MEDIUM"):
                filtered_df = st.session_state.df[st.session_state.df[level_column] == 'medium']
                st.session_state.filtered_df = filtered_df
                st.session_state.page_logs = 0
       
        with col3:
            if st.button("HIGH"):
                filtered_df = st.session_state.df[st.session_state.df[level_column] == 'high']
                st.session_state.filtered_df = filtered_df
                st.session_state.page_logs = 0
       
        # 전체 로그 보기 버튼
        if st.button("전체 로그 보기"):
            st.session_state.filtered_df = st.session_state.df.copy()
            st.session_state.page_logs = 0
    # 필터링 추가 (Event ID 필터 적용)
    if 'filtered_df' in st.session_state:
        filtered_df = st.session_state.filtered_df.copy()
        if event_id_filter and 'winlog.event_id' in filtered_df.columns:
            filtered_df = filtered_df[filtered_df['winlog.event_id'].astype(str).str.contains(event_id_filter)]
        display_paginated_df(filtered_df, key_prefix="logs")

with tab4: # 보고서 생성 탭
    st.header("보고서 & 요약 생성")
    if 'df' in st.session_state and st.button("LLM 요약 & PDF 생성"):
        high_score_df = st.session_state.df.copy()  # 전체 로그 요약
        if len(high_score_df) == 0:
            st.warning("로그가 없습니다.")
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
            
            for idx in high_score_df.index:
                st.session_state.df.at[idx, 'summary'] = high_score_df.at[idx, 'summary']
            
            st.success("요약 완료!")
            st.session_state.filtered_df = high_score_df
            
            # PDF 생성
            pdf_buffer = io.BytesIO()
            font_path = './NanumGothic-Bold.ttf' # 업로드한 폰트 사용
            pdfmetrics.registerFont(TTFont('NanumGothic', font_path))
            doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            body_style = ParagraphStyle('Body', parent=styles['Normal'], fontName='NanumGothic', fontSize=10, wordWrap='CJK')
            elements = [Paragraph("로그 분석 보고서", styles['Title'])]
            data = [['로그 ID', '메시지 (짧게)', '레벨', '요약']]
            for index, row in high_score_df.iterrows():
                msg_short = Paragraph(row.get('message', 'N/A')[:50] + '...', body_style)
                level_score = Paragraph(f"{row.get('new_level', row.get('level'))}", body_style)
                summary_para = Paragraph(row['summary'], body_style)
                data.append([Paragraph(str(index), body_style), msg_short, level_score, summary_para])
            col_widths = [50, 150, 100, 300]
            table = Table(data, colWidths=col_widths)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, -1), 'NanumGothic'),
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

    # 추가: CSV 내보내기 (Wazuh 스타일)
    if 'df' in st.session_state:
        csv = st.session_state.df.to_csv(index=False).encode('utf-8-sig')
        st.download_button("전체 로그 CSV 다운로드", csv, "logs.csv", "text/csv")

# 최종 표시 로직 (여기서 한 번만 호출, 탭 밖으로 이동)
if 'filtered_df' in st.session_state:
    st.subheader("현재 필터링된 로그")
    display_paginated_df(st.session_state.filtered_df, key_prefix="main")

# 추가: 로그 통계 차트 (있어보이게, 탭 밖으로 이동)
if 'df' in st.session_state and len(st.session_state.df) > 0:
    with st.expander("로그 통계"):
        level_counts = st.session_state.df[level_column].value_counts()
        st.bar_chart(level_counts)
