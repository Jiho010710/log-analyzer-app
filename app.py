import streamlit as st
import pandas as pd
import numpy as np
from openai import OpenAI  # GPT 사용
from elasticsearch import Elasticsearch, helpers
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
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
import plotly.express as px  # 추가 차트 라이브러리
import requests  # 취약점 API 호출용
import base64  # 이미지 인코딩
import matplotlib.pyplot as plt  # 추가 플롯
from wordcloud import WordCloud  # 워드클라우드
import seaborn as sns  # 히트맵 등
from streamlit_option_menu import option_menu  # 사이드바 메뉴
import streamlit.components.v1 as components  # HTML 컴포넌트
from PIL import Image as PILImage  # 이미지 처리
import os  # 파일 관리
import smtplib  # 이메일 보내기 (기본 설정)
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
warnings.filterwarnings("ignore")

# 폰트 등록 (NanumGothic 폰트 가정, 실제 업로드 필요)
font_path = './NanumGothic-Bold.ttf'
if os.path.exists(font_path):
    pdfmetrics.registerFont(TTFont('NanumGothic', font_path))
else:
    st.warning("NanumGothic 폰트 파일이 없습니다. 기본 폰트 사용.")

# 테마 설정 (다크/라이트 모드)
theme = st.sidebar.selectbox("테마 선택", ["Dark", "Light"])
if theme == "Dark":
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
        .stSelectbox, .stTextInput {background-color: #2a2a2a; color: #ffffff;}
        .stSlider {color: #ffffff;}
        .reportview-container .main .block-container {background-color: #1e1e1e;}
        </style>
        """, unsafe_allow_html=True)
else:
    st.markdown("""
        <style>
        .main {background-color: #ffffff; color: #000000;}
        .stButton > button {background-color: #4CAF50; color: white; border-radius: 5px;}
        .stExpander {border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9;}
        .stMetric {font-size: 1.2em; color: #000000;}
        .high-risk {color: #ff4b4b; font-weight: bold;}
        .medium-risk {color: #ffb74d;}
        .low-risk {color: #81c784;}
        .stSidebar {background-color: #f0f0f0;}
        .stDataFrame {background-color: #ffffff; color: #000000;}
        .stSelectbox, .stTextInput {background-color: #ffffff; color: #000000;}
        .stSlider {color: #000000;}
        .reportview-container .main .block-container {background-color: #ffffff;}
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

# 앱 타이틀 with 아이콘
st.title("SCP Shield 🛡️ - Advanced Threat Detection Engine")

# 사이드바 메뉴 (option_menu 사용으로 Wazuh-like 네비게이션)
with st.sidebar:
    selected = option_menu(
        menu_title="메인 메뉴",
        options=["대시보드", "로그 조회", "보고서 생성", "취약점 스캔", "알림 설정", "시스템 설정"],
        icons=["speedometer2", "search", "file-earmark-text", "bug", "bell", "gear"],
        menu_icon="cast",
        default_index=0,
    )

# 추가 옵션 (공통 사이드바 아래)
with st.sidebar:
    st.title("검색 필터")
    search_term = st.text_input("로그 검색 (메시지 내 키워드)", "")
    event_id_filter = st.text_input("Event ID 필터", "")
    user_filter = st.text_input("User 필터", "")
    time_range = st.date_input("시간 범위", value=(datetime.now() - timedelta(days=7), datetime.now()))
    severity_filter = st.multiselect("Severity 필터", ["low", "medium", "high"], default=["low", "medium", "high"])
    regex_search = st.checkbox("정규식 검색 사용")

# 페이징 함수 (한 페이지 50개로 증가, 성능 향상)
def display_paginated_df(df, page_size=50, key_prefix="main"):
    if f'page_{key_prefix}' not in st.session_state:
        st.session_state[f'page_{key_prefix}'] = 0

    if len(df) == 0:
        st.info("표시할 로그가 없습니다.")
        return

    # 추가 필터 적용 (사이드바 검색)
    if search_term and 'message' in df.columns:
        if regex_search:
            df = df[df['message'].str.contains(search_term, regex=True, na=False)]
        else:
            df = df[df['message'].str.contains(search_term, case=False, na=False)]

    if event_id_filter and 'winlog.event_id' in df.columns:
        df = df[df['winlog.event_id'].astype(str).str.contains(event_id_filter)]

    if user_filter and 'winlog.user.name' in df.columns:
        df = df[df['winlog.user.name'].str.contains(user_filter, case=False, na=False)]

    if '@timestamp' in df.columns:
        df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
        start_date, end_date = time_range
        df = df[(df['@timestamp'] >= pd.to_datetime(start_date)) & (df['@timestamp'] <= pd.to_datetime(end_date))]

    level_column = 'new_level' if 'new_level' in df.columns else 'level'
    if severity_filter:
        df = df[df[level_column].isin(severity_filter)]

    # 페이징 컨트롤 (더 세련되게)
    total_pages = (len(df) - 1) // page_size + 1
    col1, col2, col3 = st.columns([1, 3, 1])
    with col1:
        if st.button("이전 페이지", key=f"prev_page_{key_prefix}") and st.session_state[f'page_{key_prefix}'] > 0:
            st.session_state[f'page_{key_prefix}'] -= 1
    with col3:
        if st.button("다음 페이지", key=f"next_page_{key_prefix}") and st.session_state[f'page_{key_prefix}'] < total_pages - 1:
            st.session_state[f'page_{key_prefix}'] += 1
    with col2:
        st.write(f"페이지 {st.session_state[f'page_{key_prefix}'] + 1} / {total_pages} (총 {len(df)} 로그)")

    # 현재 페이지 데이터
    start = st.session_state[f'page_{key_prefix}'] * page_size
    end = start + page_size
    page_df = df.iloc[start:end]

    # 표시 컬럼 선택 (더 많은 컬럼 추가)
    columns_to_show = []
    if level_column in page_df.columns: columns_to_show.append(level_column)
    if '@timestamp' in page_df.columns: columns_to_show.append('@timestamp')
    if 'message' in page_df.columns: columns_to_show.append('message')
    if 'winlog.user.name' in page_df.columns: columns_to_show.append('winlog.user.name')
    if 'winlog.event_id' in page_df.columns: columns_to_show.append('winlog.event_id')
    if 'host.ip' in page_df.columns: columns_to_show.append('host.ip')
    if 'summary' in page_df.columns: columns_to_show.append('summary')
    if 'vulns' in page_df.columns: columns_to_show.append('vulns')

    simplified_df = page_df[columns_to_show] if columns_to_show else page_df
    simplified_df['winlog.user.name'] = simplified_df.get('winlog.user.name', 'N/A')
    st.dataframe(simplified_df, use_container_width=True, height=600)  # 높이 증가

# 로그 트리 구조 함수 (계층적 보기, 더 세련되게)
def display_log_tree(df):
    if 'winlog.event_id' in df.columns:
        grouped = df.groupby('winlog.event_id')
        for event_id, group in grouped:
            with st.expander(f"🗂 Event ID: {event_id} ({len(group)} logs)", expanded=False):
                for idx, row in group.iterrows():
                    level = row.get('new_level', row.get('level', 'low'))
                    level_class = 'high-risk' if level == 'high' else 'medium-risk' if level == 'medium' else 'low-risk'
                    st.markdown(f"<div class='{level_class}'>- Timestamp: {row.get('@timestamp', 'N/A')}</div>", unsafe_allow_html=True)
                    st.markdown(f" Message: {row.get('message', 'N/A')}")
                    st.markdown(f" User: {row.get('winlog.user.name', 'N/A')}")
                    if 'host.ip' in row: st.markdown(f" IP: {row['host.ip']}")
                    if 'summary' in row: st.markdown(f" Summary: {row['summary']}")
                    st.markdown("---")
    else:
        st.info("트리 구조를 위한 Event ID 컬럼이 없습니다. 일반 테이블로 표시합니다.")
        display_paginated_df(df)

# 대시보드 기능 (선택된 메뉴에 따라 탭 대신 직접 렌더링)
if selected == "대시보드":
    st.header("로그 대시보드 📊")
    if 'df' in st.session_state and len(st.session_state.df) > 0:
        df = st.session_state.df.copy()

        # 시간별 로그 수 차트 (Altair)
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

        # 레벨 분포 Pie Chart (Plotly로 업그레이드)
        level_counts = df['level'].value_counts().reset_index()
        level_counts.columns = ['level', 'count']
        pie_fig = px.pie(level_counts, values='count', names='level', title="로그 레벨 분포",
                         color='level', color_discrete_map={'low': '#81c784', 'medium': '#ffb74d', 'high': '#ff4b4b'})
        st.plotly_chart(pie_fig, use_container_width=True)

        # Top 5 Users/Events/IPs (표 + 바 차트)
        col1, col2, col3 = st.columns(3)
        with col1:
            if 'winlog.user.name' in df.columns:
                top_users = df['winlog.user.name'].value_counts().head(5).reset_index()
                top_users.columns = ['User', 'Count']
                st.subheader("Top 5 Users")
                st.table(top_users)
                user_bar = px.bar(top_users, x='User', y='Count', title="Top Users Bar")
                st.plotly_chart(user_bar)

        with col2:
            if 'winlog.event_id' in df.columns:
                top_events = df['winlog.event_id'].value_counts().head(5).reset_index()
                top_events.columns = ['Event ID', 'Count']
                st.subheader("Top 5 Events")
                st.table(top_events)
                event_bar = px.bar(top_events, x='Event ID', y='Count', title="Top Events Bar")
                st.plotly_chart(event_bar)

        with col3:
            if 'host.ip' in df.columns:
                top_ips = df['host.ip'].value_counts().head(5).reset_index()
                top_ips.columns = ['IP', 'Count']
                st.subheader("Top 5 IPs")
                st.table(top_ips)
                ip_bar = px.bar(top_ips, x='IP', y='Count', title="Top IPs Bar")
                st.plotly_chart(ip_bar)

        # 워드클라우드 (메시지 키워드)
        st.subheader("메시지 키워드 워드클라우드")
        if 'message' in df.columns:
            text = ' '.join(df['message'].dropna())
            wordcloud = WordCloud(width=800, height=400, background_color='white' if theme == 'Light' else 'black').generate(text)
            plt.figure(figsize=(10, 5))
            plt.imshow(wordcloud, interpolation='bilinear')
            plt.axis('off')
            st.pyplot(plt)

        # 히트맵 (User vs Event ID)
        st.subheader("User vs Event Heatmap")
        if 'winlog.user.name' in df.columns and 'winlog.event_id' in df.columns:
            pivot = pd.pivot_table(df, index='winlog.user.name', columns='winlog.event_id', aggfunc='size', fill_value=0)
            fig, ax = plt.subplots(figsize=(10, 6))
            sns.heatmap(pivot, annot=True, cmap='YlGnBu', ax=ax)
            st.pyplot(fig)

        # 타임라인 차트 (Plotly)
        st.subheader("로그 타임라인")
        timeline_fig = px.scatter(df, x='@timestamp', y='level', color='level', hover_data=['message', 'winlog.user.name'],
                                  title="로그 타임라인")
        st.plotly_chart(timeline_fig, use_container_width=True)

    else:
        st.info("로그를 먼저 불러오세요.")

elif selected == "로그 조회":
    st.header("로그 조회 🔍")
    # 1. 로그 연동 (EVTX 업로드 & ES 인덱싱, 벌크 인덱싱으로 성능 향상)
    evtx_file = st.file_uploader("EVTX 로그 업로드", type="evtx")
    if evtx_file and st.button("ES에 인덱싱"):
        with st.spinner("EVTX 파싱 & 벌크 인덱싱 중..."):
            parser = PyEvtxParser(evtx_file)
            actions = []
            for record in parser.records_json():
                log_data = json.loads(record['data'])
                event = xmltodict.parse(log_data['Event'])['Event']
                actions.append({
                    "_index": ".internal.alerts-security.alerts*",
                    "_source": event
                })
            if actions:
                helpers.bulk(es, actions)
        st.success("인덱싱 완료!")

    # 2. 모든 로그 가져오기 (스크롤링 쿼리로 대용량 처리)
    if st.button("모든 로그 가져오기"):
        query = {
            "query": {"match_all": {}},
            "size": 1000,  # 배치 크기
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        try:
            res = es.search(index=".internal.alerts-security.alerts*", body=query, scroll='2m')
            scroll_id = res['_scroll_id']
            logs = [hit['_source'] for hit in res['hits']['hits']]
            while len(res['hits']['hits']) > 0:
                res = es.scroll(scroll_id=scroll_id, scroll='2m')
                logs.extend([hit['_source'] for hit in res['hits']['hits']])
            df = pd.DataFrame(logs)

            # 초기 level 설정
            if 'kibana.alert.severity' in df.columns:
                df['level'] = df['kibana.alert.severity'].str.lower()
            else:
                df['level'] = 'low'

            st.session_state.df = df
            st.session_state.filtered_df = df.copy()
            st.session_state.page_logs = 0
            st.success(f"총 {len(df)}개 로그 가져옴")
        except Exception as e:
            st.error(f"ES 쿼리 에러: {e}")

    # 레벨별 필터링 버튼
    if 'df' in st.session_state:
        col1, col2, col3, col4 = st.columns(4)
        level_column = 'new_level' if 'new_level' in st.session_state.df.columns else 'level'

        with col1:
            if st.button("LOW"):
                filtered_df = st.session_state.df[st.session_state.df[level_column] == 'low']
                st.session_state.filtered_df = filtered_df
                st.session_state.page_logs = 0

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

        with col4:
            if st.button("전체 보기"):
                st.session_state.filtered_df = st.session_state.df.copy()
                st.session_state.page_logs = 0

    # 표시 옵션 (테이블 vs 트리)
    display_mode = st.radio("표시 모드", ["테이블", "트리 구조"])
    if 'filtered_df' in st.session_state:
        filtered_df = st.session_state.filtered_df.copy()
        if display_mode == "트리 구조":
            display_log_tree(filtered_df)
        else:
            display_paginated_df(filtered_df, key_prefix="logs")

    # 로그 상세 보기 (선택된 행 클릭 시)
    if 'filtered_df' in st.session_state:
        selected_row = st.selectbox("로그 상세 보기 (인덱스 선택)", st.session_state.filtered_df.index)
        if selected_row is not None:
            row = st.session_state.filtered_df.loc[selected_row]
            with st.expander("상세 로그 정보"):
                st.json(row.to_dict())

elif selected == "보고서 생성":
    st.header("보고서 & 요약 생성 📄")
    if 'df' in st.session_state and st.button("LLM 요약 & PDF 생성"):
        high_score_df = st.session_state.df.copy()
        if len(high_score_df) == 0:
            st.warning("로그가 없습니다.")
        else:
            with st.spinner("요약 및 취약점 분석 중..."):
                for index, row in high_score_df.iterrows():
                    level = row.get('new_level', row.get('level', 'low'))
                    log_text = row.get('message', str(row))
                    action = '관찰' if level == 'low' else '경고' if level == 'medium' else '격리'
                    # 취약점 스캔 (NVD API 예시)
                    vulns = "No vulnerabilities found"
                    if 'process.name' in row:
                        try:
                            resp = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={row['process.name']}")
                            if resp.status_code == 200:
                                data = resp.json()
                                if data['totalResults'] > 0:
                                    vulns = f"Found {data['totalResults']} vulns: {data['result']['CVE_Items'][0]['cve']['CVE_data_meta']['ID']}"
                        except:
                            pass
                    high_score_df.at[index, 'vulns'] = vulns
                    prompt = f"이 로그를 간결하게 요약하고, 잠재적 위협, 취약점 분석, 그리고 대응 방안을 제안하세요: {log_text}. 취약점: {vulns}. 레벨: {level} - 액션: {action}."
                    response = openai_client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[{"role": "user", "content": prompt}]
                    )
                    summary = response.choices[0].message.content
                    high_score_df.at[index, 'summary'] = summary

            for idx in high_score_df.index:
                st.session_state.df.at[idx, 'summary'] = high_score_df.at[idx, 'summary']
                st.session_state.df.at[idx, 'vulns'] = high_score_df.at[idx, 'vulns']

            st.success("요약 완료!")
            st.session_state.filtered_df = high_score_df

            # PDF 생성 (더 세련되게: 이미지, 스페이서 추가)
            pdf_buffer = io.BytesIO()
            doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            body_style = ParagraphStyle('Body', parent=styles['Normal'], fontName='NanumGothic', fontSize=10, wordWrap='CJK')
            elements = [Paragraph("로그 분석 보고서", styles['Title'])]
            elements.append(Spacer(1, 12))

            # 로고 이미지 추가 (가상 이미지)
            # img = Image('logo.png', width=100, height=50)  # 실제 로고 업로드 필요
            # elements.append(img)
            # elements.append(Spacer(1, 12))

            data = [['로그 ID', '메시지 (짧게)', '레벨', '취약점', '요약']]
            for index, row in high_score_df.iterrows():
                msg_short = Paragraph(row.get('message', 'N/A')[:50] + '...', body_style)
                level_score = Paragraph(f"{row.get('new_level', row.get('level'))}", body_style)
                vulns_para = Paragraph(row.get('vulns', 'N/A'), body_style)
                summary_para = Paragraph(row['summary'], body_style)
                data.append([Paragraph(str(index), body_style), msg_short, level_score, vulns_para, summary_para])

            col_widths = [50, 100, 80, 100, 250]
            table = Table(data, colWidths=col_widths)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, -1), 'NanumGothic'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(table)
            doc.build(elements)
            pdf_buffer.seek(0)
            st.download_button("PDF 다운로드", pdf_buffer, file_name="advanced_report.pdf", mime="application/pdf")

    # 추가: CSV, Excel 내보내기
    if 'df' in st.session_state:
        csv = st.session_state.df.to_csv(index=False).encode('utf-8-sig')
        st.download_button("CSV 다운로드", csv, "logs.csv", "text/csv")

        excel_buffer = io.BytesIO()
        with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
            st.session_state.df.to_excel(writer, index=False)
        excel_buffer.seek(0)
        st.download_button("Excel 다운로드", excel_buffer, "logs.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

elif selected == "취약점 스캔":
    st.header("취약점 스캔 🐛")
    scan_query = st.text_input("취약점 검색 키워드 (e.g., process name or CVE)")
    if st.button("NVD 스캔"):
        if scan_query:
            with st.spinner("스캔 중..."):
                try:
                    resp = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={scan_query}")
                    if resp.status_code == 200:
                        data = resp.json()
                        if data['totalResults'] > 0:
                            vulns_df = pd.DataFrame([item['cve']['CVE_data_meta'] for item in data['result']['CVE_Items']])
                            st.dataframe(vulns_df)
                            # 워닝 메트릭
                            st.metric("총 취약점", data['totalResults'])
                        else:
                            st.info("취약점 없음")
                except Exception as e:
                    st.error(f"스캔 에러: {e}")
        else:
            st.warning("키워드를 입력하세요.")

elif selected == "알림 설정":
    st.header("알림 설정 🔔")
    email_to = st.text_input("알림 이메일 주소")
    smtp_server = st.text_input("SMTP 서버", "smtp.gmail.com")
    smtp_port = st.number_input("SMTP 포트", 587)
    smtp_user = st.text_input("SMTP 사용자")
    smtp_pass = st.text_input("SMTP 비밀번호", type="password")
    alert_threshold = st.slider("알림 임계값 (High 로그 수)", 1, 100, 5)

    if st.button("알림 테스트"):
        if 'df' in st.session_state and len(st.session_state.df[st.session_state.df['level'] == 'high']) >= alert_threshold:
            try:
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.starttls()
                server.login(smtp_user, smtp_pass)
                msg = MIMEMultipart()
                msg['From'] = smtp_user
                msg['To'] = email_to
                msg['Subject'] = "SCP Shield Alert"
                body = f"High level alerts exceeded threshold: {alert_threshold}"
                msg.attach(MIMEText(body, 'plain'))
                # PDF 첨부 예시
                if 'pdf_buffer' in globals():
                    pdf_attach = MIMEApplication(pdf_buffer.getvalue(), _subtype="pdf")
                    pdf_attach.add_header('Content-Disposition', 'attachment', filename="report.pdf")
                    msg.attach(pdf_attach)
                server.sendmail(smtp_user, email_to, msg.as_string())
                server.quit()
                st.success("알림 전송 완료!")
            except Exception as e:
                st.error(f"이메일 에러: {e}")
        else:
            st.info("알림 조건 미달.")

elif selected == "시스템 설정":
    st.header("시스템 설정 ⚙️")
    st.subheader("로그 저장 기간")
    retention_days = st.slider("로그 보관 일수", 1, 365, 30)
    if st.button("로그 정리"):
        # ES에서 오래된 로그 삭제 (예시)
        delete_query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "lt": f"now-{retention_days}d"
                    }
                }
            }
        }
        try:
            es.delete_by_query(index=".internal.alerts-security.alerts*", body=delete_query)
            st.success("오래된 로그 정리 완료!")
        except Exception as e:
            st.error(f"정리 에러: {e}")

    st.subheader("백업 설정")
    backup_path = st.text_input("백업 파일 경로")
    if st.button("데이터 백업"):
        if 'df' in st.session_state:
            st.session_state.df.to_json(backup_path, orient='records')
            st.success("백업 완료!")

# 실시간 업데이트 (폴링 방식 예시)
if st.checkbox("실시간 업데이트 활성화"):
    st.write("5초마다 로그 새로고침...")
    # 플레이스홀더로 업데이트 (실제 구현은 루프 필요, Streamlit 제한)

# 푸터
st.markdown("---")
st.markdown("SCP Shield v2.0 | Powered by xAI & Elasticsearch | © 2025")
