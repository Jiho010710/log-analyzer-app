import streamlit as st
import pandas as pd
import numpy as np
from openai import OpenAI  # GPT 사용
from elasticsearch import Elasticsearch, helpers
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import json
import io
import warnings
from evtx import PyEvtxParser
import xmltodict
from datetime import datetime, timedelta
import altair as alt  # 대시보드 시각화
import requests  # 취약점 API 호출용
import base64  # 이미지 인코딩
from streamlit_option_menu import option_menu  # 사이드바 메뉴
import streamlit.components.v1 as components  # HTML 컴포넌트
from PIL import Image as PILImage  # 이미지 처리
import os  # 파일 관리
import smtplib  # 이메일 보내기
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import hashlib  # 사용자 인증용 해싱
import time  # 실시간 업데이트 시뮬레이션
import random  # 테스트 데이터 생성
from collections import defaultdict  # 데이터 구조
import zipfile  # 백업 압축
import shutil  # 파일 복사
import logging  # 로깅
import sqlite3  # 로컬 DB for 사용자 관리
from io import StringIO  # 문자열 IO
import re  # 정규식 검색
# sklearn 없음, numpy로 간단 anomaly 구현

warnings.filterwarnings("ignore")

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 폰트 등록 (NanumGothic 폰트 가정, 실제 업로드 필요)
font_path = './NanumGothic-Bold.ttf'
if os.path.exists(font_path):
    pdfmetrics.registerFont(TTFont('NanumGothic', font_path))
else:
    logger.warning("NanumGothic 폰트 파일이 없습니다. 기본 폰트 사용.")

# 데이터베이스 설정 (사용자 관리)
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
    conn.commit()
    return conn

conn = init_db()

# 사용자 인증 함수
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password, role='user'):
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users VALUES (?, ?, ?)", (username, hash_password(password), role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def login_user(username, password):
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hash_password(password)))
    return c.fetchone() is not None

# 세션 상태 초기화
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'user_role' not in st.session_state:
    st.session_state.user_role = 'guest'

# 로그인/등록 UI
if not st.session_state.logged_in:
    tab_login, tab_register = st.tabs(["로그인", "등록"])
    with tab_login:
        username = st.text_input("사용자명")
        password = st.text_input("비밀번호", type="password")
        if st.button("로그인"):
            if login_user(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                c = conn.cursor()
                c.execute("SELECT role FROM users WHERE username=?", (username,))
                st.session_state.user_role = c.fetchone()[0]
                st.success("로그인 성공!")
                st.rerun()
            else:
                st.error("잘못된 자격증명")
    with tab_register:
        new_username = st.text_input("새 사용자명")
        new_password = st.text_input("새 비밀번호", type="password")
        if st.button("등록"):
            if register_user(new_username, new_password):
                st.success("등록 성공! 로그인하세요.")
            else:
                st.error("사용자명 이미 존재")
    st.stop()

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
        .custom-chart {background-color: #2a2a2a;}
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
        .custom-chart {background-color: #f9f9f9;}
        </style>
        """, unsafe_allow_html=True)

st.set_page_config(layout="wide", page_title="SCP Shield", page_icon="🛡️")

# GPT 설정 (API 키 secrets 사용)
try:
    openai_client = OpenAI(api_key=st.secrets["OPENAI_API_KEY"])
except KeyError:
    st.error("OPENAI_API_KEY가 설정되지 않았습니다. secrets.toml에 추가하세요.")
    st.stop()

# ES 연결 (사용자 입력 호스트/인증, form으로 감싸서 오류 방지)
with st.sidebar.form(key="es_config_form"):
    st.title("ES 설정")
    es_host = st.text_input("ES 호스트", "http://localhost:9200")
    es_user = st.text_input("ES 사용자", "elastic")
    es_pass = st.text_input("ES 비밀번호", type="password")
    submit_es = st.form_submit_button("ES 연결")

if submit_es:
    try:
        es = Elasticsearch(hosts=[es_host], basic_auth=(es_user, es_pass), request_timeout=120, verify_certs=False)
        st.session_state.es = es
        st.sidebar.success("ES 연결 완료!")
    except Exception as e:
        st.sidebar.error(f"ES 연결 에러: {str(e)}")
        logger.error(f"ES 연결 에러: {e}")

# ES 연결 확인
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
        options=["대시보드", "로그 조회", "보고서 생성", "취약점 스캔", "알림 설정", "시스템 설정", "사용자 관리", "실시간 모니터링", "이상 탐지", "데이터 백업"],
        icons=["speedometer2", "search", "file-earmark-text", "bug", "bell", "gear", "people", "activity", "alert-triangle", "archive"],
        menu_icon="cast",
        default_index=0,
    )

# 추가 옵션 (공통 사이드바 아래)
with st.sidebar:
    st.title("검색 필터")
    search_term = st.text_input("로그 검색 (메시지 내 키워드)", "")
    event_id_filter = st.text_input("Event ID 필터", "")
    user_filter = st.text_input("User 필터", "")
    ip_filter = st.text_input("IP 필터", "")
    time_range = st.date_input("시간 범위", value=(datetime.now() - timedelta(days=30), datetime.now()))
    severity_filter = st.multiselect("Severity 필터", ["low", "medium", "high", "critical"], default=["low", "medium", "high"])
    regex_search = st.checkbox("정규식 검색 사용")
    auto_refresh = st.checkbox("자동 새로고침 (30초)")

# 페이징 함수 (페이지 크기 조정 가능)
def display_paginated_df(df, page_size=50, key_prefix="main"):
    if f'page_{key_prefix}' not in st.session_state:
        st.session_state[f'page_{key_prefix}'] = 0

    if len(df) == 0:
        st.info("표시할 로그가 없습니다.")
        return

    # 필터 적용
    if search_term and 'message' in df.columns:
        if regex_search:
            df = df[df['message'].str.contains(search_term, regex=True, na=False)]
        else:
            df = df[df['message'].str.contains(search_term, case=False, na=False)]

    if event_id_filter and 'winlog.event_id' in df.columns:
        df = df[df['winlog.event_id'].astype(str).str.contains(event_id_filter)]

    if user_filter and 'winlog.user.name' in df.columns:
        df = df[df['winlog.user.name'].str.contains(user_filter, case=False, na=False)]

    if ip_filter and 'host.ip' in df.columns:
        df = df[df['host.ip'].str.contains(ip_filter, case=False, na=False)]

    if '@timestamp' in df.columns:
        df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
        start_date, end_date = time_range
        df = df[(df['@timestamp'] >= pd.to_datetime(start_date)) & (df['@timestamp'] <= pd.to_datetime(end_date))]

    level_column = 'new_level' if 'new_level' in df.columns else 'level'
    if severity_filter:
        df = df[df[level_column].isin(severity_filter)]

    # 페이징
    total_pages = max(1, (len(df) - 1) // page_size + 1)
    col1, col2, col3 = st.columns([1, 3, 1])
    with col1:
        if st.button("이전", key=f"prev_{key_prefix}") and st.session_state[f'page_{key_prefix}'] > 0:
            st.session_state[f'page_{key_prefix}'] -= 1
    with col3:
        if st.button("다음", key=f"next_{key_prefix}") and st.session_state[f'page_{key_prefix}'] < total_pages - 1:
            st.session_state[f'page_{key_prefix}'] += 1
    with col2:
        st.write(f"페이지 {st.session_state[f'page_{key_prefix}'] + 1} / {total_pages} (총 {len(df)} 로그)")

    start = st.session_state[f'page_{key_prefix}'] * page_size
    end = min(start + page_size, len(df))
    page_df = df.iloc[start:end]

    # 컬럼 선택
    columns_to_show = [col for col in ['level', 'new_level', '@timestamp', 'message', 'winlog.user.name', 'winlog.event_id', 'host.ip', 'summary', 'vulns'] if col in page_df.columns]
    simplified_df = page_df[columns_to_show] if columns_to_show else page_df
    st.dataframe(simplified_df, use_container_width=True, height=500)

# 로그 트리 구조 (재귀적 그룹화)
def display_log_tree(df, group_by='winlog.event_id'):
    if group_by in df.columns:
        grouped = df.groupby(df[group_by])
        for name, group in grouped:
            with st.expander(f"🗂 {group_by}: {name} ({len(group)} logs)", expanded=False):
                sub_group_by = st.selectbox("하위 그룹화", ["None", "winlog.user.name", "host.ip"], key=f"subgroup_{name}")
                if sub_group_by != "None" and sub_group_by in group.columns:
                    display_log_tree(group, sub_group_by)
                else:
                    for idx, row in group.iterrows():
                        level = row.get('new_level', row.get('level', 'low'))
                        level_class = 'high-risk' if level in ['high', 'critical'] else 'medium-risk' if level == 'medium' else 'low-risk'
                        st.markdown(f"<div class='{level_class}'>- Timestamp: {row.get('@timestamp', 'N/A')}</div>", unsafe_allow_html=True)
                        st.markdown(f" Message: {row.get('message', 'N/A')}")
                        st.markdown(f" User: {row.get('winlog.user.name', 'N/A')}")
                        st.markdown(f" IP: {row.get('host.ip', 'N/A')}")
                        if 'summary' in row: st.markdown(f" Summary: {row['summary']}")
                        if 'vulns' in row: st.markdown(f" Vulns: {row['vulns']}")
                        st.markdown("---")
    else:
        display_paginated_df(df)

# 테스트 데이터 생성 함수 (개발용)
def generate_test_logs(num_logs=100):
    logs = []
    for i in range(num_logs):
        log = {
            '@timestamp': datetime.now() - timedelta(days=random.randint(0, 30)),
            'message': f"Test log message {i} with keyword {random.choice(['error', 'warning', 'info'])}",
            'winlog.event_id': random.randint(1000, 9999),
            'winlog.user.name': random.choice(['admin', 'user1', 'guest']),
            'host.ip': f"192.168.{random.randint(0,255)}.{random.randint(0,255)}",
            'level': random.choice(['low', 'medium', 'high', 'critical'])
        }
        logs.append(log)
    return pd.DataFrame(logs)

# ES 쿼리 함수 (재사용성)
def fetch_logs_from_es(query_body, index=".internal.alerts-security.alerts*"):
    try:
        res = es.search(index=index, body=query_body, scroll='5m')
        scroll_id = res['_scroll_id']
        logs = [hit['_source'] for hit in res['hits']['hits']]
        while len(res['hits']['hits']) > 0:
            res = es.scroll(scroll_id=scroll_id, scroll='5m')
            logs.extend([hit['_source'] for hit in res['hits']['hits']])
        return pd.DataFrame(logs)
    except Exception as e:
        st.error(f"ES 쿼리 에러: {str(e)}")
        logger.error(f"ES 쿼리 에러: {e}")
        return pd.DataFrame()

# 이상 탐지 함수 (간단 numpy 기반)
def detect_anomalies(df):
    if '@timestamp' in df.columns and 'level' in df.columns:
        df['numeric_level'] = df['level'].map({'low': 1, 'medium': 2, 'high': 3, 'critical': 4})
        hourly = df.set_index('@timestamp').resample('H')['numeric_level'].mean().fillna(0)
        mean = hourly.mean()
        std = hourly.std()
        anomalies = hourly[hourly > mean + 2 * std]
        return anomalies
    return pd.Series()

if selected == "대시보드":
    st.header("로그 대시보드 📊")
    if 'df' not in st.session_state or len(st.session_state.df) == 0:
        if st.button("테스트 데이터 로드"):
            st.session_state.df = generate_test_logs(500)
            st.success("테스트 데이터 로드 완료!")
    if 'df' in st.session_state and len(st.session_state.df) > 0:
        df = st.session_state.df.copy()

        # 시간별 차트 (Altair)
        if '@timestamp' in df.columns:
            df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
            df['hour'] = df['@timestamp'].dt.hour
            df['date'] = df['@timestamp'].dt.date
            time_chart = alt.Chart(df).mark_bar().encode(
                x='hour:O',
                y='count()',
                color='level',
                tooltip=['hour', 'count()', 'level']
            ).properties(title="시간별 로그 분포").interactive()
            st.altair_chart(time_chart, use_container_width=True)

            # 일별 차트 추가
            date_chart = alt.Chart(df).mark_line().encode(
                x='date:T',
                y='count()',
                color='level',
                tooltip=['date', 'count()', 'level']
            ).properties(title="일별 로그 추이").interactive()
            st.altair_chart(date_chart, use_container_width=True)

        # 레벨 분포 (Altair pie)
        level_counts = df['level'].value_counts().reset_index()
        level_counts.columns = ['level', 'count']
        pie_chart = alt.Chart(level_counts).mark_arc().encode(
            theta='count',
            color='level',
            tooltip=['level', 'count']
        ).properties(title="로그 레벨 분포").interactive()
        st.altair_chart(pie_chart, use_container_width=True)

        # Top 엔티티
        cols = st.columns(4)
        with cols[0]:
            if 'winlog.user.name' in df.columns:
                top_users = df['winlog.user.name'].value_counts().head(10).reset_index()
                top_users.columns = ['User', 'Count']
                st.subheader("Top 10 Users")
                st.table(top_users)
                user_chart = alt.Chart(top_users).mark_bar().encode(
                    x='User',
                    y='Count',
                    tooltip=['User', 'Count']
                )
                st.altair_chart(user_chart)

        with cols[1]:
            if 'winlog.event_id' in df.columns:
                top_events = df['winlog.event_id'].value_counts().head(10).reset_index()
                top_events.columns = ['Event ID', 'Count']
                st.subheader("Top 10 Events")
                st.table(top_events)
                event_chart = alt.Chart(top_events).mark_bar().encode(
                    x='Event ID',
                    y='Count',
                    tooltip=['Event ID', 'Count']
                )
                st.altair_chart(event_chart)

        with cols[2]:
            if 'host.ip' in df.columns:
                top_ips = df['host.ip'].value_counts().head(10).reset_index()
                top_ips.columns = ['IP', 'Count']
                st.subheader("Top 10 IPs")
                st.table(top_ips)
                ip_chart = alt.Chart(top_ips).mark_bar().encode(
                    x='IP',
                    y='Count',
                    tooltip=['IP', 'Count']
                )
                st.altair_chart(ip_chart)

        with cols[3]:
            if 'process.name' in df.columns:
                top_processes = df['process.name'].value_counts().head(10).reset_index()
                top_processes.columns = ['Process', 'Count']
                st.subheader("Top 10 Processes")
                st.table(top_processes)
                process_chart = alt.Chart(top_processes).mark_bar().encode(
                    x='Process',
                    y='Count',
                    tooltip=['Process', 'Count']
                )
                st.altair_chart(process_chart)

        # 메트릭 대시보드
        st.subheader("키 메트릭")
        cols_metric = st.columns(4)
        cols_metric[0].metric("총 로그", len(df))
        cols_metric[1].metric("High/Critical 로그", len(df[df['level'].isin(['high', 'critical'])]))
        cols_metric[2].metric("Unique Users", df['winlog.user.name'].nunique() if 'winlog.user.name' in df else 0)
        cols_metric[3].metric("Unique IPs", df['host.ip'].nunique() if 'host.ip' in df else 0)

    else:
        st.info("로그를 불러오거나 테스트 데이터를 로드하세요.")

elif selected == "로그 조회":
    st.header("로그 조회 🔍")
    col_load1, col_load2 = st.columns(2)
    with col_load1:
        evtx_file = st.file_uploader("EVTX 로그 업로드", type="evtx")
        if evtx_file and st.button("ES에 인덱싱"):
            with st.spinner("EVTX 파싱 & 인덱싱 중..."):
                parser = PyEvtxParser(evtx_file)
                actions = []
                count = 0
                for record in parser.records_json():
                    log_data = json.loads(record['data'])
                    event = xmltodict.parse(log_data['Event'])['Event']
                    actions.append({
                        "_index": ".internal.alerts-security.alerts*",
                        "_source": event
                    })
                    count += 1
                    if len(actions) >= 500:
                        helpers.bulk(es, actions)
                        actions = []
                if actions:
                    helpers.bulk(es, actions)
                st.success(f"{count}개 로그 인덱싱 완료!")

    with col_load2:
        if st.button("모든 로그 가져오기"):
            query = {
                "query": {"match_all": {}},
                "size": 1000,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            df = fetch_logs_from_es(query)
            if not df.empty:
                if 'kibana.alert.severity' in df.columns:
                    df['level'] = df['kibana.alert.severity'].str.lower()
                else:
                    df['level'] = 'low'
                st.session_state.df = df
                st.session_state.filtered_df = df.copy()
                st.success(f"총 {len(df)}개 로그 가져옴")
            else:
                st.warning("로그가 없습니다.")

    if 'df' in st.session_state:
        filtered_df = st.session_state.df.copy()
        # 레벨 버튼 필터
        cols_filter = st.columns(5)
        levels = ['low', 'medium', 'high', 'critical', 'all']
        for i, lvl in enumerate(levels):
            with cols_filter[i % 5]:
                if st.button(lvl.upper()):
                    if lvl == 'all':
                        st.session_state.filtered_df = st.session_state.df.copy()
                    else:
                        st.session_state.filtered_df = st.session_state.df[st.session_state.df['level'] == lvl]
                    st.session_state.page_logs = 0

        display_mode = st.radio("표시 모드", ["테이블", "트리", "JSON"])
        filtered_df = st.session_state.filtered_df
        if display_mode == "트리":
            group_by = st.selectbox("그룹화 기준", ["winlog.event_id", "winlog.user.name", "host.ip"])
            display_log_tree(filtered_df, group_by)
        elif display_mode == "JSON":
            st.json(filtered_df.to_dict(orient='records'))
        else:
            page_size = st.slider("페이지 크기", 10, 100, 50)
            display_paginated_df(filtered_df, page_size, "logs")

        # 상세 보기
        if not filtered_df.empty:
            selected_idx = st.selectbox("상세 로그 선택", filtered_df.index)
            if selected_idx is not None:
                row = filtered_df.loc[selected_idx]
                with st.expander("상세 정보"):
                    st.json(row.to_dict())
                    if st.button("이 로그 요약"):
                        prompt = f"요약: {row['message']}"
                        response = openai_client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}])
                        st.write(response.choices[0].message.content)

elif selected == "보고서 생성":
    st.header("보고서 생성 📄")
    report_type = st.selectbox("보고서 타입", ["요약 PDF", "상세 PDF", "CSV", "Excel", "JSON"])
    if 'df' in st.session_state and st.button("보고서 생성"):
        df = st.session_state.df.copy()
        if len(df) == 0:
            st.warning("로그 없음")
        else:
            with st.spinner("생성 중..."):
                for index, row in df.iterrows():
                    level = row.get('level', 'low')
                    log_text = row.get('message', str(row))
                    vulns = "N/A"
                    if 'process.name' in row:
                        try:
                            resp = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={row['process.name']}", timeout=10)
                            if resp.status_code == 200:
                                data = resp.json()
                                if data['totalResults'] > 0:
                                    vulns = f"{data['totalResults']} vulns found, e.g., {data['result']['CVE_Items'][0]['cve']['CVE_data_meta']['ID']}"
                        except:
                            pass
                    df.at[index, 'vulns'] = vulns
                    prompt = f"로그 요약, 위협 분석, 대응: {log_text}. 취약점: {vulns}. 레벨: {level}"
                    response = openai_client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}])
                    df.at[index, 'summary'] = response.choices[0].message.content

                st.session_state.df = df

            if report_type == "요약 PDF" or report_type == "상세 PDF":
                pdf_buffer = io.BytesIO()
                doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
                styles = getSampleStyleSheet()
                body_style = ParagraphStyle('Body', fontName='NanumGothic', fontSize=9 if report_type == "상세 PDF" else 10, wordWrap='CJK')
                elements = [Paragraph("SCP Shield 보고서", styles['Title'])]
                elements.append(Spacer(1, 12))
                data = [['ID', 'Timestamp', 'Message', 'Level', 'User', 'IP', 'Vulns', 'Summary']]
                for index, row in df.iterrows():
                    data.append([
                        str(index),
                        str(row.get('@timestamp', 'N/A')),
                        Paragraph(row.get('message', 'N/A')[:100] + '...' if report_type == "요약 PDF" else row.get('message', 'N/A'), body_style),
                        row.get('level', 'N/A'),
                        row.get('winlog.user.name', 'N/A'),
                        row.get('host.ip', 'N/A'),
                        Paragraph(row.get('vulns', 'N/A'), body_style),
                        Paragraph(row['summary'], body_style)
                    ])
                table = Table(data, colWidths=[30, 60, 150, 40, 50, 50, 80, 150])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'NanumGothic'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ]))
                elements.append(table)
                doc.build(elements)
                pdf_buffer.seek(0)
                st.download_button("PDF 다운로드", pdf_buffer, "report.pdf")

            elif report_type == "CSV":
                csv = df.to_csv(index=False).encode('utf-8-sig')
                st.download_button("CSV 다운로드", csv, "report.csv")
            elif report_type == "Excel":
                excel_buffer = io.BytesIO()
                df.to_excel(excel_buffer, index=False)
                excel_buffer.seek(0)
                st.download_button("Excel 다운로드", excel_buffer, "report.xlsx")
            elif report_type == "JSON":
                json_str = df.to_json(orient='records')
                st.download_button("JSON 다운로드", json_str, "report.json")

elif selected == "취약점 스캔":
    st.header("취약점 스캔 🐛")
    scan_type = st.selectbox("스캔 타입", ["키워드 검색", "전체 로그 스캔"])
    if scan_type == "키워드 검색":
        scan_query = st.text_input("검색 키워드 (e.g., CVE or process)")
        if st.button("스캔"):
            if scan_query:
                with st.spinner("NVD 스캔 중..."):
                    try:
                        resp = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={scan_query}", timeout=10)
                        if resp.status_code == 200:
                            data = resp.json()
                            if data['totalResults'] > 0:
                                vulns_df = pd.DataFrame([item['cve']['CVE_data_meta'] for item in data['result']['CVE_Items']])
                                st.dataframe(vulns_df)
                                st.metric("총 취약점", data['totalResults'])
                                # 상세 보기
                                selected_cve = st.selectbox("CVE 상세", vulns_df['ID'])
                                if selected_cve:
                                    cve_data = next(item for item in data['result']['CVE_Items'] if item['cve']['CVE_data_meta']['ID'] == selected_cve)
                                    st.json(cve_data)
                            else:
                                st.info("취약점 없음")
                    except Exception as e:
                        st.error(f"스캔 에러: {str(e)}")
    else:
        if 'df' in st.session_state and st.button("로그 기반 스캔"):
            df = st.session_state.df
            vulns_list = []
            for _, row in df.iterrows():
                if 'process.name' in row:
                    try:
                        resp = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={row['process.name']}", timeout=5)
                        if resp.status_code == 200:
                            data = resp.json()
                            if data['totalResults'] > 0:
                                vulns_list.append({'log_index': _, 'vulns_count': data['totalResults'], 'example': data['result']['CVE_Items'][0]['cve']['CVE_data_meta']['ID']})
                    except:
                        pass
            if vulns_list:
                vulns_df = pd.DataFrame(vulns_list)
                st.dataframe(vulns_df)
            else:
                st.info("취약점 없음")

elif selected == "알림 설정":
    st.header("알림 설정 🔔")
    if st.session_state.user_role != 'admin':
        st.warning("관리자만 접근 가능")
        st.stop()
    email_to = st.text_input("수신 이메일")
    smtp_server = st.text_input("SMTP 서버", "smtp.gmail.com")
    smtp_port = st.number_input("포트", 587)
    smtp_user = st.text_input("SMTP 사용자")
    smtp_pass = st.text_input("SMTP 비밀번호", type="password")
    alert_threshold = st.slider("High/Critical 임계값", 1, 100, 10)
    alert_interval = st.slider("알림 간격 (분)", 1, 60, 5)

    if st.button("설정 저장"):
        st.session_state.alert_config = {
            'email_to': email_to,
            'smtp_server': smtp_server,
            'smtp_port': smtp_port,
            'smtp_user': smtp_user,
            'smtp_pass': smtp_pass,
            'threshold': alert_threshold,
            'interval': alert_interval
        }
        st.success("설정 저장됨")

    if 'alert_config' in st.session_state and st.button("알림 테스트"):
        config = st.session_state.alert_config
        try:
            server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
            server.starttls()
            server.login(config['smtp_user'], config['smtp_pass'])
            msg = MIMEMultipart()
            msg['From'] = config['smtp_user']
            msg['To'] = config['email_to']
            msg['Subject'] = "SCP Shield 테스트 알림"
            body = "테스트 알림입니다."
            msg.attach(MIMEText(body, 'plain'))
            server.sendmail(config['smtp_user'], config['email_to'], msg.as_string())
            server.quit()
            st.success("테스트 알림 전송!")
        except Exception as e:
            st.error(f"에러: {str(e)}")

elif selected == "시스템 설정":
    st.header("시스템 설정 ⚙️")
    if st.session_state.user_role != 'admin':
        st.warning("관리자만 접근 가능")
        st.stop()
    st.subheader("로그 보관 정책")
    retention_days = st.slider("보관 일수", 7, 365, 30)
    if st.button("오래된 오래된 로그 삭제"):
        delete_query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "lt": f"now-{retention_days}d/d"
                    }
                }
            }
        }
        try:
            res = es.delete_by_query(index=".internal.alerts-security.alerts*", body=delete_query)
            st.success(f"{res['deleted']}개 로그 삭제")
        except Exception as e:
            st.error(f"에러: {str(e)}")

    st.subheader("인덱스 관리")
    index_name = st.text_input("새 인덱스 이름")
    if st.button("인덱스 생성"):
        try:
            es.indices.create(index=index_name)
            st.success("인덱스 생성 완료")
        except Exception as e:
            st.error(f"에러: {str(e)}")

    st.subheader("ES 클러스터 상태")
    if st.button("상태 확인"):
        try:
            health = es.cluster.health()
            st.json(health)
        except Exception as e:
            st.error(f"에러: {str(e)}")

elif selected == "사용자 관리":
    st.header("사용자 관리 👥")
    if st.session_state.user_role != 'admin':
        st.warning("관리자만 접근 가능")
        st.stop()
    c = conn.cursor()
    c.execute("SELECT username, role FROM users")
    users = c.fetchall()
    users_df = pd.DataFrame(users, columns=['Username', 'Role'])
    st.dataframe(users_df)

    st.subheader("사용자 추가")
    new_user = st.text_input("새 사용자명")
    new_pass = st.text_input("비밀번호", type="password")
    new_role = st.selectbox("역할", ["user", "admin"])
    if st.button("추가"):
        if register_user(new_user, new_pass, new_role):
            st.success("추가 완료")
            st.rerun()
        else:
            st.error("이미 존재")

    st.subheader("사용자 삭제")
    del_user = st.selectbox("삭제할 사용자", users_df['Username'])
    if st.button("삭제"):
        c.execute("DELETE FROM users WHERE username=?", (del_user,))
        conn.commit()
        st.success("삭제 완료")
        st.rerun()

elif selected == "실시간 모니터링":
    st.header("실시간 모니터링 ⏱️")
    if st.button("모니터링 시작"):
        st.session_state.monitoring = True
    if 'monitoring' in st.session_state and st.session_state.monitoring:
        placeholder = st.empty()
        while True:
            query = {
                "query": {"range": {"@timestamp": {"gte": "now-1m"}}},
                "size": 100,
                "sort": [{"@timestamp": "desc"}]
            }
            new_df = fetch_logs_from_es(query)
            if not new_df.empty:
                placeholder.dataframe(new_df)
            time.sleep(30)  # Streamlit에서 스레드 필요하지만, 간단 시뮬
            if auto_refresh:
                st.rerun()
    else:
        st.info("모니터링 시작 버튼을 누르세요.")

elif selected == "이상 탐지":
    st.header("이상 탐지 🚨")
    if 'df' in st.session_state:
        anomalies = detect_anomalies(st.session_state.df)
        if not anomalies.empty:
            st.subheader("탐지된 이상")
            anomaly_df = anomalies.reset_index()
            anomaly_df.columns = ['Time', 'Anomaly Score']
            anomaly_chart = alt.Chart(anomaly_df).mark_line().encode(
                x='Time:T',
                y='Anomaly Score',
                tooltip=['Time', 'Anomaly Score']
            ).properties(title="이상 점수 추이").interactive()
            st.altair_chart(anomaly_chart, use_container_width=True)
            st.dataframe(anomalies)
        else:
            st.info("이상 없음")
    if st.button("ML 기반 재학습"):
        st.info("간단 numpy 기반, 고급 ML은 torch 사용 가능 but not implemented")

elif selected == "데이터 백업":
    st.header("데이터 백업 💾")
    backup_type = st.selectbox("백업 타입", ["로그 CSV", "전체 DB", "ES 스냅샷"])
    if st.button("백업 생성"):
        if backup_type == "로그 CSV":
            if 'df' in st.session_state:
                csv = st.session_state.df.to_csv(index=False).encode('utf-8-sig')
                st.download_button("다운로드", csv, "backup.csv")
        elif backup_type == "전체 DB":
            shutil.copy('users.db', 'backup_users.db')
            with open('backup_users.db', 'rb') as f:
                st.download_button("DB 다운로드", f, "backup_users.db")
        elif backup_type == "ES 스냅샷":
            st.info("ES 스냅샷 기능은 ES 설정 필요, 여기서는 시뮬")
            # 실제 구현: es.snapshot.create(repository='repo', snapshot='snap1')

# 푸터
st.markdown("---")
st.markdown(f"SCP Shield v3.0 | 사용자: {st.session_state.username} ({st.session_state.user_role}) | © 2025")
