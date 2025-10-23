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
import requests  # 취약점 API 호출용, VirusTotal 포함
import base64  # 이미지 인코딩
import streamlit.components.v1 as components  # HTML 컴포넌트
from PIL import Image as PILImage  # 이미지 처리
import os  # 파일 관리
import smtplib  # 이메일 보내기
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import time  # 실시간 업데이트 시뮬레이션
import random  # 테스트 데이터 생성
from collections import defaultdict  # 데이터 구조
import zipfile  # 백업 압축
import shutil  # 파일 복사
import logging  # 로깅
from io import StringIO  # 문자열 IO
import re  # 정규식 검색

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

# VirusTotal API 키
VT_API_KEY = "45848f3c007559530ef8923c7b6d819d2d240a87f472e8ad3edb57051210b9ee"

# 테마 설정 (다크/라이트 모드)
theme = st.sidebar.selectbox("테마 선택", ["Dark", "Light"])
if theme == "Dark":
    st.markdown("""
        <style>
        .main {background-color: #0e1117; color: #fafafa;}
        .stButton > button {background-color: #4CAF50; color: white; border-radius: 8px; border: none; padding: 10px 24px; font-weight: bold;}
        .stButton > button:hover {background-color: #45a049;}
        .stExpander {border: 1px solid #333; border-radius: 8px; background-color: #1c1f2b;}
        .stMetric {font-size: 1.4em; color: #fafafa;}
        .high-risk {color: #ff4b4b; font-weight: bold;}
        .medium-risk {color: #ffb74d;}
        .low-risk {color: #81c784;}
        .stSidebar {background-color: #0e1117;}
        .stDataFrame {background-color: #1c1f2b; color: #fafafa; border-radius: 8px;}
        .stSelectbox, .stTextInput {background-color: #1c1f2b; color: #fafafa; border-radius: 8px; border: 1px solid #333;}
        .stSlider {color: #fafafa;}
        .reportview-container .main .block-container {background-color: #0e1117; padding: 2rem; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);}
        .custom-chart {background-color: #1c1f2b; border-radius: 8px; padding: 10px;}
        h1, h2, h3 {color: #fafafa; font-family: 'Arial', sans-serif;}
        .stTabs [data-baseweb="tab-list"] {gap: 24px;}
        .stTabs [data-baseweb="tab"] {height: 50px; white-space: pre-wrap; background-color: #1c1f2b; border-radius: 4px 4px 0 0; color: #fafafa; font-weight: bold;}
        .stTabs [aria-selected="true"] {background-color: #0e1117;}
        </style>
        """, unsafe_allow_html=True)
else:
    st.markdown("""
        <style>
        .main {background-color: #f6f7f9; color: #333;}
        .stButton > button {background-color: #4CAF50; color: white; border-radius: 8px; border: none; padding: 10px 24px; font-weight: bold;}
        .stButton > button:hover {background-color: #45a049;}
        .stExpander {border: 1px solid #ddd; border-radius: 8px; background-color: #ffffff;}
        .stMetric {font-size: 1.4em; color: #333;}
        .high-risk {color: #ff4b4b; font-weight: bold;}
        .medium-risk {color: #ffb74d;}
        .low-risk {color: #81c784;}
        .stSidebar {background-color: #ffffff; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
        .stDataFrame {background-color: #ffffff; color: #333; border-radius: 8px; border: 1px solid #ddd;}
        .stSelectbox, .stTextInput {background-color: #ffffff; color: #333; border-radius: 8px; border: 1px solid #ddd;}
        .stSlider {color: #333;}
        .reportview-container .main .block-container {background-color: #f6f7f9; padding: 2rem; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.05);}
        .custom-chart {background-color: #ffffff; border-radius: 8px; padding: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);}
        h1, h2, h3 {color: #333; font-family: 'Arial', sans-serif;}
        .stTabs [data-baseweb="tab-list"] {gap: 24px;}
        .stTabs [data-baseweb="tab"] {height: 50px; white-space: pre-wrap; background-color: #ffffff; border-radius: 4px 4px 0 0; color: #333; font-weight: bold; border: 1px solid #ddd; border-bottom: none;}
        .stTabs [aria-selected="true"] {background-color: #f6f7f9; border-bottom: 2px solid #4CAF50;}
        </style>
        """, unsafe_allow_html=True)

st.set_page_config(layout="wide", page_title="SCP Shield Pro", page_icon="🛡️")

# GPT 설정 (API 키 secrets 사용)
try:
    openai_client = OpenAI(api_key=st.secrets["OPENAI_API_KEY"])
except KeyError:
    st.error("OPENAI_API_KEY가 설정되지 않았습니다. secrets.toml에 추가하세요.")
    st.stop()

# ES 연결 (사용자 입력 호스트/인증, form으로 감싸서 오류 방지)
with st.sidebar.form(key="es_config_form"):
    st.title("ElasticSearch 설정")
    es_host = st.text_input("ES 호스트", "http://3.38.65.230:9200")
    es_user = st.text_input("ES 사용자", "elastic")
    es_pass = st.text_input("ES 비밀번호", type="password")
    submit_es = st.form_submit_button("연결")

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

# 앱 타이틀
st.title("SCP Shield Pro 🛡️")
st.markdown("Advanced AI-Powered Threat Detection and Analysis Platform")

# 사이드바 메뉴
menu_options = ["대시보드", "로그 조회", "보고서 생성", "취약점 스캔 (VirusTotal 통합)", "알림 설정", "시스템 설정", "실시간 모니터링", "이상 탐지", "데이터 백업"]
selected = st.sidebar.selectbox("메인 메뉴", menu_options)

# 추가 옵션
with st.sidebar:
    st.title("검색 & 필터")
    search_term = st.text_input("키워드 검색", "")
    event_id_filter = st.text_input("Event ID 필터", "")
    user_filter = st.text_input("User 필터", "")
    ip_filter = st.text_input("IP 필터", "")
    time_range = st.date_input("시간 범위", value=(datetime.now() - timedelta(days=30), datetime.now()))
    severity_filter = st.multiselect("Severity 수준", ["low", "medium", "high", "critical"], default=["low", "medium", "high"])
    regex_search = st.checkbox("정규식 검색")
    auto_refresh = st.checkbox("자동 새로고침 (30초)")

# 페이징 함수
def display_paginated_df(df, page_size=50, key_prefix="main"):
    if f'page_{key_prefix}' not in st.session_state:
        st.session_state[f'page_{key_prefix}'] = 0

    if len(df) == 0:
        st.info("데이터 없음.")
        return

    # 필터 적용
    if search_term and 'message' in df.columns:
        df = df[df['message'].str.contains(search_term, regex=regex_search, case=False, na=False)]

    if event_id_filter and 'winlog.event_id' in df.columns:
        df = df[df['winlog.event_id'].astype(str).str.contains(event_id_filter)]

    if user_filter and 'winlog.user.name' in df.columns:
        df = df[df['winlog.user.name'].str.contains(user_filter, case=False, na=False)]

    if ip_filter and 'host.ip' in df.columns:
        df = df[df['host.ip'].str.contains(ip_filter, case=False, na=False)]

    if '@timestamp' in df.columns:
        df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
        start_date, end_date = time_range
        start_date = pd.to_datetime(start_date, utc=True)
        end_date = pd.to_datetime(end_date, utc=True)
        df = df[(df['@timestamp'] >= start_date) & (df['@timestamp'] <= end_date)]

    level_column = 'new_level' if 'new_level' in df.columns else 'level'
    if severity_filter:
        df = df[df[level_column].isin(severity_filter)]

    total_pages = max(1, (len(df) - 1) // page_size + 1)
    col1, col2, col3 = st.columns([1, 3, 1])
    with col1:
        if st.button("◀ 이전", key=f"prev_{key_prefix}") and st.session_state[f'page_{key_prefix}'] > 0:
            st.session_state[f'page_{key_prefix}'] -= 1
    with col3:
        if st.button("다음 ▶", key=f"next_{key_prefix}") and st.session_state[f'page_{key_prefix}'] < total_pages - 1:
            st.session_state[f'page_{key_prefix}'] += 1
    with col2:
        st.write(f"페이지 {st.session_state[f'page_{key_prefix}'] + 1} / {total_pages} (총 {len(df)} 항목)")

    start = st.session_state[f'page_{key_prefix}'] * page_size
    end = min(start + page_size, len(df))
    page_df = df.iloc[start:end]

    columns_to_show = [col for col in ['level', 'new_level', '@timestamp', 'message', 'winlog.user.name', 'winlog.event_id', 'host.ip', 'summary', 'vulns'] if col in page_df.columns]
    simplified_df = page_df[columns_to_show] if columns_to_show else page_df
    st.dataframe(simplified_df, use_container_width=True, height=500)

# 로그 트리 구조
def display_log_tree(df, group_by='winlog.event_id'):
    if group_by in df.columns:
        grouped = df.groupby(df[group_by])
        for name, group in grouped:
            with st.expander(f"📁 {group_by}: {name} ({len(group)})", expanded=False):
                sub_group_by = st.selectbox("하위 그룹", ["None", "winlog.user.name", "host.ip"], key=f"sub_{name}")
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

# ES 로그 가져오기
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
        return pd.DataFrame()

# VirusTotal 해시 스캔
def scan_hash_with_vt(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()['data']['attributes']
            malicious = data.get('last_analysis_stats', {}).get('malicious', 0)
            return malicious, data
        else:
            return 0, None
    except Exception as e:
        logger.error(f"VT 스캔 에러: {e}")
        return 0, None

# 이상 탐지
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
    st.header("지능형 위협 대시보드")
    if 'df' not in st.session_state or len(st.session_state.df) == 0:
        st.info("로그를 불러오세요.")
    if 'df' in st.session_state and len(st.session_state.df) > 0:
        df = st.session_state.df.copy()

        if '@timestamp' in df.columns:
            df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
            df['hour'] = df['@timestamp'].dt.hour
            df['date'] = df['@timestamp'].dt.date
            time_chart = alt.Chart(df).mark_bar(color='#4CAF50').encode(
                x='hour:O',
                y='count()',
                color='level',
                tooltip=['hour', 'count()', 'level']
            ).properties(title="시간별 로그 분포", width=700).interactive()
            st.altair_chart(time_chart, use_container_width=True)

            date_chart = alt.Chart(df).mark_line(color='#2196F3').encode(
                x='date:T',
                y='count()',
                color='level',
                tooltip=['date', 'count()', 'level']
            ).properties(title="일별 로그 추이", width=700).interactive()
            st.altair_chart(date_chart, use_container_width=True)

        level_counts = df['level'].value_counts().reset_index()
        level_counts.columns = ['level', 'count']
        pie_chart = alt.Chart(level_counts).mark_arc().encode(
            theta='count',
            color='level',
            tooltip=['level', 'count']
        ).properties(title="로그 수준 분포", width=400).interactive()
        st.altair_chart(pie_chart, use_container_width=True)

        st.subheader("탑 엔티티 분석")
        cols = st.columns(4)
        entity_lists = [
            ('winlog.user.name', 'Top Users', cols[0]),
            ('winlog.event_id', 'Top Events', cols[1]),
            ('host.ip', 'Top IPs', cols[2]),
            ('process.name', 'Top Processes', cols[3])
        ]
        for col_name, title, col in entity_lists:
            if col_name in df.columns:
                top = df[col_name].value_counts().head(10).reset_index()
                top.columns = [title.split()[-1], 'Count']
                with col:
                    st.subheader(title)
                    st.table(top)
                    chart = alt.Chart(top).mark_bar(color='#FF9800').encode(
                        x=title.split()[-1],
                        y='Count',
                        tooltip=[title.split()[-1], 'Count']
                    )
                    st.altair_chart(chart)

        st.subheader("키 메트릭")
        metric_cols = st.columns(4)
        metric_cols[0].metric("총 로그", len(df), delta_color="normal")
        metric_cols[1].metric("High/Critical", len(df[df['level'].isin(['high', 'critical'])]), delta_color="inverse")
        metric_cols[2].metric("Unique Users", df['winlog.user.name'].nunique() if 'winlog.user.name' in df else 0)
        metric_cols[3].metric("Unique IPs", df['host.ip'].nunique() if 'host.ip' in df else 0)

    else:
        st.info("로그를 불러오세요.")

elif selected == "로그 조회":
    st.header("로그 조회 & 분석")
    col1, col2 = st.columns(2)
    with col1:
        evtx_file = st.file_uploader("EVTX 파일 업로드", type="evtx")
        if evtx_file and st.button("인덱싱", type="primary"):
            with st.spinner("파싱 & 인덱싱 중..."):
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

    with col2:
        if st.button("로그 불러오기", type="primary"):
            query = {
                "query": {"match_all": {}},
                "size": 1000,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            df = fetch_logs_from_es(query)
            if not df.empty:
                df['level'] = df.get('kibana.alert.severity', 'low').str.lower()
                st.session_state.df = df
                st.session_state.filtered_df = df.copy()
                st.success(f"총 {len(df)}개 로그 불러옴")
            else:
                st.warning("로그 없음.")

    if 'df' in st.session_state:
        filtered_df = st.session_state.filtered_df if 'filtered_df' in st.session_state else st.session_state.df
        cols_filter = st.columns(5)
        levels = ['low', 'medium', 'high', 'critical', 'all']
        for i, lvl in enumerate(levels):
            with cols_filter[i]:
                if st.button(lvl.upper(), type="secondary"):
                    if lvl == 'all':
                        st.session_state.filtered_df = st.session_state.df.copy()
                    else:
                        st.session_state.filtered_df = st.session_state.df[st.session_state.df['level'] == lvl]
                    st.session_state.page_logs = 0

        display_mode = st.radio("뷰 모드", ["테이블", "트리 구조", "JSON 뷰"])
        if display_mode == "트리 구조":
            group_by = st.selectbox("그룹 기준", ["winlog.event_id", "winlog.user.name", "host.ip"])
            display_log_tree(filtered_df, group_by)
        elif display_mode == "JSON 뷰":
            st.json(filtered_df.to_dict(orient='records'))
        else:
            page_size = st.slider("페이지 크기", 10, 100, 50, 10)
            display_paginated_df(filtered_df, page_size, "logs")

        if not filtered_df.empty:
            selected_idx = st.selectbox("상세 로그", filtered_df.index)
            if selected_idx is not None:
                row = filtered_df.loc[selected_idx]
                with st.expander("로그 상세 분석"):
                    st.json(row.to_dict())
                    if st.button("LLM 요약 생성", type="primary"):
                        prompt = f"이 로그를 분석하고 위협 수준, 대응 방안 제안: {row['message']}"
                        response = openai_client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}])
                        st.write(response.choices[0].message.content)

elif selected == "취약점 스캔 (VirusTotal 통합)":
    st.header("취약점 & 악성코드 스캔")
    scan_type = st.selectbox("스캔 타입", ["NVD 키워드 검색", "VirusTotal 해시 스캔 (로그 기반)"])
    if scan_type == "NVD 키워드 검색":
        scan_query = st.text_input("키워드 (e.g., process or CVE)")
        if st.button("스캔 시작", type="primary"):
            if scan_query:
                with st.spinner("NVD 검색 중..."):
                    try:
                        resp = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={scan_query}", timeout=10)
                        if resp.status_code == 200:
                            data = resp.json()
                            if data['totalResults'] > 0:
                                vulns_df = pd.DataFrame([item['cve']['CVE_data_meta'] for item in data['result']['CVE_Items']])
                                st.dataframe(vulns_df, use_container_width=True)
                                st.metric("총 취약점", data['totalResults'], delta_color="inverse")
                                selected_cve = st.selectbox("CVE 상세 보기", vulns_df['ID'])
                                if selected_cve:
                                    cve_data = next(item for item in data['result']['CVE_Items'] if item['cve']['CVE_data_meta']['ID'] == selected_cve)
                                    st.json(cve_data)
                            else:
                                st.info("취약점 발견되지 않음.")
                    except Exception as e:
                        st.error(f"스캔 에러: {str(e)}")
    else:
        if st.button("로그 기반 VT 스캔", type="primary"):
            query = {
                "query": {"match_all": {}},
                "size": 1000,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            df = fetch_logs_from_es(query)
            if not df.empty:
                df['level'] = df.get('kibana.alert.severity', 'low').str.lower()
                st.session_state.df = df
                st.session_state.filtered_df = df.copy()
            else:
                st.warning("로그 없음.")
                st.stop()
            # medium, high 수준 로그 필터
            risk_levels = ['medium', 'high', 'critical']
            risk_df = df[df['level'].isin(risk_levels)]
            high_score_logs = []
            with st.spinner("VirusTotal 스캔 중... (악성 점수 > 5)"):
                for _, row in risk_df.iterrows():
                    if 'winlog.event_data.Hashes' in row and row['winlog.event_data.Hashes']:
                        # 실제 ES 필드에 맞게 'winlog.event_data.Hashes' 가정, 필요시 변경
                        hash_value = row['winlog.event_data.Hashes'].split('SHA256=')[1] if 'SHA256=' in row['winlog.event_data.Hashes'] else None
                        if hash_value:
                            malicious, data = scan_hash_with_vt(hash_value)
                            if malicious > 5:
                                high_score_logs.append({'log': row['message'], 'level': row['level'], 'hash': hash_value, 'malicious_score': malicious, 'vt_data': data})

            if high_score_logs:
                high_df = pd.DataFrame(high_score_logs)
                st.subheader("고위험 로그 (악성 점수 > 5, medium/high 수준)")
                st.dataframe(high_df[['log', 'level', 'hash', 'malicious_score']])

                if st.button("LLM 취약점 분석 보고서 생성", type="primary"):
                    with st.spinner("LLM 보고서 생성 중..."):
                        reports = []
                        for item in high_score_logs:
                            prompt = f"이 로그와 VirusTotal 데이터를 기반으로 취약점 분석 보고서 작성: 로그 - {item['log']}, 레벨 - {item['level']}, VT 데이터 - {json.dumps(item['vt_data'])}. 잠재적 위협, 취약점 상세, 대응 방안 포함."
                            response = openai_client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": prompt}])
                            reports.append(response.choices[0].message.content)
                        st.subheader("취약점 분석 보고서")
                        for report in reports:
                            st.markdown(report)
                            st.markdown("---")
            else:
                st.info("고위험 항목 없음.")

elif selected == "보고서 생성":
    st.header("분석 보고서 생성")
    # 기존 보고서 생성 로직, VT 데이터 포함 가능
    if 'df' in st.session_state and st.button("보고서 생성", type="primary"):
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
                    response = openai_client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[{"role": "user", "content": prompt}]
                    )
                    df.at[index, 'summary'] = response.choices[0].message.content

                st.session_state.df = df
                st.success("요약 완료!")

            pdf_buffer = io.BytesIO()
            doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            body_style = ParagraphStyle('Body', fontName='NanumGothic', fontSize=10, wordWrap='CJK')
            elements = [Paragraph("로그 분석 보고서", styles['Title'])]
            data = [['로그 ID', '메시지 (짧게)', '레벨', '요약']]
            for index, row in df.iterrows():
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

# 다른 섹션 생략, 필요시 추가
# 푸터
st.markdown("---")
st.markdown("SCP Shield Pro | AI-Driven Security Intelligence | © 2025 xAI")
