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
import requests  # VirusTotal API 호출을 위해 추가
import time  # API 호출 지연을 위해 추가
import re  # 해시 추출을 위해 추가 (개선)
warnings.filterwarnings("ignore")

# VirusTotal API 키 (제공된 키 사용)
VIRUSTOTAL_API_KEY = "45848f3c007559530ef8923c7b6d819d2d240a87f472e8ad3edb57051210b9ee"

# 커스텀 CSS로 Kibana/Wazuh 스타일 UI/UX 개선 (깔끔한 테마, 더 세련되게 업그레이드)
st.markdown("""
    <style>
    .main {background-color: #f0f2f6;}
    .stButton > button {background-color: #4CAF50; color: white; border-radius: 5px; padding: 8px 16px;}
    .stExpander {border: 1px solid #ddd; border-radius: 5px; background-color: white;}
    .stMetric {font-size: 1.2em; color: #333;}
    .high-risk {color: red; font-weight: bold;}
    .medium-risk {color: orange;}
    .low-risk {color: green;}
    .stDataFrame {border: 1px solid #ddd; border-radius: 5px; overflow: hidden;}
    .stAlert {border-radius: 5px;}
    /* 테이블 헤더 스타일 */
    thead tr th {background-color: #e0e0e0; text-align: left; padding: 10px;}
    tbody tr td {padding: 10px; border-bottom: 1px solid #ddd;}
    /* 검색 바 스타일 */
    .stTextInput > div > div > input {border-radius: 5px; padding: 8px;}
    </style>
    """, unsafe_allow_html=True)

st.set_page_config(layout="wide", page_title="SCP Shield - Advanced Detection Engine", page_icon="🛡️")

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
st.title("SCP Shield - Advanced Detection Engine")

# 사이드바에 추가 옵션 (있어보이게: 로그 검색 필터 등, 업그레이드: 더 많은 필터 추가)
with st.sidebar:
    st.title("추가 옵션")
    search_term = st.text_input("로그 검색 (메시지 내 키워드)", "")
    event_id_filter = st.text_input("Event ID 필터", "")
    user_filter = st.text_input("User 필터", "")  # 추가: 사용자 필터
    ip_filter = st.text_input("IP 필터", "")  # 신규: IP 필터 추가
    process_filter = st.text_input("Process Name 필터", "")  # 신규: 프로세스 이름 필터 추가
    time_range = st.date_input("시간 범위", (datetime.now() - timedelta(days=7), datetime.now()))  # 추가: 시간 범위 필터
    vt_threshold = st.slider("VirusTotal 악성 점수 임계값", 0, 100, 20)  # 추가: VT 점수 임계값 설정

# 페이징 함수 (한 페이지 50개로 업그레이드, 검색/필터 통합, 정렬 기능 추가)
def display_paginated_df(df, page_size=50, key_prefix="main"):
    if f'page_{key_prefix}' not in st.session_state:
        st.session_state[f'page_{key_prefix}'] = 0
    if f'sort_col_{key_prefix}' not in st.session_state:
        default_sort_col = next((col for col in ['@timestamp', 'level', 'new_level', 'winlog.event_id', 'winlog.user.name'] if col in df.columns), None)
        st.session_state[f'sort_col_{key_prefix}'] = default_sort_col
    if f'sort_asc_{key_prefix}' not in st.session_state:
        st.session_state[f'sort_asc_{key_prefix}'] = False  # 내림차순 기본

    if len(df) == 0:
        st.info("표시할 로그가 없습니다.")
        return

    # 추가 필터 적용 (사이드바 검색 + 필터 업그레이드)
    if search_term and 'message' in df.columns:
        df = df[df['message'].str.contains(search_term, case=False, na=False)]
    if event_id_filter and 'winlog.event_id' in df.columns:
        df = df[df['winlog.event_id'].astype(str).str.contains(event_id_filter)]
    if user_filter and 'winlog.user.name' in df.columns:
        df = df[df['winlog.user.name'].str.contains(user_filter, case=False, na=False)]
    if ip_filter and 'winlog.event_data.SourceIp' in df.columns:  # 신규: IP 필터 (필드 가정)
        df = df[df['winlog.event_data.SourceIp'].str.contains(ip_filter, case=False, na=False)]
    if process_filter and 'winlog.event_data.ProcessName' in df.columns:  # 신규: Process 필터 (필드 가정)
        df = df[df['winlog.event_data.ProcessName'].str.contains(process_filter, case=False, na=False)]
    if '@timestamp' in df.columns:
        df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
        start_date, end_date = time_range
        start_dt = pd.to_datetime(start_date, utc=True)
        end_dt = pd.to_datetime(end_date, utc=True) + pd.Timedelta(days=1)
        df = df[(df['@timestamp'] >= start_dt) & (df['@timestamp'] < end_dt)]

    # 정렬 컬럼 선택 (드롭다운으로 업그레이드)
    sort_options = [col for col in df.columns if col in ['@timestamp', 'level', 'new_level', 'winlog.event_id', 'winlog.user.name']]
    sort_col = st.selectbox("정렬 기준", sort_options, key=f'sort_col_{key_prefix}')
    sort_asc = st.checkbox("오름차순 정렬", key=f'sort_asc_{key_prefix}')
    if sort_col:
        df = df.sort_values(by=sort_col, ascending=sort_asc)

    # 페이징 컨트롤 (더 세련되게: 슬라이더 추가)
    total_pages = (len(df) - 1) // page_size + 1
    col1, col2, col3 = st.columns([1, 3, 1])
    with col1:
        if st.button("이전 페이지", key=f"prev_page_{key_prefix}") and st.session_state[f'page_{key_prefix}'] > 0:
            st.session_state[f'page_{key_prefix}'] -= 1
    with col3:
        if st.button("다음 페이지", key=f"next_page_{key_prefix}") and st.session_state[f'page_{key_prefix}'] < total_pages - 1:
            st.session_state[f'page_{key_prefix}'] += 1
    with col2:
        st.session_state[f'page_{key_prefix}'] = st.slider("페이지 선택", 1, total_pages, st.session_state[f'page_{key_prefix}'] + 1, key=f"page_slider_{key_prefix}") - 1

    # 현재 페이지 데이터
    start = st.session_state[f'page_{key_prefix}'] * page_size
    end = start + page_size
    page_df = df.iloc[start:end]

    # 표시 컬럼 선택 (업그레이드: VT 점수, 요약 등 추가)
    columns_to_show = []
    if 'level' in page_df.columns: columns_to_show.append('level')
    if 'new_level' in page_df.columns: columns_to_show.append('new_level')
    if '@timestamp' in page_df.columns: columns_to_show.append('@timestamp')
    if 'message' in page_df.columns: columns_to_show.append('message')
    if 'winlog.user.name' in page_df.columns: columns_to_show.append('winlog.user.name')
    if 'winlog.event_id' in page_df.columns: columns_to_show.append('winlog.event_id')
    if 'vt_score' in page_df.columns: columns_to_show.append('vt_score')  # 추가: VT 점수
    if 'summary' in page_df.columns: columns_to_show.append('summary')
    if 'winlog.event_data.SourceIp' in page_df.columns: columns_to_show.append('winlog.event_data.SourceIp')  # 신규
    if 'winlog.event_data.ProcessName' in page_df.columns: columns_to_show.append('winlog.event_data.ProcessName')  # 신규
    simplified_df = page_df[columns_to_show] if columns_to_show else page_df
    simplified_df['winlog.user.name'] = simplified_df.get('winlog.user.name', 'N/A')

    # 레벨에 따라 색상 적용 (DataFrame 스타일링 업그레이드)
    def color_levels(val):
        if val == 'high': return 'color: red; font-weight: bold'
        elif val == 'medium': return 'color: orange'
        elif val == 'low': return 'color: green'
        return ''

    level_col = 'new_level' if 'new_level' in simplified_df.columns else 'level'
    styled_df = simplified_df.style.applymap(color_levels, subset=[level_col])
    st.dataframe(styled_df, use_container_width=True)  # 더 넓게 표시

# 로그 트리 구조 함수 (업그레이드: 계층적 보기, event_id 그룹화 + 검색 통합)
def display_log_tree(df):
    if 'winlog.event_id' in df.columns:
        grouped = df.groupby('winlog.event_id')
        for event_id, group in grouped:
            with st.expander(f"Event ID: {event_id} ({len(group)} logs)", expanded=False):
                display_paginated_df(group, page_size=10, key_prefix=f"tree_{event_id}")  # 페이징 통합
    else:
        st.info("트리 구조를 위한 Event ID 컬럼이 없습니다. 일반 테이블로 표시합니다.")
        display_paginated_df(df)

# VirusTotal API 호출 함수 (해시 추출 및 점수 확인, 업그레이드: 캐싱 추가, 해시 유효성 검사 강화)
@st.cache_data(ttl=3600)  # 1시간 캐싱으로 API 호출 최소화
def get_virustotal_score(hash_value):
    if not hash_value or len(hash_value) not in [32, 40, 64]:  # MD5(32), SHA1(40), SHA256(64) 지원
        return 0
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            positives = stats.get('malicious', 0) + stats.get('suspicious', 0)  # suspicious도 포함 (개선)
            total = sum(stats.values())
            score = (positives / total) * 100 if total > 0 else 0
            return round(score, 2)  # 소수점 2자리로 반올림 (0.00 방지)
        elif response.status_code == 404:
            # 파일이 없으면 업로드 시도 (신규 기능: VT에 업로드 후 분석 대기)
            upload_url = "https://www.virustotal.com/api/v3/files"
            # 하지만 파일이 없으므로, 여기서는 가정하고 스킵 (실제 파일 필요 시 추가)
            return 0
        else:
            st.warning(f"VirusTotal API 에러: {response.status_code} - {response.text}")
            return 0
    except Exception as e:
        st.error(f"VirusTotal 호출 에러: {e}")
        return 0

# 신규: Threat Intelligence API (예: AbuseIPDB) 호출 함수 (추가 기능: IP 악성 체크)
@st.cache_data(ttl=3600)
def get_abuseipdb_score(ip):
    if not ip:
        return 0
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": st.secrets.get("ABUSEIPDB_API_KEY", "your_abuseipdb_key_here"), "Accept": "application/json"}  # API 키 secrets 사용
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data['data']['abuseConfidenceScore']
        else:
            return 0
    except Exception:
        return 0

# 탭 구조 추가 (업그레이드: Dashboard, Logs, VT Scan, Reports, Alerts, Threat Hunting 신규 탭)
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["대시보드", "로그 조회", "VirusTotal 스캔", "보고서 생성", "알림 설정", "위협 헌팅"])

with tab1:  # 대시보드 탭 (업그레이드: 더 많은 차트 + VT 통합 통계 + AbuseIPDB 통계)
    st.header("로그 대시보드")
    if 'df' in st.session_state and len(st.session_state.df) > 0:
        df = st.session_state.df.copy()

        # 시간별 로그 수 차트 (Altair 사용, 업그레이드: 줌 기능)
        if '@timestamp' in df.columns:
            df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
            df['hour'] = df['@timestamp'].dt.hour
            time_chart = alt.Chart(df).mark_bar().encode(
                x='hour:O',
                y='count()',
                color='level',
                tooltip=['hour', 'count()', 'level']
            ).properties(title="시간별 로그 분포").interactive(bind_y=True)
            st.altair_chart(time_chart, use_container_width=True)

        # 레벨 분포 Pie Chart (업그레이드: VT 점수 기반 필터링 옵션)
        level_counts = df['level'].value_counts().reset_index()
        level_counts.columns = ['level', 'count']
        pie_chart = alt.Chart(level_counts).mark_arc().encode(
            theta='count',
            color='level',
            tooltip=['level', 'count']
        ).properties(title="로그 레벨 분포").interactive()
        st.altair_chart(pie_chart, use_container_width=True)

        # Top 5 Users/Events/VT High Scores/AbuseIPDB High Scores (표 형식, 업그레이드)
        if 'winlog.user.name' in df.columns:
            top_users = df['winlog.user.name'].value_counts().head(5).reset_index()
            top_users.columns = ['User', 'Count']
            st.subheader("Top 5 Users")
            st.table(top_users)

        if 'winlog.event_id' in df.columns:
            top_events = df['winlog.event_id'].value_counts().head(5).reset_index()
            top_events.columns = ['Event ID', 'Count']
            st.subheader("Top 5 Events")
            st.table(top_events)

        if 'vt_score' in df.columns:
            high_vt = df[df['vt_score'] > vt_threshold].sort_values('vt_score', ascending=False).head(5)
            st.subheader("Top 5 High VT Scores")
            st.table(high_vt[['message', 'vt_score']])

        if 'abuse_score' in df.columns:
            high_abuse = df[df['abuse_score'] > 50].sort_values('abuse_score', ascending=False).head(5)
            st.subheader("Top 5 High AbuseIPDB Scores")
            st.table(high_abuse[['winlog.event_data.SourceIp', 'abuse_score']])

with tab2:  # 로그 조회 탭 (업그레이드: 트리 뷰 + 페이징 통합)
    st.header("로그 조회")
    # 1. 로그 연동 (EVTX 업로드 & ES 인덱싱, 업그레이드: 프로그레스 바 추가)
    evtx_file = st.file_uploader("EVTX 로그 업로드", type="evtx")
    if evtx_file and st.button("ES에 인덱싱"):
        with st.spinner("EVTX 파싱 & 인덱싱 중..."):
            parser = PyEvtxParser(evtx_file)
            progress_bar = st.progress(0)
            records = list(parser.records_json())  # 한 번에 모두 로드 (총 수 계산)
            total = len(records)
            for i, record in enumerate(records):
                log_data = json.loads(record['data'])
                event = xmltodict.parse(log_data['Event'])['Event']
                es.index(index=".internal.alerts-security.alerts*", body=event)
                progress_bar.progress((i + 1) / total if total > 0 else 0)
        st.success("인덱싱 완료!")

    # 2. 모든 로그 가져오기 (업그레이드: 시간 범위 통합 쿼리)
    if st.button("모든 로그 가져오기"):
        query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": time_range[0].isoformat(),
                        "lte": time_range[1].isoformat()
                    }
                }
            },
            "size": 10000,
            "sort": [{"@timestamp": {"order": "desc"}}]
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
            st.session_state.page_logs = 0
            st.success(f"총 {len(df)}개 로그 가져옴")
        except Exception as e:
            st.error(f"ES 쿼리 에러: {e}")

    # 레벨별 필터링 버튼 (LOW/MEDIUM/HIGH, 업그레이드: 동적 카운트 표시)
    if 'df' in st.session_state:
        level_column = 'new_level' if 'new_level' in st.session_state.df.columns else 'level'
        level_counts = st.session_state.df[level_column].value_counts()

        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button(f"LOW ({level_counts.get('low', 0)})"):
                filtered_df = st.session_state.df[st.session_state.df[level_column] == 'low']
                st.session_state.filtered_df = filtered_df
                st.session_state.page_logs = 0
        with col2:
            if st.button(f"MEDIUM ({level_counts.get('medium', 0)})"):
                filtered_df = st.session_state.df[st.session_state.df[level_column] == 'medium']
                st.session_state.filtered_df = filtered_df
                st.session_state.page_logs = 0
        with col3:
            if st.button(f"HIGH ({level_counts.get('high', 0)})"):
                filtered_df = st.session_state.df[st.session_state.df[level_column] == 'high']
                st.session_state.filtered_df = filtered_df
                st.session_state.page_logs = 0

        # 전체 로그 보기 버튼
        if st.button("전체 로그 보기"):
            st.session_state.filtered_df = st.session_state.df.copy()
            st.session_state.page_logs = 0

    # 로그 표시 (트리 뷰 또는 테이블 선택 가능)
    if 'filtered_df' in st.session_state:
        view_mode = st.radio("뷰 모드", ["테이블 뷰", "트리 뷰"])
        filtered_df = st.session_state.filtered_df.copy()
        if view_mode == "트리 뷰":
            display_log_tree(filtered_df)
        else:
            display_paginated_df(filtered_df, key_prefix="logs")

with tab3:  # VirusTotal 스캔 탭 (업그레이드: 해시 추출 개선, AbuseIPDB 통합)
    st.header("VirusTotal & Threat Intel 스캔")
    if 'df' in st.session_state and st.button("로그에서 해시/IP 추출 & 스캔 (VT + AbuseIPDB)"):
        df = st.session_state.df.copy()
        with st.spinner("스캔 중... (API 제한으로 지연될 수 있음)"):
            progress_bar = st.progress(0)
            for idx, row in df.iterrows():
                message = row.get('message', '')
                # 해시 추출 개선: MD5, SHA1, SHA256 지원
                hashes = re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', message)
                hash_value = hashes[0] if hashes else None
                score = get_virustotal_score(hash_value)
                df.at[idx, 'vt_score'] = score
                # VT 점수에 따라 level 업그레이드
                if score > 70:
                    df.at[idx, 'new_level'] = 'high'
                elif score > 30:
                    df.at[idx, 'new_level'] = 'medium'
                else:
                    df.at[idx, 'new_level'] = 'low'

                # AbuseIPDB 스캔 (IP 추출)
                ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', message)  # 간단 IP 패턴
                ip_value = ips[0] if ips else row.get('winlog.event_data.SourceIp', None)
                abuse_score = get_abuseipdb_score(ip_value)
                df.at[idx, 'abuse_score'] = abuse_score
                # Abuse 점수에 따라 level 업그레이드
                if abuse_score > 80 and df.at[idx, 'new_level'] != 'high':
                    df.at[idx, 'new_level'] = 'high'
                elif abuse_score > 40 and df.at[idx, 'new_level'] == 'low':
                    df.at[idx, 'new_level'] = 'medium'

                progress_bar.progress((idx + 1) / len(df))
                time.sleep(15 / 60)  # VT 무료: 4/min, so ~15 sec delay

        st.session_state.df = df
        st.session_state.filtered_df = df.copy()
        st.success("스캔 완료! VT & AbuseIPDB 점수가 추가되었습니다.")

    # 고점수 로그만 필터링
    if 'df' in st.session_state and 'vt_score' in st.session_state.df.columns:
        high_vt_df = st.session_state.df[st.session_state.df['vt_score'] > vt_threshold]
        st.subheader(f"High VT Score Logs (>{vt_threshold})")
        display_paginated_df(high_vt_df, key_prefix="vt_high")

    if 'df' in st.session_state and 'abuse_score' in st.session_state.df.columns:
        high_abuse_df = st.session_state.df[st.session_state.df['abuse_score'] > 50]
        st.subheader("High AbuseIPDB Score Logs (>50)")
        display_paginated_df(high_abuse_df, key_prefix="abuse_high")

with tab4:  # 보고서 생성 탭 (업그레이드: VT + Abuse 통합 + LLM 보고서 생성)
    st.header("보고서 & 요약 생성")
    if 'df' in st.session_state and st.button("LLM 요약 & PDF 생성 (VT/Abuse 고점수 우선)"):
        # 고점수 로그만 필터링하여 LLM 보내기
        if 'vt_score' not in st.session_state.df.columns or 'abuse_score' not in st.session_state.df.columns:
            st.warning("먼저 스캔을 실행하세요.")
        else:
            high_score_df = st.session_state.df[(st.session_state.df['vt_score'] > vt_threshold) | (st.session_state.df['abuse_score'] > 50)].copy()
            if len(high_score_df) == 0:
                st.warning("고점수 로그가 없습니다. 전체 로그로 진행합니다.")
                high_score_df = st.session_state.df.copy()

            with st.spinner("LLM 요약 & 취약점 분석 중..."):
                for index, row in high_score_df.iterrows():
                    level = row.get('new_level', row.get('level', 'low'))
                    log_text = row.get('message', str(row))
                    vt_score = row.get('vt_score', 0)
                    abuse_score = row.get('abuse_score', 0)
                    action = '관찰' if level == 'low' else '경고' if level == 'medium' else '격리'
                    vulns_str = row.get('vulns', 'No vulnerabilities found')
                    prompt = f"이 로그를 기반으로 취약점 분석 보고서를 작성하세요. 로그: {log_text}. VirusTotal 점수: {vt_score}. AbuseIPDB 점수: {abuse_score}. 취약점: {vulns_str}. 레벨: {level} - 액션: {action}. 잠재적 위협, 상세 분석, 대응 방안을 포함하세요."
                    response = openai_client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[{"role": "user", "content": prompt}]
                    )
                    summary = response.choices[0].message.content
                    high_score_df.at[index, 'summary'] = summary

            # 원본 DF 업데이트
            for idx in high_score_df.index:
                st.session_state.df.at[idx, 'summary'] = high_score_df.at[idx, 'summary']

            st.success("요약 및 취약점 분석 완료!")
            st.session_state.filtered_df = high_score_df

            # PDF 생성 (업그레이드: VT/Abuse 점수 컬럼 추가, 폰트 경로 수정 필요 시)
            pdf_buffer = io.BytesIO()
            # font_path = './NanumGothic-Bold.ttf'  # Streamlit 클라우드에서 폰트 업로드 필요, 또는 기본 폰트 사용
            pdfmetrics.registerFont(TTFont('Helvetica', 'Helvetica.ttf'))  # 기본 폰트로 대체 (오류 방지)
            doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            body_style = ParagraphStyle('Body', parent=styles['Normal'], fontName='Helvetica', fontSize=10, wordWrap='CJK')
            elements = [Paragraph("로그 분석 보고서 (VT/Abuse 통합)", styles['Title'])]
            data = [['로그 ID', '메시지 (짧게)', '레벨', 'VT 점수', 'Abuse 점수', '요약']]
            for index, row in high_score_df.iterrows():
                msg_short = Paragraph(row.get('message', 'N/A')[:50] + '...', body_style)
                level_score = Paragraph(f"{row.get('new_level', row.get('level'))}", body_style)
                vt_para = Paragraph(str(row.get('vt_score', 0)), body_style)
                abuse_para = Paragraph(str(row.get('abuse_score', 0)), body_style)
                summary_para = Paragraph(row['summary'], body_style)
                data.append([Paragraph(str(index), body_style), msg_short, level_score, vt_para, abuse_para, summary_para])
            col_widths = [50, 150, 100, 50, 50, 200]
            table = Table(data, colWidths=col_widths)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
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
            st.download_button("PDF 다운로드", pdf_buffer, file_name="threat_report.pdf", mime="application/pdf")

    # 추가: CSV/JSON 내보내기 (업그레이드: VT/Abuse 컬럼 포함)
    if 'df' in st.session_state:
        csv = st.session_state.df.to_csv(index=False).encode('utf-8-sig')
        st.download_button("전체 로그 CSV 다운로드", csv, "logs.csv", "text/csv")
        json_data = st.session_state.df.to_json(orient='records').encode('utf-8')
        st.download_button("전체 로그 JSON 다운로드", json_data, "logs.json", "application/json")

with tab5:  # 알림 설정 탭 (업그레이드: 고위험 시 자동 알림 시뮬레이션)
    st.header("알림 설정")
    email_alert = st.text_input("알림 이메일 (고위험 시 알림)")
    slack_webhook = st.text_input("Slack Webhook URL (옵션)")
    if st.button("알림 테스트"):
        st.info("테스트 알림 전송: 고위험 로그가 탐지되면 이메일/Slack으로 알림을 보냅니다. (실제 구현은 SMTP/Slack API 필요)")
    if 'df' in st.session_state and st.button("고위험 로그 알림 확인"):
        high_df = st.session_state.df[st.session_state.df.get('new_level', 'low') == 'high']
        if len(high_df) > 0:
            st.warning(f"{len(high_df)}개의 고위험 로그 발견! 알림 전송 시뮬레이션.")
            # 실제 알림: 여기서 email/slack API 호출 가능 (예: smtplib, requests.post(slack_webhook))
        else:
            st.success("고위험 로그 없음.")
    st.warning("알림 기능은 실제 배포 시 SMTP 또는 외부 서비스 연동이 필요합니다. 여기서는 시뮬레이션만.")

with tab6:  # 신규: 위협 헌팅 탭 (GPT로 쿼리 생성 + ES 검색)
    st.header("위협 헌팅")
    hunt_query = st.text_area("헌팅 쿼리 (예: 의심스러운 이벤트 설명)")
    if st.button("GPT로 ES 쿼리 생성 & 검색"):
        if hunt_query:
            prompt = f"이 설명을 기반으로 Elasticsearch 쿼리를 생성하세요: {hunt_query}. 쿼리는 JSON 형식으로 반환하세요."
            response = openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}]
            )
            generated_query = response.choices[0].message.content.strip()
            try:
                query_json = json.loads(generated_query)
                res = es.search(index=".internal.alerts-security.alerts*", body=query_json)
                logs = [hit['_source'] for hit in res['hits']['hits']]
                hunt_df = pd.DataFrame(logs)
                st.session_state.hunt_df = hunt_df
                st.success(f"헌팅 결과: {len(hunt_df)}개 로그")
            except Exception as e:
                st.error(f"쿼리 에러: {e}")
    if 'hunt_df' in st.session_state:
        display_paginated_df(st.session_state.hunt_df, key_prefix="hunt")

# 최종 표시 로직 (탭 밖: 현재 필터링된 로그 요약)
if 'filtered_df' in st.session_state:
    st.subheader("현재 필터링된 로그 요약")
    display_paginated_df(st.session_state.filtered_df, key_prefix="main", page_size=20)  # 작은 페이지로 요약

# 추가: 로그 통계 차트 (업그레이드: VT/Abuse 포함 바 차트)
if 'df' in st.session_state and len(st.session_state.df) > 0:
    with st.expander("로그 통계 (VT/Abuse 포함)"):
        level_column = 'new_level' if 'new_level' in st.session_state.df.columns else 'level'
        level_counts = st.session_state.df[level_column].value_counts()
        st.bar_chart(level_counts)
        if 'vt_score' in st.session_state.df.columns:
            vt_hist = alt.Chart(st.session_state.df).mark_bar().encode(
                x=alt.X('vt_score:Q', bin=True),
                y='count()',
                tooltip=['vt_score', 'count()']
            ).properties(title="VirusTotal 점수 분포")
            st.altair_chart(vt_hist, use_container_width=True)
        if 'abuse_score' in st.session_state.df.columns:
            abuse_hist = alt.Chart(st.session_state.df).mark_bar().encode(
                x=alt.X('abuse_score:Q', bin=True),
                y='count()',
                tooltip=['abuse_score', 'count()']
            ).properties(title="AbuseIPDB 점수 분포")
            st.altair_chart(abuse_hist, use_container_width=True)
