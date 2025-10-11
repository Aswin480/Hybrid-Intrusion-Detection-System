# frontend.py
import streamlit as st
import json
import pandas as pd
import time
import random
import requests
from collections import defaultdict
from datetime import datetime
import database as db  # --- Import the database module ---

# --- Page Configuration ---
st.set_page_config(
    page_title="Hybrid Intrusion Detection System",
    layout="wide",
    initial_sidebar_state="auto"
)

# --- Initialize the database on startup ---
db.init_db()

# --- Styling ---
st.markdown("""
<style>
.stApp { background-color: #F0F2F6; }
[data-testid="stVerticalBlockBorderWrapper"] {
    background-color: #FFFFFF;
    border-radius: 10px;
    border: 1px solid #E2E8F0;
    padding: 1rem;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1),
                0 2px 4px -1px rgba(0, 0, 0, 0.06);
}
h1 { color: #1A202C; font-weight: 700; }
h2, h3, h5, h6 { color: #2D3748; }
.stButton>button[kind="primary"] {
    background-color: #3182CE; color: white; font-weight: 600; border: none;
}
.stButton>button[kind="primary"]:hover { background-color: #2B6CB0; }
</style>
""", unsafe_allow_html=True)

# --- Backend URL ---
BACKEND_URL = "http://127.0.0.1:5000"

# --- Session State Initialization ---
# Remove log and count tracking, as the DB will handle this.
# Keep state_manager for the live session's DFA states.
defaults = {
    'state_manager': {},
    'packet_input': "",
    'last_analysis': None,
    'is_simulating': False,
    'ml_threshold': 70,
    'sim_speed': 3,
    'backend_status': ("Unknown", "Checking connection...")
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# --- Helper Functions ---
@st.cache_data(ttl=15)
def check_backend_status():
    try:
        r = requests.get(f"{BACKEND_URL}/status", timeout=2)
        return ("Connected", "Backend is online.") if r.status_code == 200 else ("Error", f"Status {r.status_code}")
    except requests.exceptions.ConnectionError:
        return ("Disconnected", "Cannot reach backend.")
    except Exception as e:
        return ("Error", str(e))

def display_pipeline_visualization(pipeline_steps):
    st.subheader("Analysis Pipeline")
    for step in pipeline_steps:
        with st.expander(f"{step['stage']} - {step['status']}", expanded=step['status'] == 'Failed'):
            if step['status'] == 'Passed':
                st.success(step['details'])
            else:
                st.error(step['details'])

def get_threat_intelligence(reason):
    mapping = {
        "Stateful DFA Match": ("High", "Potential brute-force attack. Block source IP."),
        "Stateless DFA Rule Match": ("Medium", "Packet matches known malicious signature."),
        "ML Model Detection": ("Low", "Anomalous traffic detected by ML model."),
        "ANN Model Detection": ("Critical", "High-confidence attack detection. Investigate immediately.")
    }
    return mapping.get(reason, ("Info", "No action required."))

# ==========================================================
# SAFE FUNCTION (no widget conflicts)
# ==========================================================
def analyze_and_update(packet_data_str):
    try:
        parsed = json.loads(packet_data_str)
        src = parsed.get("Source IP", "192.168.1.100")
        current_state = st.session_state.state_manager.get(src, 'START')

        payload = {
            'packet_data': parsed,
            'current_state': current_state,
            'ml_threshold': st.session_state.ml_threshold / 100
        }
        resp = requests.post(f"{BACKEND_URL}/analyze", json=payload)

        if resp.status_code == 200:
            result_json = resp.json()
            st.session_state.last_analysis = result_json
            st.session_state.packet_input = packet_data_str

            result = result_json['final_result']
            new_state = result_json['new_state']
            st.session_state.state_manager[src] = new_state

            sev, rec = get_threat_intelligence(result['reason'])

            # --- Create a log entry dictionary ---
            log_entry = {
                'Timestamp': datetime.now(),
                'Source IP': parsed.get('Source IP', 'N/A'),
                'Destination Port': parsed.get('Destination Port', 'N/A'),
                'Status': result['status'],
                'Reason': result['reason'],
                'Severity': sev,
                'Recommendation': rec,
                'Details': result['details']
            }
            # --- Add the new entry to the database ---
            db.add_log_entry(log_entry)
        else:
            st.error(f"Backend error: {resp.status_code} - {resp.text}")
    except Exception as e:
        st.error(f"An error occurred during analysis: {e}")
        # Safe stop simulation
        if 'is_simulating' in st.session_state:
            st.session_state.is_simulating = False

# ==========================================================
# SIDEBAR
# ==========================================================
with st.sidebar:
    st.title("Configuration")

    with st.container(border=True):
        st.subheader("System Status")
        s, msg = check_backend_status()
        st.success(f"Backend: {s}" if s == "Connected" else f"Backend: {s}")

    with st.container(border=True):
        st.subheader("Analysis Settings")
        st.slider("ML Sensitivity Threshold (%)", 50, 95,
                  key="ml_threshold", help="Set confidence threshold for XGBoost.")

    with st.container(border=True):
        st.subheader("Simulation Settings")
        st.slider("Simulation Speed (seconds/packet)", 1, 10,
                  key="sim_speed", help="Delay between packets in Live Simulation.")

# ==========================================================
# MAIN PAGE
# ==========================================================
st.title("Hybrid Intrusion Detection System")
st.markdown("Detect network threats using a hybrid analytical pipeline (DFA + ML + ANN).")

tab1, tab2, tab3 = st.tabs(["🔬 Live Analysis", "📈 Reporting & Analytics", "📋 Threat Log"])

# ==========================================================
# TAB 1: Live Analysis
# ==========================================================
with tab1:
    # --- Samples from the CSV will be loaded here ---
    df = pd.read_csv('sampled_by_label.csv')
    df.columns = df.columns.str.strip()


    benign_samples = [row.to_json() for index, row in df[df['Label'] == 'BENIGN'].iterrows()]
    attack_samples = [row.to_json() for index, row in df[df['Label'] != 'BENIGN'].iterrows()]

    stateless_samples = [
    json.dumps({'Destination Port': 80, 'Flow Duration': 500000, 'Total Fwd Packets': 60, 'Total Backward Packets': 1, 'Total Length of Fwd Packets': 20, 'Total Length of Bwd Packets': 20, 'Fwd Packet Length Max': 20, 'Fwd Packet Length Min': 20, 'Fwd Packet Length Mean': 20.0, 'Fwd Packet Length Std': 0.0, 'Bwd Packet Length Max': 20, 'Bwd Packet Length Min': 20, 'Bwd Packet Length Mean': 20.0, 'Bwd Packet Length Std': 0.0, 'Flow Bytes/s': 400.0, 'Flow Packets/s': 20.0, 'Flow IAT Mean': 100.0, 'Flow IAT Std': 0.0, 'Flow IAT Max': 100, 'Flow IAT Min': 100, 'Fwd IAT Total': 100, 'Fwd IAT Mean': 100.0, 'Fwd IAT Std': 0.0, 'Fwd IAT Max': 100, 'Fwd IAT Min': 100, 'Bwd IAT Total': 0, 'Bwd IAT Mean': 0.0, 'Bwd IAT Std': 0.0, 'Bwd IAT Max': 0, 'Bwd IAT Min': 0, 'Fwd PSH Flags': 0, 'Bwd PSH Flags': 0, 'Fwd URG Flags': 0, 'Bwd URG Flags': 0, 'Fwd Header Length': 20, 'Bwd Header Length': 20, 'Fwd Packets/s': 10.0, 'Bwd Packets/s': 10.0, 'Min Packet Length': 20, 'Max Packet Length': 20, 'Packet Length Mean': 20.0, 'Packet Length Std': 0.0, 'Packet Length Variance': 0.0, 'FIN Flag Count': 0, 'SYN Flag Count': 1, 'RST Flag Count': 0, 'PSH Flag Count': 0, 'ACK Flag Count': 0, 'URG Flag Count': 0, 'CWE Flag Count': 0, 'ECE Flag Count': 0, 'Down/Up Ratio': 1, 'Average Packet Size': 30.0, 'Avg Fwd Segment Size': 20.0, 'Avg Bwd Segment Size': 20.0, 'Fwd Header Length.1': 20, 'Fwd Avg Bytes/Bulk': 0, 'Fwd Avg Packets/Bulk': 0, 'Fwd Avg Bulk Rate': 0, 'Bwd Avg Bytes/Bulk': 0, 'Bwd Avg Packets/Bulk': 0, 'Bwd Avg Bulk Rate': 0, 'Subflow Fwd Packets': 1, 'Subflow Fwd Bytes': 20, 'Subflow Bwd Packets': 1, 'Subflow Bwd Bytes': 20, 'Init_Win_bytes_forward': 8192, 'Init_Win_bytes_backward': 8192, 'act_data_pkt_fwd': 1, 'min_seg_size_forward': 20, 'Active Mean': 0.0, 'Active Std': 0.0, 'Active Max': 0, 'Active Min': 0, 'Idle Mean': 0.0, 'Idle Std': 0.0, 'Idle Max': 0, 'Idle Min': 0}, indent=4),
    json.dumps({'Destination Port': 80, 'Flow Duration': 600000, 'Total Fwd Packets': 75, 'Total Backward Packets': 2, 'Total Length of Fwd Packets': 40, 'Total Length of Bwd Packets': 40, 'Fwd Packet Length Max': 20, 'Fwd Packet Length Min': 20, 'Fwd Packet Length Mean': 20.0, 'Fwd Packet Length Std': 0.0, 'Bwd Packet Length Max': 20, 'Bwd Packet Length Min': 20, 'Bwd Packet Length Mean': 20.0, 'Bwd Packet Length Std': 0.0, 'Flow Bytes/s': 400.0, 'Flow Packets/s': 20.0, 'Flow IAT Mean': 50.0, 'Flow IAT Std': 28.86, 'Flow IAT Max': 100, 'Flow IAT Min': 0, 'Fwd IAT Total': 200, 'Fwd IAT Mean': 100.0, 'Fwd IAT Std': 0.0, 'Fwd IAT Max': 100, 'Fwd IAT Min': 100, 'Bwd IAT Total': 100, 'Bwd IAT Mean': 50.0, 'Bwd IAT Std': 0.0, 'Bwd IAT Max': 50, 'Bwd IAT Min': 50, 'Fwd PSH Flags': 0, 'Bwd PSH Flags': 0, 'Fwd URG Flags': 0, 'Bwd URG Flags': 0, 'Fwd Header Length': 40, 'Bwd Header Length': 40, 'Fwd Packets/s': 10.0, 'Bwd Packets/s': 10.0, 'Min Packet Length': 20, 'Max Packet Length': 20, 'Packet Length Mean': 20.0, 'Packet Length Std': 0.0, 'Packet Length Variance': 0.0, 'FIN Flag Count': 0, 'SYN Flag Count': 1, 'RST Flag Count': 0, 'PSH Flag Count': 1, 'ACK Flag Count': 1, 'URG Flag Count': 0, 'CWE Flag Count': 0, 'ECE Flag Count': 0, 'Down/Up Ratio': 1, 'Average Packet Size': 25.0, 'Avg Fwd Segment Size': 20.0, 'Avg Bwd Segment Size': 20.0, 'Fwd Header Length.1': 40, 'Fwd Avg Bytes/Bulk': 0, 'Fwd Avg Packets/Bulk': 0, 'Fwd Avg Bulk Rate': 0, 'Bwd Avg Bytes/Bulk': 0, 'Bwd Avg Packets/Bulk': 0, 'Bwd Avg Bulk Rate': 0, 'Subflow Fwd Packets': 2, 'Subflow Fwd Bytes': 40, 'Subflow Bwd Packets': 2, 'Subflow Bwd Bytes': 40, 'Init_Win_bytes_forward': 4096, 'Init_Win_bytes_backward': 4096, 'act_data_pkt_fwd': 2, 'min_seg_size_forward': 20, 'Active Mean': 0.0, 'Active Std': 0.0, 'Active Max': 0, 'Active Min': 0, 'Idle Mean': 0.0, 'Idle Std': 0.0, 'Idle Max': 0, 'Idle Min': 0}, indent=4)
]

    stateful_samples = [
        json.dumps({"Source IP": "10.0.0.5", 'Destination Port': 22, 'Flow Duration': 100, 'Total Fwd Packets': 1, 'Total Backward Packets': 1, 'num_failed_logins': 1, 'logged_in': 0, 'Total Length of Fwd Packets': 20, 'Total Length of Bwd Packets': 20, 'Fwd Packet Length Max': 20, 'Fwd Packet Length Min': 20, 'Fwd Packet Length Mean': 20.0, 'Fwd Packet Length Std': 0.0, 'Bwd Packet Length Max': 20, 'Bwd Packet Length Min': 20, 'Bwd Packet Length Mean': 20.0, 'Bwd Packet Length Std': 0.0, 'Flow Bytes/s': 400.0, 'Flow Packets/s': 20.0, 'Flow IAT Mean': 100.0, 'Flow IAT Std': 0.0, 'Flow IAT Max': 100, 'Flow IAT Min': 100, 'Fwd IAT Total': 100, 'Fwd IAT Mean': 100.0, 'Fwd IAT Std': 0.0, 'Fwd IAT Max': 100, 'Fwd IAT Min': 100, 'Bwd IAT Total': 0, 'Bwd IAT Mean': 0.0, 'Bwd IAT Std': 0.0, 'Bwd IAT Max': 0, 'Bwd IAT Min': 0, 'Fwd PSH Flags': 0, 'Bwd PSH Flags': 0, 'Fwd URG Flags': 0, 'Bwd URG Flags': 0, 'Fwd Header Length': 20, 'Bwd Header Length': 20, 'Fwd Packets/s': 10.0, 'Bwd Packets/s': 10.0, 'Min Packet Length': 20, 'Max Packet Length': 20, 'Packet Length Mean': 20.0, 'Packet Length Std': 0.0, 'Packet Length Variance': 0.0, 'FIN Flag Count': 0, 'SYN Flag Count': 1, 'RST Flag Count': 0, 'PSH Flag Count': 0, 'ACK Flag Count': 0, 'URG Flag Count': 0, 'CWE Flag Count': 0, 'ECE Flag Count': 0, 'Down/Up Ratio': 1, 'Average Packet Size': 30.0, 'Avg Fwd Segment Size': 20.0, 'Avg Bwd Segment Size': 20.0, 'Fwd Header Length.1': 20, 'Fwd Avg Bytes/Bulk': 0, 'Fwd Avg Packets/Bulk': 0, 'Fwd Avg Bulk Rate': 0, 'Bwd Avg Bytes/Bulk': 0, 'Bwd Avg Packets/Bulk': 0, 'Bwd Avg Bulk Rate': 0, 'Subflow Fwd Packets': 1, 'Subflow Fwd Bytes': 20, 'Subflow Bwd Packets': 1, 'Subflow Bwd Bytes': 20, 'Init_Win_bytes_forward': 8192, 'Init_Win_bytes_backward': 8192, 'act_data_pkt_fwd': 1, 'min_seg_size_forward': 20, 'Active Mean': 0.0, 'Active Std': 0.0, 'Active Max': 0, 'Active Min': 0, 'Idle Mean': 0.0, 'Idle Std': 0.0, 'Idle Max': 0, 'Idle Min': 0}, indent=4),
        json.dumps({"Source IP": "10.0.0.5", 'Destination Port': 22, 'Flow Duration': 100, 'Total Fwd Packets': 1, 'Total Backward Packets': 1, 'num_failed_logins': 1, 'logged_in': 0, 'Total Length of Fwd Packets': 20, 'Total Length of Bwd Packets': 20, 'Fwd Packet Length Max': 20, 'Fwd Packet Length Min': 20, 'Fwd Packet Length Mean': 20.0, 'Fwd Packet Length Std': 0.0, 'Bwd Packet Length Max': 20, 'Bwd Packet Length Min': 20, 'Bwd Packet Length Mean': 20.0, 'Bwd Packet Length Std': 0.0, 'Flow Bytes/s': 400.0, 'Flow Packets/s': 20.0, 'Flow IAT Mean': 100.0, 'Flow IAT Std': 0.0, 'Flow IAT Max': 100, 'Flow IAT Min': 100, 'Fwd IAT Total': 100, 'Fwd IAT Mean': 100.0, 'Fwd IAT Std': 0.0, 'Fwd IAT Max': 100, 'Fwd IAT Min': 100, 'Bwd IAT Total': 0, 'Bwd IAT Mean': 0.0, 'Bwd IAT Std': 0.0, 'Bwd IAT Max': 0, 'Bwd IAT Min': 0, 'Fwd PSH Flags': 0, 'Bwd PSH Flags': 0, 'Fwd URG Flags': 0, 'Bwd URG Flags': 0, 'Fwd Header Length': 20, 'Bwd Header Length': 20, 'Fwd Packets/s': 10.0, 'Bwd Packets/s': 10.0, 'Min Packet Length': 20, 'Max Packet Length': 20, 'Packet Length Mean': 20.0, 'Packet Length Std': 0.0, 'Packet Length Variance': 0.0, 'FIN Flag Count': 0, 'SYN Flag Count': 0, 'RST Flag Count': 0, 'PSH Flag Count': 0, 'ACK Flag Count': 1, 'URG Flag Count': 0, 'CWE Flag Count': 0, 'ECE Flag Count': 0, 'Down/Up Ratio': 1, 'Average Packet Size': 30.0, 'Avg Fwd Segment Size': 20.0, 'Avg Bwd Segment Size': 20.0, 'Fwd Header Length.1': 20, 'Fwd Avg Bytes/Bulk': 0, 'Fwd Avg Packets/Bulk': 0, 'Fwd Avg Bulk Rate': 0, 'Bwd Avg Bytes/Bulk': 0, 'Bwd Avg Packets/Bulk': 0, 'Bwd Avg Bulk Rate': 0, 'Subflow Fwd Packets': 1, 'Subflow Fwd Bytes': 20, 'Subflow Bwd Packets': 1, 'Subflow Bwd Bytes': 20, 'Init_Win_bytes_forward': 8192, 'Init_Win_bytes_backward': 8192, 'act_data_pkt_fwd': 1, 'min_seg_size_forward': 20, 'Active Mean': 0.0, 'Active Std': 0.0, 'Active Max': 0, 'Active Min': 0, 'Idle Mean': 0.0, 'Idle Std': 0.0, 'Idle Max': 0, 'Idle Min': 0}, indent=4),
    ]

    sample_packets = {
        "Stateless (DFA)": stateless_samples,
        "Stateful (Login)": stateful_samples,
        "ML Attack": attack_samples,
        "Benign": benign_samples,
    }

    all_samples = [packet for packets in sample_packets.values() for packet in packets]


    # --- Safe Widget Mirror ---
    st.session_state.is_simulating = st.session_state.get("is_simulating_ui", False)
    st.session_state.packet_input = st.session_state.get("packet_input_ui", "")

    if st.session_state.is_simulating:
        random_packet = random.choice(all_samples)
        analyze_and_update(random_packet)
        time.sleep(st.session_state.sim_speed)
        st.rerun()

    input_col, result_col = st.columns([0.55, 0.45], gap="large")

    with input_col:
        with st.container(border=True):
            st.subheader("Packet Data Input")
            st.toggle("Live Simulation", key="is_simulating_ui", help="Automatically analyze random sample packets.")
            packet_data_input = st.text_area(
                "Paste Packet Data (JSON format):",
                height=250,
                key="packet_input_ui",
                label_visibility="collapsed",
                disabled=st.session_state.is_simulating
            )

            st.markdown("<h6>Load a sample packet:</h6>", unsafe_allow_html=True)
            bcols = st.columns(len(sample_packets))
            for i, (label, packets) in enumerate(sample_packets.items()):
                bcols[i].button(label, on_click=lambda p=packets: st.session_state.update(packet_input_ui=random.choice(p)), disabled=st.session_state.is_simulating)


            if st.button("Analyze Packet", type="primary", use_container_width=True, disabled=st.session_state.is_simulating):
                if not packet_data_input:
                    st.warning("Input is empty.")
                else:
                    analyze_and_update(packet_data_input)

        with st.container(border=True):
            st.subheader("Stateful Tracker (Session)")
            if not st.session_state.state_manager:
                st.caption("No states currently tracked.")
            else:
                st.json(st.session_state.state_manager)
            if st.button("Clear Tracked States", disabled=st.session_state.is_simulating):
                st.session_state.state_manager = {}
                st.rerun()

    with result_col:
        with st.container(border=True, height=750):
            st.subheader("Analysis Result")
            # --- Fetch the latest log for display ---
            all_logs_df = db.get_logs_as_df()
            if st.session_state.last_analysis and not all_logs_df.empty:
                result = st.session_state.last_analysis['final_result']
                # Get the most recent log entry from the DataFrame
                log_entry = all_logs_df.iloc[0]
                if result['status'] == 'Safe':
                    st.success(f"**Status: {result['status']}**")
                else:
                    st.error(f"**Status: {result['status']}** | Severity: **{log_entry['severity']}**")
                st.info(f"**Finding:** {result['details']}")
                if result['status'] != 'Safe':
                    st.warning(f"**Recommendation:** {log_entry['recommendation']}")
                with st.expander("Packet Inspector"):
                    st.dataframe(pd.DataFrame(json.loads(st.session_state.packet_input).items(),
                                              columns=['Feature', 'Value']),
                                 use_container_width=True, hide_index=True)
                st.markdown("---")
                display_pipeline_visualization(st.session_state.last_analysis['pipeline_steps'])
            else:
                st.info("Results will appear here after analysis.")

# ==========================================================
# TAB 2: Reporting & Analytics
# ==========================================================
with tab2:
    st.subheader("Reporting & Analytics")
    # --- Fetch data directly from the database ---
    df = db.get_logs_as_df()
    if df.empty:
        st.info("No data yet. Analyze some packets to see analytics.")
    else:
        total_packets = len(df)
        total_threats = len(df[df['status'] == 'Not Safe'])
        rate = (total_threats / total_packets * 100) if total_packets else 0
        k1, k2, k3 = st.columns(3)
        k1.metric("Total Packets Logged", total_packets)
        k2.metric("Total Threats Found", total_threats)
        k3.metric("Overall Detection Rate", f"{rate:.2f}%")

# ==========================================================
# TAB 3: Threat Log
# ==========================================================
with tab3:
    st.subheader("Threat Log")
    # --- Fetch data directly from the database ---
    df = db.get_logs_as_df()
    if df.empty:
        st.info("No threats have been logged.")
    else:
        filter_txt = st.text_input("Search Log", placeholder="e.g., IP, Reason, Severity")
        if filter_txt:
            # Search across all columns by converting row to a single string
            df = df[df.apply(lambda r: filter_txt.lower() in ' '.join(r.astype(str)).lower(), axis=1)]

        # Display the timestamp correctly
        df['timestamp'] = pd.to_datetime(df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
        st.dataframe(df, use_container_width=True, hide_index=True,
                     column_order=["timestamp", "status", "severity", "reason", "source_ip", "destination_port", "details"])

        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("Download Log (CSV)", csv, "threat_log.csv", "text/csv")

        # --- Clear button calls the database function ---
        if st.button("Clear All Log Data", type="primary"):
            db.clear_logs()
            st.session_state.last_analysis = None # Clear last result from UI
            st.success("All logs have been cleared from the database.")
            time.sleep(1) # Give user time to see the message
            st.rerun()