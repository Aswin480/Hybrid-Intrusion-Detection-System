# backend.py
import json
import pandas as pd
import joblib
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from tensorflow.keras.models import load_model
from sklearn.preprocessing import LabelEncoder
import os
import warnings

# Suppress scikit-learn version warnings for cleaner output
warnings.filterwarnings("ignore", category=UserWarning, module='sklearn')


# --- Flask App Initialization ---
app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing

# --- Stateful DFA Implementation ---
class StatefulDFAChecker:
    def __init__(self):
        self.states = {'START', 'ONE_FAILED', 'TWO_FAILED', 'ALARM_BRUTE_FORCE'}
        self.initial_state = 'START'
        self.alarm_state = 'ALARM_BRUTE_FORCE'
        self.transitions = {
            ('START', 'FAILED_LOGIN'): 'ONE_FAILED',
            ('ONE_FAILED', 'FAILED_LOGIN'): 'TWO_FAILED',
            ('TWO_FAILED', 'FAILED_LOGIN'): 'ALARM_BRUTE_FORCE',
            ('START', 'SUCCESSFUL_LOGIN'): 'START',
            ('ONE_FAILED', 'SUCCESSFUL_LOGIN'): 'START',
            ('TWO_FAILED', 'SUCCESSFUL_LOGIN'): 'START',
        }

    def _get_event_from_packet(self, packet_data):
        if packet_data.get('num_failed_logins', 0) > 0 and packet_data.get('logged_in', 0) == 0:
            return 'FAILED_LOGIN'
        if packet_data.get('logged_in', 0) == 1 and packet_data.get('num_failed_logins', 0) == 0:
            return 'SUCCESSFUL_LOGIN'
        return None

    def process_packet(self, current_state, packet_data):
        event = self._get_event_from_packet(packet_data)
        if event is None:
            return current_state
        return self.transitions.get((current_state, event), self.initial_state)

# --- Backend Analysis Logic ---
def load_rules(filename='rules.json'):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading stateless DFA rules: {e}")
        return []

def load_ml_components(model_path, scaler_path):
    try:
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        return model, scaler
    except Exception as e:
        print(f"Error loading ML components: {e}")
        return None, None

def load_ann_components(model_path, scaler_path):
    try:
        ann_model = load_model(model_path)
        ann_scaler = joblib.load(scaler_path)
        return ann_model, ann_scaler
    except Exception as e:
        print(f"Error loading ANN components: {e}")
        return None, None

def evaluate_condition(packet_value, operator, rule_value):
    op_map = {
        '==': lambda a, b: a == b,
        '!=': lambda a, b: a != b,
        '>':  lambda a, b: a > b,
        '<':  lambda a, b: a < b,
        '>=': lambda a, b: a >= b,
        '<=': lambda a, b: a <= b
    }
    return op_map.get(operator, lambda a, b: False)(packet_value, rule_value)

def run_stateless_dfa_check(packet_data, rules):
    for rule in rules:
        is_match = all(
            condition['feature'] in packet_data and
            evaluate_condition(packet_data[condition['feature']], condition['operator'], condition['value'])
            for condition in rule['conditions']
        )
        if is_match:
            return rule['rule_name']
    return None

# --- Feature and Label Definitions ---

# Features for the ML (XGBoost) model (70 features)
ML_FEATURE_COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
    'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
    'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
    'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Subflow Fwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

# Features for the ANN model (78 features)
ANN_FEATURE_COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk',
    'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
    'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

# Label mapping for the ML (XGBoost) model
ML_LABEL_MAPPING = {
    0: 'BENIGN', 1: 'Bot', 2: 'DDoS', 3: 'DoS GoldenEye',
    4: 'DoS Hulk', 5: 'DoS Slowhttptest', 6: 'DoS slowloris',
    7: 'FTP-Patator', 8: 'Heartbleed', 9: 'Infiltration',
    10: 'PortScan', 11: 'SSH-Patator', 12: 'Web Attack - Brute Force',
    13: 'Web Attack - Sql Injection', 14: 'Web Attack - XSS'
}

# Labels for the ANN model
ANN_POSSIBLE_LABELS = [
    'BENIGN', 'DDoS', 'PortScan', 'Bot', 'Infiltration', 'Web Attack - Brute Force',
    'Web Attack - XSS', 'Web Attack - Sql Injection', 'FTP-Patator', 'SSH-Patator',
    'DoS slowloris', 'DoS Slowhttptest', 'DoS Hulk', 'DoS GoldenEye', 'Heartbleed'
]
ANN_LABEL_ENCODER = LabelEncoder()
ANN_LABEL_ENCODER.fit(ANN_POSSIBLE_LABELS)

# --- Prediction Functions ---
def predict_with_ml(packet_data, model, scaler):
    """
    Loads the trained XGBoost model and scaler to predict the label and confidence
    for a single data point representing network traffic.
    """
    if not model or not scaler:
        return "N/A", 0.0

    df = pd.DataFrame([packet_data])
    
    # Ensure all required columns exist, adding any that are missing with a default value (0)
    for col in ML_FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0
            
    # Ensure the columns are in the correct order and drop any extras
    df = df[ML_FEATURE_COLUMNS]
    df = df.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    
    # Apply the loaded scaler
    scaled_data = scaler.transform(df)

    # Make prediction and get probabilities
    prediction_numeric = model.predict(scaled_data)[0]
    probabilities = model.predict_proba(scaled_data)[0]
    
    confidence = probabilities[prediction_numeric]
    predicted_label = ML_LABEL_MAPPING.get(prediction_numeric, "Unknown Label")
    
    return predicted_label, confidence

def predict_with_ann(packet_data, model, scaler, encoder):
    if not model or not scaler:
        return 0, 0.0, "N/A"

    df = pd.DataFrame([packet_data])
    # Use the specific feature columns for the ANN model
    df = df.reindex(columns=ANN_FEATURE_COLUMNS, fill_value=0)
    df = df.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    scaled_data = scaler.transform(df)

    all_predictions = model.predict(scaled_data, verbose=0)
    predicted_index = np.argmax(all_predictions, axis=1)[0]
    probability = all_predictions[0][predicted_index]
    predicted_label = encoder.inverse_transform([predicted_index])[0]
    prediction = 0 if predicted_label == 'BENIGN' else 1
    return prediction, probability, predicted_label

# --- Main Analysis Pipeline ---
def analyze_packet(packet_data, current_state, stateful_dfa, stateless_rules,
                   ml_model, ml_scaler, ann_model, ann_scaler, ann_encoder, ml_threshold):
    pipeline_steps = []
    final_result = None
    source_id = packet_data.get("Source IP", "192.168.1.100")

    # Stage 1: Stateful DFA
    new_state = stateful_dfa.process_packet(current_state, packet_data)
    if new_state == stateful_dfa.alarm_state:
        final_result = {"status": "Not Safe", "reason": "Stateful DFA Match",
                        "details": f"Brute-force detected from {source_id}"}
        pipeline_steps.append({'stage': 'Stateful DFA', 'status': 'Failed', 'details': final_result['details']})
        return {'final_result': final_result, 'pipeline_steps': pipeline_steps, 'new_state': new_state}
    pipeline_steps.append({'stage': 'Stateful DFA', 'status': 'Passed', 'details': f'State for {source_id} is {new_state}.'})

    # Stage 2: Stateless DFA
    stateless_result = run_stateless_dfa_check(packet_data, stateless_rules)
    if stateless_result:
        final_result = {"status": "Not Safe", "reason": "Stateless DFA Rule Match", "details": stateless_result}
        pipeline_steps.append({'stage': 'Stateless DFA', 'status': 'Failed', 'details': stateless_result})
        return {'final_result': final_result, 'pipeline_steps': pipeline_steps, 'new_state': new_state}
    pipeline_steps.append({'stage': 'Stateless DFA', 'status': 'Passed', 'details': 'No rule match.'})

    # Stage 3: ML Model (Updated Logic)
    ml_label, ml_confidence = predict_with_ml(packet_data, ml_model, ml_scaler)
    if ml_label != 'BENIGN' and ml_confidence >= ml_threshold:
        details = f"Anomalous traffic detected as '{ml_label}' with {ml_confidence:.2%} confidence (ML), meeting threshold {ml_threshold:.0%}."
        final_result = {"status": "Not Safe", "reason": "ML Model Detection", "details": details}
        pipeline_steps.append({'stage': 'ML Model', 'status': 'Failed', 'details': details})
        return {'final_result': final_result, 'pipeline_steps': pipeline_steps, 'new_state': new_state}
    
    pass_details = f"Predicted as '{ml_label}' with {ml_confidence:.2%} confidence."
    if ml_label != 'BENIGN':
        pass_details += f" (Below confidence threshold of {ml_threshold:.0%})"
    pipeline_steps.append({'stage': 'ML Model', 'status': 'Passed', 'details': pass_details})


    # Stage 4: ANN Model
    ann_prediction, ann_proba, ann_label = predict_with_ann(packet_data, ann_model, ann_scaler, ann_encoder)
    if ann_prediction == 1:
        details = f"Anomalous traffic detected as '{ann_label}' with {ann_proba:.2%} confidence (ANN)."
        final_result = {"status": "Not Safe", "reason": "ANN Model Detection", "details": details}
        pipeline_steps.append({'stage': 'ANN Model', 'status': 'Failed', 'details': details})
        return {'final_result': final_result, 'pipeline_steps': pipeline_steps, 'new_state': new_state}
    pipeline_steps.append({'stage': 'ANN Model', 'status': 'Passed', 'details': f"Predicted as 'BENIGN' with {ann_proba:.2%} confidence."})

    final_result = {"status": "Safe", "reason": "Passed All Checks", "details": "The packet appears to be benign."}
    return {'final_result': final_result, 'pipeline_steps': pipeline_steps, 'new_state': new_state}

# --- Load Models and Rules on Startup ---
print("Loading models and rules...")
STATEFUL_DFA_CHECKER = StatefulDFAChecker()
STATELESS_DFA_RULES = load_rules('rules.json')
ML_MODEL, ML_SCALER = load_ml_components('models/ml_model.joblib', 'models/ml_scaler.joblib')
ANN_MODEL, ANN_SCALER = load_ann_components('models/ann.joblib', 'models/ann_scaler.joblib')
print("Models and rules loaded successfully.")

# --- API Endpoints ---
@app.route('/status', methods=['GET'])
def get_status():
    return jsonify({"status": "ok", "message": "Backend is running"}), 200

@app.route('/analyze', methods=['POST'])
def handle_analysis():
    data = request.get_json()
    if not data or 'packet_data' not in data or 'current_state' not in data:
        return jsonify({"error": "Invalid request payload"}), 400

    packet_data = data['packet_data']
    current_state = data['current_state']
    ml_threshold = data.get('ml_threshold', 0.7)

    result = analyze_packet(
        packet_data,
        current_state,
        STATEFUL_DFA_CHECKER,
        STATELESS_DFA_RULES,
        ML_MODEL,
        ML_SCALER,
        ANN_MODEL,
        ANN_SCALER,
        ANN_LABEL_ENCODER,
        ml_threshold
    )
    return jsonify(result)

# --- Main Execution ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)