# 🛡️ Hybrid Intrusion Detection System (IDS)

A sophisticated **network security tool** that uses a **multi-layered analytical pipeline** to detect and classify network threats in real-time.  
This system combines the **speed of Deterministic Finite Automata (DFA)** with the **intelligence of Machine Learning (ML)** and **Artificial Neural Networks (ANN)** to provide robust, high-accuracy threat detection.

The interactive **Streamlit** web dashboard allows security analysts to perform **live packet analysis**, **simulate network traffic**, **monitor system state**, and **review detailed threat logs and analytics**.

[MIT License](https://opensource.org/licenses/MIT)  
[Python Downloads](https://www.python.org/downloads/)  
[Streamlit](https://streamlit.io/)  
[Flask](https://flask.palletsprojects.com/)

---

## ⚙️ Key Features

### 🔍 Hybrid Analysis Pipeline
Leverages **four distinct stages** for comprehensive threat detection:

1. **Stateless DFA**  
   Scans individual packets for known malicious signatures (e.g., port scanning).

2. **Stateful DFA**  
   Tracks packet sequences and session states to identify attacks that unfold over time (e.g., brute-force login attempts).

3. **XGBoost ML Model**  
   Analyzes traffic patterns to detect anomalous behavior that may indicate zero-day threats.

4. **ANN Model**  
   Provides a final, high-confidence classification for complex and nuanced attack vectors.

### 🖥️ Interactive Dashboard
A user-friendly interface for **real-time monitoring and analysis**.

### ⚡ Live Packet Analysis
Manually submit packet data in JSON format for an **immediate security verdict**.

### 🔄 Continuous Simulation
Run a live simulation that automatically feeds random sample packets (benign & malicious) into the analysis engine.

### 📡 Stateful Session Tracking
Displays the current state of tracked IPs in the **Stateful DFA**, showing ongoing interactions.

### 📊 Dynamic Reporting & Analytics
Visualizes key metrics like **total packets logged**, **threats detected**, and **overall detection rates**.

### 🧾 Comprehensive Threat Log
A searchable and downloadable log of all detected events — with timestamps, severity, source IP, and recommendations.

### ⚙️ Configurable Settings
Easily adjust **ML threshold** and **simulation speed** directly from the UI.

---

## 🏗️ System Architecture

The IDS follows a **decoupled frontend-backend architecture**, ensuring modularity and scalability.  
The heart of the system is the **four-stage analysis pipeline**.

### 1. Frontend (Streamlit)
- Provides the UI for all interactions.  
- Manages session state for UI elements and the stateful DFA tracker.  
- Sends analysis requests to the backend via a REST API.  
- Visualizes results, logs, and analytics fetched from the backend/database.

### 2. Backend (Flask)
- Exposes API endpoints (`/status`, `/analyze`) for communication with the frontend.  
- Hosts the **core logic** of the four-stage analysis pipeline.  
- Loads pre-trained DFA rules, XGBoost, and ANN models.  
- Returns structured JSON responses with detailed pipeline analysis.

### 3. Database (SQLite)
- Lightweight, file-based storage for persistent logging of all analysis events.  
- Populates **Threat Log** and **Reporting & Analytics** tabs.

### 4. Analysis Pipeline Flow

1. **Stateless DFA**:  
   Checks for known malicious signatures.  
2. **Stateful DFA**:  
   Tracks sequences and session states.  
3. **XGBoost**:  
   Performs anomaly detection using learned traffic patterns.  
4. **ANN**:  
   Conducts final classification for complex patterns.  

The **first stage to identify a threat** determines the outcome.  
If all pass, the packet is marked as **Safe**.

---

## 🧠 Technologies Used

| Category | Technologies |
|-----------|---------------|
| **Frontend** | Streamlit |
| **Backend** | Flask |
| **Database** | SQLite |
| **ML / Data Science** | Pandas, Scikit-learn, XGBoost, TensorFlow/Keras |
| **Core Language** | Python 3.9+ |

---

## 🚀 Setup and Installation

### Prerequisites
- Python 3.9 or higher  
- `pip` package manager  
- Virtual environment tool (`venv` recommended)

### Installation Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/hybrid-ids-project.git
   cd hybrid-ids-project
   ```

2. **Create and activate a virtual environment**
   - **macOS/Linux:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
   - **Windows:**
     ```bash
     python -m venv venv
     .\venv\Scripts\activate
     ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
   *(If missing, manually install: `streamlit`, `flask`, `pandas`, `requests`, `xgboost`, `tensorflow`, `scikit-learn`)*

4. **Run the Backend Server**
   ```bash
   python backend.py
   ```
   The backend runs on [http://127.0.0.1:5000](http://127.0.0.1:5000)

5. **Run the Frontend**
   ```bash
   streamlit run frontend.py
   ```
   Opens automatically at [http://localhost:8501](http://localhost:8501)

---

## 🧭 How to Use the Application

### 🔬 Live Analysis Tab
The main control panel for the IDS.

- **Live Simulation**: Toggle ON to feed random packets automatically.  
  Adjust delay using the “Simulation Speed” slider.  
- **Manual Analysis**:
  1. Paste packet JSON manually or load a sample (`Stateless`, `Stateful`, `ML Attack`, `Benign`).
  2. Click **Analyze Packet**.
- **Results**: Displays:
  - Final status (`Safe` / `Not Safe`)
  - Severity & recommended action
  - Pipeline verdict breakdown
- **Stateful Tracker**:  
  Shows current states of all tracked source IPs (can be cleared anytime).

### 📈 Reporting & Analytics Tab
Displays metrics like:
- Total packets processed  
- Total threats detected  
- Detection rate & performance over time

### 📋 Threat Log Tab
A detailed, filterable log of every IDS event.

- **Search**: Filter by keyword (IP, severity, etc.)  
- **Download**: Export logs as CSV  
- **Clear Logs**: Delete all entries from the database

---

## 🧩 Backend API Endpoints

### `GET /status`
**Description:** Health check for backend server.  
**Response:**
```json
{
  "status": "online"
}
```

### `POST /analyze`
**Description:** Submits packet data for analysis.

**Request Body:**
```json
{
  "packet_data": {
    "Destination Port": 80,
    "Flow Duration": 500000,
    "Total Fwd Packets": 60,
    "...": "..."
  },
  "current_state": "START",
  "ml_threshold": 0.70
}
```

**Response Body:**
```json
{
  "final_result": {
    "status": "Not Safe",
    "reason": "Stateful DFA Match",
    "details": "Multiple failed login attempts detected from 10.0.0.5."
  },
  "new_state": "ALERT",
  "pipeline_steps": [
    {
      "stage": "Stateless DFA",
      "status": "Passed",
      "details": "No stateless rule match."
    },
    {
      "stage": "Stateful DFA",
      "status": "Failed",
      "details": "Transitioned to ALERT state due to failed login event."
    }
  ]
}
```

---

## 🪪 License
This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

---

## 🧑‍💻 Author
**Your Name**  
Hybrid IDS Project — Combining DFA + ML + ANN for Smarter Threat Detection
