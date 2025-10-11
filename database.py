import sqlite3
import pandas as pd
from datetime import datetime

DB_NAME = "ids_log.db"

def init_db():
    """Initializes the database and creates the 'logs' table if it doesn't exist."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                destination_port INTEGER,
                status TEXT,
                reason TEXT,
                severity TEXT,
                recommendation TEXT,
                details TEXT
            )
        """)
        conn.commit()

def add_log_entry(log_data: dict):
    """Adds a new analysis log entry to the database."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO logs (
                timestamp, source_ip, destination_port, status, reason,
                severity, recommendation, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log_data.get('Timestamp').strftime('%Y-%m-%d %H:%M:%S'),
            log_data.get('Source IP'),
            log_data.get('Destination Port'),
            log_data.get('Status'),
            log_data.get('Reason'),
            log_data.get('Severity'),
            log_data.get('Recommendation'),
            log_data.get('Details')
        ))
        conn.commit()

def get_logs_as_df() -> pd.DataFrame:
    """Retrieves all logs from the database and returns them as a Pandas DataFrame."""
    with sqlite3.connect(DB_NAME) as conn:
        # Query logs and order by the latest first
        df = pd.read_sql_query("SELECT * FROM logs ORDER BY timestamp DESC", conn)
        # Convert timestamp column back to datetime objects for correct sorting/display
        if not df.empty and 'timestamp' in df.columns:
            df['Timestamp'] = pd.to_datetime(df['timestamp'])
        return df

def clear_logs():
    """Deletes all records from the logs table."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM logs")
        conn.commit()