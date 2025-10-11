import sqlite3
import pandas as pd
import os

DB_NAME = "ids_log.db"

def view_all_records():
    """Connects to the database and prints all records from the 'logs' table."""
    if not os.path.exists(DB_NAME):
        print(f"Error: Database file '{DB_NAME}' not found.")
        print("Please run the main application first to generate some logs.")
        return

    try:
        with sqlite3.connect(DB_NAME) as conn:
            # Use pandas to read the entire table into a DataFrame
            df = pd.read_sql_query("SELECT * FROM logs", conn)

            if df.empty:
                print("The 'logs' table is empty. No records to show.")
            else:
                print(f"--- Displaying all {len(df)} records from '{DB_NAME}' ---")
                # Set pandas display options to show all rows and columns
                pd.set_option('display.max_rows', None)
                pd.set_option('display.max_columns', None)
                pd.set_option('display.width', 1000)
                print(df)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    view_all_records()