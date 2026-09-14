
import os
import time
import sqlite3
from datetime import datetime

# Project paths
LOG_FILE = "data/server.log"
DATABASE_FILE = "data/logs.db"

os.makedirs("data", exist_ok=True)


def create_database():
    """Create the database and logs table if they do not exist."""

    connection = sqlite3.connect(DATABASE_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS web_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            http_method TEXT NOT NULL,
            url TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            response_time INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()

    print("Database is ready.")


def parse_log(line):
    """Convert one log line into structured data."""

    parts = line.strip().split()

    # Expected format:
    # IP DATE TIME METHOD URL STATUS RESPONSE_TIME

    if len(parts) != 7:
        return None

    try:
        ip_address = parts[0]
        timestamp = f"{parts[1]} {parts[2]}"
        http_method = parts[3]
        url = parts[4]
        status_code = int(parts[5])
        response_time = int(parts[6])

        # Validate timestamp
        datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

        return (
            ip_address,
            timestamp,
            http_method,
            url,
            status_code,
            response_time
        )

    except (ValueError, IndexError):
        return None


def save_log(record):
    """Insert one structured record into SQLite."""

    connection = sqlite3.connect(DATABASE_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO web_logs (
            ip_address,
            timestamp,
            http_method,
            url,
            status_code,
            response_time
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, record)

    connection.commit()
    connection.close()


def process_new_logs():
    """Monitor the log file and process new lines."""

    print("Live log processor started.")
    print("Monitoring:", LOG_FILE)
    print("Press Ctrl+C to stop.\n")

    # Start at the current end of the file.
    # Existing historical records are not duplicated.
    
    with open(LOG_FILE, "r", encoding="utf-8") as file:

        file.seek(0)

        while True:

            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            record = parse_log(line)

            if record is None:
                print("Skipped invalid log:", line.strip())
                continue

            save_log(record)

            print(
                f"Stored: {record[1]} | "
                f"{record[0]} | "
                f"{record[3]} | "
                f"Status: {record[4]} | "
                f"{record[5]} ms"
            )


if __name__ == "__main__":

    create_database()

    try:
        process_new_logs()

    except FileNotFoundError:
        print("Log file not found:", LOG_FILE)
        print("Start the log generator first.")

    except KeyboardInterrupt:
        print("\nLive processor stopped.")
