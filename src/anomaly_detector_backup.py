import os
import sqlite3
import time
from datetime import datetime, timedelta


DATABASE_FILE = "data/logs.db"

# How often the detector checks the database
CHECK_INTERVAL_SECONDS = 5

# Analyze logs from the most recent 60 seconds
WINDOW_SECONDS = 60

# Detection thresholds
HIGH_ERROR_COUNT = 5
HIGH_SLOW_REQUEST_COUNT = 3
HIGH_AVERAGE_RESPONSE_TIME = 800
HIGH_TRAFFIC_COUNT = 45


def connect_database():
    """Open the SQLite database."""
    if not os.path.exists(DATABASE_FILE):
        raise FileNotFoundError(
            f"Database not found: {DATABASE_FILE}"
        )

    return sqlite3.connect(DATABASE_FILE)


def create_anomaly_table(connection):
    """Create the anomaly table if it does not already exist."""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at TEXT NOT NULL,
            anomaly_type TEXT NOT NULL,
            description TEXT NOT NULL,
            metric_value REAL,
            threshold REAL,
            severity TEXT NOT NULL,
            fingerprint TEXT UNIQUE
        )
        """
    )

    connection.commit()


def get_recent_logs(connection):
    """Read logs from the most recent time window."""
    cutoff_time = datetime.now() - timedelta(
        seconds=WINDOW_SECONDS
    )

    cutoff_text = cutoff_time.strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor = connection.execute(
        """
        SELECT
            ip_address,
            timestamp,
            http_method,
            url,
            status_code,
            response_time
        FROM web_logs
        WHERE timestamp >= ?
        ORDER BY timestamp ASC
        """,
        (cutoff_text,),
    )

    return cursor.fetchall()


def calculate_metrics(rows):
    """Calculate basic metrics for the recent logs."""
    total_requests = len(rows)

    if total_requests == 0:
        return {
            "total_requests": 0,
            "error_count": 0,
            "slow_count": 0,
            "average_response_time": 0,
        }

    error_count = 0
    slow_count = 0
    total_response_time = 0

    for row in rows:
        status_code = int(row[4])
        response_time = int(row[5])

        if status_code >= 500:
            error_count += 1

        if response_time > HIGH_AVERAGE_RESPONSE_TIME:
            slow_count += 1

        total_response_time += response_time

    average_response_time = (
        total_response_time / total_requests
    )

    return {
        "total_requests": total_requests,
        "error_count": error_count,
        "slow_count": slow_count,
        "average_response_time": average_response_time,
    }


def save_anomaly(
    connection,
    anomaly_type,
    description,
    metric_value,
    threshold,
    severity,
):
    """Save an anomaly once per minute and anomaly type."""
    detected_at = datetime.now()
    minute_bucket = detected_at.strftime(
        "%Y-%m-%d %H:%M"
    )

    fingerprint = f"{anomaly_type}:{minute_bucket}"

    connection.execute(
        """
        INSERT OR IGNORE INTO anomalies (
            detected_at,
            anomaly_type,
            description,
            metric_value,
            threshold,
            severity,
            fingerprint
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            detected_at.strftime("%Y-%m-%d %H:%M:%S"),
            anomaly_type,
            description,
            metric_value,
            threshold,
            severity,
            fingerprint,
        ),
    )

    connection.commit()


def detect_anomalies(connection, metrics):
    """Check metrics against configured thresholds."""
    anomalies_found = []

    if metrics["error_count"] >= HIGH_ERROR_COUNT:
        description = (
            f"High server error count: "
            f"{metrics['error_count']} errors in the last "
            f"{WINDOW_SECONDS} seconds"
        )

        save_anomaly(
            connection=connection,
            anomaly_type="HIGH_ERROR_RATE",
            description=description,
            metric_value=metrics["error_count"],
            threshold=HIGH_ERROR_COUNT,
            severity="HIGH",
        )

        anomalies_found.append(description)

    if metrics["slow_count"] >= HIGH_SLOW_REQUEST_COUNT:
        description = (
            f"Many slow requests: "
            f"{metrics['slow_count']} requests exceeded "
            f"{HIGH_AVERAGE_RESPONSE_TIME} ms"
        )

        save_anomaly(
            connection=connection,
            anomaly_type="SLOW_REQUESTS",
            description=description,
            metric_value=metrics["slow_count"],
            threshold=HIGH_SLOW_REQUEST_COUNT,
            severity="MEDIUM",
        )

        anomalies_found.append(description)

    if (
        metrics["average_response_time"]
        >= HIGH_AVERAGE_RESPONSE_TIME
    ):
        description = (
            f"High average response time: "
            f"{metrics['average_response_time']:.2f} ms"
        )

        save_anomaly(
            connection=connection,
            anomaly_type="HIGH_AVERAGE_RESPONSE_TIME",
            description=description,
            metric_value=metrics["average_response_time"],
            threshold=HIGH_AVERAGE_RESPONSE_TIME,
            severity="MEDIUM",
        )

        anomalies_found.append(description)

    if metrics["total_requests"] >= HIGH_TRAFFIC_COUNT:
        description = (
            f"High traffic volume: "
            f"{metrics['total_requests']} requests in the last "
            f"{WINDOW_SECONDS} seconds"
        )

        save_anomaly(
            connection=connection,
            anomaly_type="HIGH_TRAFFIC",
            description=description,
            metric_value=metrics["total_requests"],
            threshold=HIGH_TRAFFIC_COUNT,
            severity="MEDIUM",
        )

        anomalies_found.append(description)

    return anomalies_found


def run_detector_once():
    """Run one anomaly-detection cycle."""
    connection = connect_database()

    try:
        create_anomaly_table(connection)

        rows = get_recent_logs(connection)
        metrics = calculate_metrics(rows)
        anomalies = detect_anomalies(connection, metrics)

        print("\n===== LIVE ANOMALY DETECTION =====")
        print(
            "Time:",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        print(
            f"Requests in last {WINDOW_SECONDS} seconds:",
            metrics["total_requests"],
        )
        print("Server errors:", metrics["error_count"])
        print("Slow requests:", metrics["slow_count"])
        print(
            "Average response time:",
            f"{metrics['average_response_time']:.2f} ms",
        )

        if anomalies:
            print("\nDetected anomalies:")

            for anomaly in anomalies:
                print("-", anomaly)
        else:
            print("\nNo anomalies detected.")

    finally:
        connection.close()


def main():
    """Continuously monitor the database."""
    print("Starting live anomaly detector...")
    print("Press CTRL+C to stop.")

    try:
        while True:
            run_detector_once()
            time.sleep(CHECK_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\nAnomaly detector stopped.")


if __name__ == "__main__":
    main()