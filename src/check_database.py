import sqlite3

DATABASE_FILE = "data/logs.db"

connection = sqlite3.connect(DATABASE_FILE)
cursor = connection.cursor()

print("===== DATABASE CHECK =====")

print("\nTables:")
tables = cursor.execute(
    "SELECT name FROM sqlite_master WHERE type = 'table'"
).fetchall()

for table in tables:
    print("-", table[0])

print("\nTotal web log records:")
count = cursor.execute(
    "SELECT COUNT(*) FROM web_logs"
).fetchone()[0]

print(count)

print("\nFirst 5 web log records:")
rows = cursor.execute(
    "SELECT * FROM web_logs LIMIT 5"
).fetchall()

for row in rows:
    print(row)
print("\nDetected anomalies:")

anomalies = cursor.execute(
    """
    SELECT
        detected_at,
        anomaly_type,
        description,
        metric_value,
        threshold,
        severity
    FROM anomalies
    ORDER BY detected_at DESC
    """
).fetchall()

if anomalies:
    for anomaly in anomalies:
        print(anomaly)
else:
    print("No anomalies recorded yet.")
connection.close()
