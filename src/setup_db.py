Create src/setup_db.py:

import psycopg2

conn = psycopg2.connect(
    host="localhost",
    port=5432,
    dbname="wslp_db",
    user="wslp_user",
    password="wslp_pass"
)
cur = conn.cursor()

# Main table: every parsed log line goes here
cur.execute("""
CREATE TABLE IF NOT EXISTS web_logs (
    id SERIAL PRIMARY KEY,
    site_id VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    ip_address VARCHAR(45),
    method VARCHAR(10),
    endpoint VARCHAR(255),
    status_code INT,
    response_time_ms INT,
    user_agent VARCHAR(255)
);
""")

# Anomalies table: every problem the detector finds
cur.execute("""
CREATE TABLE IF NOT EXISTS anomalies (
    id SERIAL PRIMARY KEY,
    site_id VARCHAR(50) NOT NULL,
    detected_at TIMESTAMP NOT NULL,
    anomaly_type VARCHAR(50),
    severity VARCHAR(20),
    description TEXT
);
""")

# Blocked IPs table: for security detection
cur.execute("""
CREATE TABLE IF NOT EXISTS blocked_ips (
    id SERIAL PRIMARY KEY,
    site_id VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    reason TEXT,
    blocked_at TIMESTAMP DEFAULT NOW()
);
""")

conn.commit()
cur.close()
conn.close()
print("Tables created successfully.")
