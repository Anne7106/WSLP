import psycopg2
import requests
import os
from datetime import datetime, timedelta

conn = psycopg2.connect(host="localhost", port=5432, dbname="wslp_db", user="wslp_user", password="wslp_pass")
cur = conn.cursor()

# ---- Put your Slack webhook URL here (Phase 5c explains how to get one) ----
import os

WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

SUSPICIOUS_PATHS = ["/wp-admin", "/.env", "/admin", "/phpmyadmin"]

def send_alert(message):
    print(f"ALERT: {message}")
    if SLACK_WEBHOOK_URL and "PASTE" not in SLACK_WEBHOOK_URL:
        try:
            requests.post(SLACK_WEBHOOK_URL, json={"text": message})
        except Exception as e:
            print(f"Failed to send Slack alert: {e}")

def log_anomaly(site_id, anomaly_type, severity, description):
    cur.execute("""
        INSERT INTO anomalies (site_id, detected_at, anomaly_type, severity, description)
        VALUES (%s, %s, %s, %s, %s)
    """, (site_id, datetime.utcnow(), anomaly_type, severity, description))
    conn.commit()
    send_alert(f"[{site_id}] {anomaly_type} ({severity}): {description}")

def get_sites():
    cur.execute("SELECT DISTINCT site_id FROM web_logs")
    return [row[0] for row in cur.fetchall()]

# ---------------------------------------------------------------------------
# 1. SECURITY — Attack & Bot Detection
# ---------------------------------------------------------------------------
def check_security(site_id):
    since = datetime.utcnow() - timedelta(minutes=1)

    # A) Same IP hammering the site = possible bot/DDoS
    cur.execute("""
        SELECT ip_address, COUNT(*) as cnt
        FROM web_logs
        WHERE site_id = %s AND timestamp > %s
        GROUP BY ip_address
        HAVING COUNT(*) > 20
    """, (site_id, since))
    for ip, cnt in cur.fetchall():
        log_anomaly(site_id, "BOT_SUSPECTED", "HIGH",
                    f"IP {ip} made {cnt} requests in the last minute")
        cur.execute("""
            INSERT INTO blocked_ips (site_id, ip_address, reason)
            VALUES (%s, %s, %s)
        """, (site_id, ip, f"{cnt} requests/min"))
        conn.commit()

    # B) Requests to sensitive/scanning paths
    cur.execute("""
        SELECT ip_address, endpoint, COUNT(*)
        FROM web_logs
        WHERE site_id = %s AND timestamp > %s AND endpoint = ANY(%s)
        GROUP BY ip_address, endpoint
    """, (site_id, since, SUSPICIOUS_PATHS))
    for ip, endpoint, cnt in cur.fetchall():
        log_anomaly(site_id, "SCAN_ATTEMPT", "MEDIUM",
                    f"IP {ip} probed suspicious path {endpoint}")

# ---------------------------------------------------------------------------
# 2. UPTIME & RELIABILITY MONITORING
# ---------------------------------------------------------------------------
def check_uptime(site_id):
    since = datetime.utcnow() - timedelta(minutes=1)
    cur.execute("""
        SELECT
            COUNT(*) FILTER (WHERE status_code >= 500) as errors,
            COUNT(*) as total
        FROM web_logs
        WHERE site_id = %s AND timestamp > %s
    """, (site_id, since))
    errors, total = cur.fetchone()
    if total == 0:
        return
    error_rate = (errors / total) * 100
    if error_rate > 10:
        log_anomaly(site_id, "HIGH_ERROR_RATE", "HIGH",
                    f"Error rate {error_rate:.1f}% ({errors}/{total} requests) in last minute")

# ---------------------------------------------------------------------------
# 3. REAL-TIME ALERTING
#    (already wired in — log_anomaly() above calls send_alert() every time)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 4. TRAFFIC & BUSINESS INSIGHTS
# ---------------------------------------------------------------------------
def traffic_insights(site_id):
    since = datetime.utcnow() - timedelta(minutes=5)
    cur.execute("""
        SELECT endpoint, COUNT(*) as hits
        FROM web_logs
        WHERE site_id = %s AND timestamp > %s
        GROUP BY endpoint ORDER BY hits DESC LIMIT 3
    """, (site_id, since))
    top = cur.fetchall()
    print(f"[{site_id}] Top endpoints (last 5 min): {top}")

    cur.execute("""
        SELECT COUNT(*) FROM web_logs
        WHERE site_id = %s AND timestamp > %s AND status_code = 404
    """, (site_id, since))
    broken = cur.fetchone()[0]
    if broken > 5:
        log_anomaly(site_id, "BROKEN_LINKS", "LOW",
                    f"{broken} 404 errors in last 5 min — check for broken links")

# ---------------------------------------------------------------------------
# 5. CAPACITY PLANNING
# ---------------------------------------------------------------------------
def capacity_check(site_id):
    since = datetime.utcnow() - timedelta(minutes=5)
    cur.execute("""
        SELECT AVG(response_time_ms), COUNT(*)
        FROM web_logs
        WHERE site_id = %s AND timestamp > %s
    """, (site_id, since))
    avg_time, volume = cur.fetchone()
    if avg_time and volume:
        print(f"[{site_id}] Avg response: {avg_time:.0f}ms over {volume} requests (last 5 min)")
        if avg_time > 1000 and volume > 20:
            log_anomaly(site_id, "CAPACITY_WARNING", "MEDIUM",
                        f"Response time degrading ({avg_time:.0f}ms) under load ({volume} req/5min) — consider scaling")

# ---------------------------------------------------------------------------
# MAIN LOOP
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import time
    print("Anomaly detector running. Checking every 15 seconds...")
    while True:
        for site in get_sites():
            check_security(site)
            check_uptime(site)
            traffic_insights(site)
            capacity_check(site)
        time.sleep(15)