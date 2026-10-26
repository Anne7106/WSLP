import os
import psycopg2
from datetime import datetime, timedelta

def db():
    c = psycopg2.connect(host=os.getenv("PG_HOST", "localhost"), port=int(os.getenv("PG_PORT", "5433")),
                         dbname="wslp_db", user="wslp_user", password="wslp_pass")
    c.autocommit = True
    return c

SEV = {"info": 0, "warning": 1, "critical": 2}
PATHS = ["/wp-admin", "/.env", "/admin", "/phpmyadmin"]
# rule: (label, unit, window_minutes, default_threshold, default_severity)
RULES = {
    "BOT_SUSPECTED":   ("Bot / DDoS (max requests from one IP)", "req/min", 1, 20, "critical"),
    "HIGH_ERROR_RATE": ("Server error rate (5xx)", "%", 1, 10, "critical"),
    "SLOW_RESPONSE":   ("Average response time", "ms", 5, 1000, "warning"),
    "SCAN_ATTEMPT":    ("Vulnerability scanning (/.env, /wp-admin...)", "probes/min", 1, 25, "warning"),
    "BROKEN_LINKS":    ("Broken links (404s)", "404s/5min", 5, 15, "info"),
}
EXPR = {
    "HIGH_ERROR_RATE": "COALESCE(100.0*COUNT(*) FILTER (WHERE status_code>=500)/NULLIF(COUNT(*),0),0)",
    "SLOW_RESPONSE": "COALESCE(AVG(response_time_ms),0)",
    "BROKEN_LINKS": "COUNT(*) FILTER (WHERE status_code=404)",
    "SCAN_ATTEMPT": "COUNT(*) FILTER (WHERE endpoint = ANY(%s))",
}
DEFAULTS = {"slack_webhook": "", "slack_min_severity": "critical", "digest_minutes": "10",
            "resolve_after_min": "2", "reopen_cooldown_min": "10", "last_digest": ""}

SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_rules(site_id TEXT, rule TEXT, enabled BOOLEAN DEFAULT TRUE,
  threshold FLOAT, severity TEXT, PRIMARY KEY(site_id, rule));
CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS incidents(id SERIAL PRIMARY KEY, site_id TEXT, rule TEXT, severity TEXT,
  status TEXT DEFAULT 'open', first_seen TIMESTAMP, last_seen TIMESTAMP, hits INT DEFAULT 1,
  peak FLOAT, detail TEXT, notified BOOLEAN DEFAULT FALSE);
CREATE TABLE IF NOT EXISTS audit_log(id SERIAL PRIMARY KEY, ts TIMESTAMP DEFAULT NOW(), change TEXT);
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS updated_by TEXT, ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS acked_by TEXT, ADD COLUMN IF NOT EXISTS acked_at TIMESTAMP,
  ADD COLUMN IF NOT EXISTS resolved_by TEXT, ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP, ADD COLUMN IF NOT EXISTS notified_sev TEXT;
CREATE TABLE IF NOT EXISTS detections(id SERIAL PRIMARY KEY, incident_id INT, ts TIMESTAMP, value FLOAT);
CREATE INDEX IF NOT EXISTS ix_det ON detections(incident_id);
"""

LIMITS = {"BOT_SUSPECTED": (1, 100000), "HIGH_ERROR_RATE": (0, 100), "SLOW_RESPONSE": (1, 600000),
          "SCAN_ATTEMPT": (1, 100000), "BROKEN_LINKS": (1, 100000)}

def validate(rule, threshold, severity):
    if rule not in RULES:
        raise ValueError("Unknown rule")
    if severity not in SEV:
        raise ValueError("Severity must be info, warning or critical")
    try:
        t = float(threshold)
    except (TypeError, ValueError):
        raise ValueError("Threshold must be a number")
    lo, hi = LIMITS[rule]
    if not lo <= t <= hi:
        raise ValueError(f"Threshold must be between {lo} and {hi} ({RULES[rule][1]})")
    return t

def init_db(cur):
    cur.execute(SCHEMA)
    for k, v in DEFAULTS.items():
        cur.execute("INSERT INTO app_settings VALUES (%s,%s) ON CONFLICT DO NOTHING", (k, v))
    cur.execute("SELECT DISTINCT site_id FROM web_logs")
    for (s,) in cur.fetchall():
        for r, m in RULES.items():
            cur.execute("INSERT INTO alert_rules(site_id,rule,threshold,severity) VALUES(%s,%s,%s,%s) "
                        "ON CONFLICT DO NOTHING", (s, r, m[3], m[4]))

def settings(cur):
    cur.execute("SELECT key,value FROM app_settings")
    return dict(cur.fetchall())

def metric(cur, site, rule):
    """Current value of a rule over its window."""
    since = datetime.utcnow() - timedelta(minutes=RULES[rule][2])
    if rule == "BOT_SUSPECTED":
        cur.execute("SELECT COALESCE(MAX(c),0) FROM (SELECT COUNT(*) c FROM web_logs "
                    "WHERE site_id=%s AND timestamp>%s GROUP BY ip_address) t", (site, since))
    else:
        cur.execute(f"SELECT {EXPR[rule]} FROM web_logs WHERE site_id=%s AND timestamp>%s",
                    ([PATHS] if rule == "SCAN_ATTEMPT" else []) + [site, since])
    return float(cur.fetchone()[0])

def series(cur, site, rule, hours=1):
    """Metric per window-sized bucket over the last N hours (used for threshold back-testing)."""
    w = f"{RULES[rule][2]} minutes"
    since = datetime.utcnow() - timedelta(hours=hours)
    b = "date_bin(%s::interval, timestamp, TIMESTAMP '2000-01-01')"
    if rule == "BOT_SUSPECTED":
        sql = (f"SELECT b, MAX(c) FROM (SELECT {b} b, COUNT(*) c FROM web_logs WHERE site_id=%s "
               "AND timestamp>%s GROUP BY b, ip_address) t GROUP BY b ORDER BY b")
        p = [w, site, since]
    else:
        sql = f"SELECT {b} b, {EXPR[rule]} FROM web_logs WHERE site_id=%s AND timestamp>%s GROUP BY b ORDER BY b"
        p = [w] + ([PATHS] if rule == "SCAN_ATTEMPT" else []) + [site, since]
    cur.execute(sql, p)
    return [(t.isoformat(), float(v)) for t, v in cur.fetchall()]