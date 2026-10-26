import requests
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, send_from_directory
from core import db, init_db, settings, series, validate, RULES, SEV, DEFAULTS

app = Flask(__name__, static_folder="static")

def q(sql, p=()):
    c = db()
    cur = c.cursor()
    cur.execute(sql, p)
    out = [dict(zip([d[0] for d in cur.description], r)) for r in cur.fetchall()] if cur.description else []
    c.close()
    return out

def operator():
    return ((request.get_json(silent=True) or {}).get("who") or "unknown")[:40]

def audit(who, text):
    q("INSERT INTO audit_log(change) VALUES(%s)", (f"{who}: {text}",))

def sites(s):
    return [r["site_id"] for r in q("SELECT DISTINCT site_id FROM alert_rules")] if s == "*" else [s]

@app.route("/")
def home():
    return send_from_directory("static", "index.html")

@app.route("/api/overview")
def overview():
    since = datetime.utcnow() - timedelta(hours=24)
    d = q("""SELECT COUNT(*) FILTER (WHERE status<>'resolved') AS open,
        COUNT(*) FILTER (WHERE status<>'resolved' AND severity='critical') AS critical,
        COALESCE(SUM(hits),0)::int AS raw, COUNT(*) AS incidents,
        COUNT(*) FILTER (WHERE notified) AS slack FROM incidents WHERE last_seen>%s""", (since,))[0]
    d["sites"] = [r["site_id"] for r in q("SELECT DISTINCT site_id FROM alert_rules ORDER BY 1")]
    return jsonify(d)

@app.route("/api/incidents")
def incidents():
    a, w, p = request.args, [], []
    if a.get("site"):
        w.append("site_id=%s"); p.append(a["site"])
    if a.get("severity"):
        w.append("severity=%s"); p.append(a["severity"])
    st = a.get("status", "active")
    if st == "active":
        w.append("status<>'resolved'")
    elif st != "all":
        w.append("status=%s"); p.append(st)
    return jsonify(q("SELECT * FROM incidents" + (" WHERE " + " AND ".join(w) if w else "") +
                     " ORDER BY (status='resolved'), first_seen DESC LIMIT 200", p))

@app.route("/api/incidents/<int:i>/history")
def history(i):
    return jsonify(q("SELECT ts, value FROM detections WHERE incident_id=%s ORDER BY ts DESC LIMIT 30", (i,)))

@app.route("/api/incidents/<int:i>/<action>", methods=["POST"])
def act(i, action):
    if action not in ("ack", "resolve"):
        return jsonify(error="bad action"), 400
    u, now = operator(), datetime.utcnow()
    if action == "ack":
        q("UPDATE incidents SET status='acked',acked_by=%s,acked_at=%s WHERE id=%s AND status='open'", (u, now, i))
    else:
        q("UPDATE incidents SET status='resolved',resolved_by=%s,resolved_at=%s WHERE id=%s AND status<>'resolved'", (u, now, i))
    audit(u, f"incident #{i} {action}")
    return jsonify(ok=True)

@app.route("/api/rules")
def rules():
    rows = q("SELECT * FROM alert_rules ORDER BY site_id, rule")
    for r in rows:
        r["label"], r["unit"], r["window"] = RULES[r["rule"]][:3]
        r["default"] = RULES[r["rule"]][3]
    return jsonify(rows)

@app.route("/api/rules", methods=["POST"])
def save_rule():
    d, u = request.json, operator()
    try:
        t = validate(d.get("rule"), d.get("threshold"), d.get("severity"))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    for s in sites(d["site_id"]):
        q("UPDATE alert_rules SET enabled=%s,threshold=%s,severity=%s,updated_by=%s,updated_at=%s WHERE site_id=%s AND rule=%s",
          (bool(d.get("enabled")), t, d["severity"], u, datetime.utcnow(), s, d["rule"]))
    audit(u, f"{d['site_id']}/{d['rule']} -> enabled={d.get('enabled')}, threshold={t:g}, severity={d['severity']}")
    return jsonify(ok=True)

@app.route("/api/rules/reset", methods=["POST"])
def reset_rule():
    d, u = request.json, operator()
    if d.get("rule") not in RULES:
        return jsonify(error="Unknown rule"), 400
    m = RULES[d["rule"]]
    for s in sites(d["site_id"]):
        q("UPDATE alert_rules SET enabled=TRUE,threshold=%s,severity=%s,updated_by=%s,updated_at=%s WHERE site_id=%s AND rule=%s",
          (m[3], m[4], u, datetime.utcnow(), s, d["rule"]))
    audit(u, f"{d['site_id']}/{d['rule']} reset to default ({m[3]} {m[1]}, {m[4]})")
    return jsonify(ok=True)

@app.route("/api/backtest")
def backtest():
    s, r, t = request.args["site"], request.args["rule"], float(request.args["threshold"])
    c = db()
    pts = series(c.cursor(), s, r)
    c.close()
    return jsonify(points=pts, breaches=sum(v > t for _, v in pts), total=len(pts))

@app.route("/api/settings")
def get_settings():
    c = db(); cfg = settings(c.cursor()); c.close()
    w = cfg.get("slack_webhook", "")
    cfg["slack_webhook"] = ("…" + w[-6:]) if w else ""      # the real URL never reaches the browser
    cfg.pop("last_digest", None)
    return jsonify(cfg)

@app.route("/api/settings", methods=["POST"])
def set_settings():
    d, u = request.json, operator()
    for k, v in d.items():
        if k not in DEFAULTS or k == "last_digest" or (k == "slack_webhook" and str(v).startswith("…")):
            continue
        if k == "slack_min_severity" and v not in SEV:
            return jsonify(error="Invalid severity"), 400
        if k.endswith(("_min", "_minutes")):
            try:
                assert float(v) >= 1
            except (ValueError, AssertionError):
                return jsonify(error=f"{k} must be a number of at least 1"), 400
        if k == "slack_webhook" and v and not str(v).startswith("https://hooks.slack.com/"):
            return jsonify(error="Webhook must start with https://hooks.slack.com/"), 400
        q("UPDATE app_settings SET value=%s WHERE key=%s", (str(v), k))
        audit(u, f"setting {k} changed" if k == "slack_webhook" else f"setting {k} = {v}")
    return jsonify(ok=True)

@app.route("/api/test-slack", methods=["POST"])
def test_slack():
    c = db(); url = settings(c.cursor()).get("slack_webhook"); c.close()
    if not url:
        return jsonify(ok=False, error="No webhook saved yet"), 400
    r = requests.post(url, json={"text": "✅ WSLP control panel test message"}, timeout=5)
    return jsonify(ok=r.status_code == 200, status=r.status_code)

@app.route("/api/audit")
def get_audit():
    return jsonify(q("SELECT ts, change FROM audit_log ORDER BY id DESC LIMIT 50"))

if __name__ == "__main__":
    c = db(); init_db(c.cursor()); c.close()
    app.run(port=5050, debug=False)