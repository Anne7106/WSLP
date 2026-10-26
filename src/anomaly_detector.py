import os
import time
import requests
from datetime import datetime, timedelta
from core import db, init_db, settings, metric, RULES, SEV

ICON = {"critical": "🔴", "warning": "🟠", "info": "🔵"}

def slack(cfg, text):
    print("SLACK:", text)
    url = cfg.get("slack_webhook") or os.getenv("SLACK_WEBHOOK_URL", "")
    if url:
        try:
            requests.post(url, json={"text": text}, timeout=5)
        except Exception as e:
            print("Slack failed:", e)

def cycle(cur, only_site=None):
    init_db(cur)
    cfg, now = settings(cur), datetime.utcnow()      # thresholds re-read every cycle -> UI edits apply live
    min_sev = SEV[cfg["slack_min_severity"]]
    cur.execute("UPDATE incidents SET status='resolved',resolved_by='system',resolved_at=%s WHERE status<>'resolved' "
                "AND (site_id,rule) IN (SELECT site_id,rule FROM alert_rules WHERE NOT enabled)", (now,))
    cur.execute("SELECT site_id,rule,threshold,severity FROM alert_rules WHERE enabled "
                "AND (%s::text IS NULL OR site_id=%s)", (only_site, only_site))
    for site, rule, thr, sev in cur.fetchall():
        val = metric(cur, site, rule)
        label, unit = RULES[rule][:2]
        cur.execute("SELECT id,notified_sev,last_seen,status FROM incidents WHERE site_id=%s AND rule=%s "
                    "AND status IN ('open','acked')", (site, rule))
        inc = cur.fetchone()
        if val > thr:
            detail = f"{label}: {val:.1f} {unit} (limit {thr:g})"
            if not inc:
                # a flapping problem that auto-resolved moments ago reopens the SAME incident, silently
                cur.execute("UPDATE incidents SET status='open',resolved_at=NULL,resolved_by=NULL WHERE id=("
                            "SELECT id FROM incidents WHERE site_id=%s AND rule=%s AND status='resolved' "
                            "AND resolved_by='system' AND resolved_at>%s ORDER BY id DESC LIMIT 1) "
                            "RETURNING id,notified_sev,last_seen,status",
                            (site, rule, now - timedelta(minutes=float(cfg["reopen_cooldown_min"]))))
                inc = cur.fetchone()
            if inc:
                iid, was = inc[0], inc[1]
                cur.execute("UPDATE incidents SET hits=hits+1,last_seen=%s,peak=GREATEST(peak,%s),detail=%s,severity=%s "
                            "WHERE id=%s", (now, val, detail, sev, iid))
            else:
                cur.execute("INSERT INTO incidents(site_id,rule,severity,first_seen,last_seen,peak,detail) "
                            "VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING id", (site, rule, sev, now, now, val, detail))
                iid, was = cur.fetchone()[0], None
            cur.execute("INSERT INTO detections(incident_id,ts,value) VALUES(%s,%s,%s)", (iid, now, val))
            # alert on first open, or when severity rises above what Slack was last told (also un-acks it)
            if SEV[sev] >= min_sev and (was is None or SEV[sev] > SEV[was]):
                head = "ALERT" if was is None else f"ESCALATED to {sev.upper()}"
                slack(cfg, f"{ICON[sev]} *[{site}] {head}* - {detail}")
                cur.execute("UPDATE incidents SET notified=TRUE,notified_sev=%s,status='open' WHERE id=%s", (sev, iid))
            # note: acknowledging does NOT silence detection - it keeps updating, it just stops repeat messages
        elif inc and now - inc[2] > timedelta(minutes=float(cfg["resolve_after_min"])):
            cur.execute("UPDATE incidents SET status='resolved',resolved_by='system',resolved_at=%s WHERE id=%s", (now, inc[0]))
            if inc[1]:
                slack(cfg, f"✅ *[{site}]* {label} is back to normal")
    if only_site:
        return
    last = cfg.get("last_digest")
    if not last or now - datetime.fromisoformat(last) >= timedelta(minutes=float(cfg["digest_minutes"])):
        cur.execute("SELECT site_id,severity,detail,hits FROM incidents WHERE status<>'resolved'")
        rows = sorted(cur.fetchall(), key=lambda r: -SEV[r[1]])
        if rows:
            lines = [f"{ICON[s]} [{site}] {d} - seen {h}x" for site, s, d, h in rows]
            slack(cfg, f"📋 *Digest: {len(rows)} open incident(s)*\n" + "\n".join(lines))
        cur.execute("UPDATE app_settings SET value=%s WHERE key='last_digest'", (now.isoformat(),))
        cur.execute("DELETE FROM detections WHERE ts<%s", (now - timedelta(days=7),))   # keep 7 days of history

if __name__ == "__main__":
    print("Detector running (reads thresholds from the database every 15s)...")
    while True:
        try:
            conn = db()
            cycle(conn.cursor())
            conn.close()
        except Exception as e:
            print("Cycle error:", e)
        time.sleep(15)