"""Run from the project root:  python tests/test_rules.py
Uses an isolated site 'zz_test' with known log rows, so real sites and real Slack are never touched."""
import sys, os
from datetime import datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import anomaly_detector as ad
from core import db, init_db, metric, series, validate, settings

SITE = "zz_test"
c = db(); cur = c.cursor()
init_db(cur)
orig = settings(cur)
sent = []
ad.slack = lambda cfg, text: sent.append(text)     # capture instead of posting to Slack

def wipe():
    cur.execute("DELETE FROM detections WHERE incident_id IN (SELECT id FROM incidents WHERE site_id=%s)", (SITE,))
    for t in ("incidents", "alert_rules", "web_logs"):
        cur.execute(f"DELETE FROM {t} WHERE site_id=%s", (SITE,))

def rule(r, thr=None, sev=None, on=True):
    cur.execute("UPDATE alert_rules SET threshold=COALESCE(%s,threshold),severity=COALESCE(%s,severity),enabled=%s "
                "WHERE site_id=%s AND rule=%s", (thr, sev, on, SITE, r))

def incs(r):
    cur.execute("SELECT id,status,hits FROM incidents WHERE site_id=%s AND rule=%s ORDER BY id", (SITE, r))
    return cur.fetchall()

try:
    wipe()
    # --- known data: 45 requests, all in one minute bucket -------------------------------------------------------
    ts = datetime.utcnow().replace(second=1, microsecond=0)
    rows = [("9.9.9.9", "/", 200, 100)] * 30                                   # one IP, 30 requests
    rows += [(f"1.1.1.{i}", "/", 500 if i < 5 else 200, 300) for i in range(10)]   # 5 server errors
    rows += [(f"2.2.2.{i}", "/.env", 404, 100) for i in range(5)]              # 5 scans, all 404
    for ip, ep, st, rt in rows:
        cur.execute("INSERT INTO web_logs(site_id,timestamp,ip_address,method,endpoint,status_code,response_time_ms,user_agent) "
                    "VALUES(%s,%s,%s,'GET',%s,%s,%s,'test')", (SITE, ts, ip, ep, st, rt))
    init_db(cur)
    expected = {"BOT_SUSPECTED": 30, "HIGH_ERROR_RATE": 100 * 5 / 45, "SLOW_RESPONSE": 6500 / 45,
                "SCAN_ATTEMPT": 5, "BROKEN_LINKS": 5}
    for r, exp in expected.items():
        got = metric(cur, SITE, r)
        assert abs(got - exp) < 0.01, f"{r}: metric {got} != {exp}"
        pts = series(cur, SITE, r)                       # the preview chart must agree with the live metric
        assert len(pts) == 1 and abs(pts[0][1] - exp) < 0.01, f"{r}: chart {pts} != {exp}"
    print("PASS metrics and preview charts match known data")

    # --- validation ----------------------------------------------------------------------------------------------
    for bad in (("HIGH_ERROR_RATE", 150, "info"), ("BOT_SUSPECTED", "abc", "info"), ("BOT_SUSPECTED", 5, "urgent"), ("NOPE", 1, "info")):
        try:
            validate(*bad); raise SystemExit(f"validate accepted {bad}")
        except ValueError:
            pass
    print("PASS validation rejects bad input")

    # --- incident lifecycle (Slack threshold = critical only, instant auto-resolve) ------------------------------
    cur.execute("UPDATE app_settings SET value='critical' WHERE key='slack_min_severity'")
    cur.execute("UPDATE app_settings SET value='0' WHERE key='resolve_after_min'")
    cur.execute("UPDATE app_settings SET value='' WHERE key='slack_webhook'")
    rule("BOT_SUSPECTED", 20, "critical"); rule("HIGH_ERROR_RATE", 10, "critical"); rule("SLOW_RESPONSE", 1000, "warning")
    rule("SCAN_ATTEMPT", 3, "warning"); rule("BROKEN_LINKS", 3, "info")
    for _ in range(3):                                   # 3 cycles = 45 seconds of the same continuing problem
        ad.cycle(cur, SITE)
    assert [len(incs(r)) for r in expected] == [1, 1, 0, 1, 1], "one incident per continuing problem"
    assert all(incs(r)[0][2] == 3 for r in ("BOT_SUSPECTED", "HIGH_ERROR_RATE")), "hits should be 3"
    assert len(sent) == 2, f"expected 2 critical alerts, got {len(sent)}: {sent}"
    print("PASS dedup: 3 cycles -> 4 incidents, only 2 Slack messages")

    rule("SCAN_ATTEMPT", sev="critical"); ad.cycle(cur, SITE)
    assert len(sent) == 3 and "ALERT" in sent[-1], sent
    rule("SCAN_ATTEMPT", sev="warning"); ad.cycle(cur, SITE)
    assert len(sent) == 3, "lowering severity must not send again"
    print("PASS severity increase alerts once")

    cur.execute("UPDATE incidents SET status='acked' WHERE site_id=%s AND rule='BOT_SUSPECTED'", (SITE,))
    before = incs("BOT_SUSPECTED")[0][2]; ad.cycle(cur, SITE)
    assert incs("BOT_SUSPECTED")[0][2] == before + 1 and len(sent) == 3, "ack must keep detecting but stay quiet"
    print("PASS acknowledged incidents keep being tracked without repeat messages")

    rule("BOT_SUSPECTED", 1000); ad.cycle(cur, SITE)
    assert incs("BOT_SUSPECTED")[0][1] == "resolved" and "back to normal" in sent[-1], sent[-1]
    n = len(sent); rule("BOT_SUSPECTED", 20); ad.cycle(cur, SITE)
    assert len(incs("BOT_SUSPECTED")) == 1 and incs("BOT_SUSPECTED")[0][1] == "open" and len(sent) == n
    print("PASS recovery message sent; flapping reopens the same incident silently")
    print("\nALL TESTS PASSED")
finally:
    wipe()
    for k, v in orig.items():
        cur.execute("UPDATE app_settings SET value=%s WHERE key=%s", (v, k))
    c.close()