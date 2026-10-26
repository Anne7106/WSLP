import os, requests

webhook_url = os.getenv("SLACK_WEBHOOK_URL")
if not webhook_url:
    raise SystemExit("Set it first: $env:SLACK_WEBHOOK_URL='https://hooks.slack.com/services/...'")
r = requests.post(webhook_url, json={"text": "Test message from WSLP"})
print(r.status_code, r.text)