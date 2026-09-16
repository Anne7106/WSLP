import random
import time
import os
from datetime import datetime
from minio import Minio
import io

# --- Settings ---
SITES = ["site_a", "site_b", "site_c"]
STATUS_CODES = [200, 200, 200, 200, 301, 404, 404, 500, 503]
ENDPOINTS = ["/", "/home", "/login", "/api/users", "/checkout", "/admin", "/wp-admin", "/.env"]
METHODS = ["GET", "GET", "GET", "POST", "PUT"]

# --- MinIO connection ---
client = Minio(
    "localhost:9000",
    access_key="minioadmin",
    secret_key="minioadmin",
    secure=False
)

BUCKET = "weblogs"

def random_ip():
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

def generate_log_line():
    ip = random_ip()
    method = random.choice(METHODS)
    endpoint = random.choice(ENDPOINTS)
    status = random.choice(STATUS_CODES)
    response_time = random.randint(20, 2000)
    timestamp = datetime.utcnow().isoformat()
    return f"{timestamp}|{ip}|{method}|{endpoint}|{status}|{response_time}|Mozilla/5.0"

def upload_batch(site):
    lines = [generate_log_line() for _ in range(random.randint(5, 15))]
    content = "\n".join(lines)
    filename = f"{site}/{datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')}.log"

    data = io.BytesIO(content.encode("utf-8"))
    client.put_object(BUCKET, filename, data, length=len(content.encode("utf-8")))
    print(f"Uploaded {filename} ({len(lines)} lines)")

if _name_ == "_main_":
    while True:
        for site in SITES:
            upload_batch(site)
        time.sleep(10)  # wait 10 seconds, then generate more logs