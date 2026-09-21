import time
import psycopg2
from minio import Minio
from datetime import datetime

client = Minio("localhost:9000", access_key="minioadmin", secret_key="minioadmin", secure=False)
BUCKET = "weblogs"

conn = psycopg2.connect(host="localhost", port=5432, dbname="wslp_db", user="wslp_user", password="wslp_pass")
cur = conn.cursor()

processed_files = set()

def parse_and_insert(site_id, content):
    for line in content.strip().split("\n"):
        if not line:
            continue
        parts = line.split("|")
        if len(parts) != 7:
            continue
        timestamp, ip, method, endpoint, status, response_time, user_agent = parts
        cur.execute("""
            INSERT INTO web_logs (site_id, timestamp, ip_address, method, endpoint, status_code, response_time_ms, user_agent)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (site_id, timestamp, ip, method, endpoint, int(status), int(response_time), user_agent))
    conn.commit()

def check_new_files():
    objects = client.list_objects(BUCKET, recursive=True)
    for obj in objects:
        if obj.object_name in processed_files:
            continue
        site_id = obj.object_name.split("/")[0]
        response = client.get_object(BUCKET, obj.object_name)
        content = response.read().decode("utf-8")
        parse_and_insert(site_id, content)
        processed_files.add(obj.object_name)
        print(f"Processed {obj.object_name} -> site: {site_id}")

if _name_ == "_main_":
    print("Live processor started. Watching MinIO for new logs...")
    while True:
        check_new_files()
        time.sleep(5)