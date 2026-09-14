import random
from datetime import datetime, timedelta

ips = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "10.0.0.5",
    "172.16.0.8"
]

urls = [
    "/",
    "/home",
    "/login",
    "/products",
    "/about",
    "/contact"
]

methods = ["GET", "POST"]
statuses = [200, 200, 200, 201, 404, 500]

start_time = datetime.now() - timedelta(hours=1)

with open("data/server.log", "w") as file:

    for i in range(100):
        ip = random.choice(ips)
        url = random.choice(urls)
        method = random.choice(methods)
        status = random.choice(statuses)
        response_time = random.randint(50, 1000)

        timestamp = start_time + timedelta(seconds=i * 30)

        log = f"{ip} {timestamp.strftime('%Y-%m-%d %H:%M:%S')} {method} {url} {status} {response_time}\n"

        file.write(log)

print("server.log generated successfully.")