
import random
import time
import os
from datetime import datetime

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

# Create the data folder if it doesn't exist
os.makedirs("data", exist_ok=True)

# Open the log file in append mode
with open("data/server.log", "a") as file:

    print("Automatic log generator started.")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:

            ip = random.choice(ips)
            url = random.choice(urls)
            method = random.choice(methods)
            status = random.choice(statuses)
            response_time = random.randint(50, 1000)

            timestamp = datetime.now()

            log = (
                f"{ip} "
                f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} "
                f"{method} {url} {status} {response_time}\n"
            )

            # Write the new log
            file.write(log)

            # Make the log immediately available to other programs
            file.flush()

            print(log.strip())

            # Wait 2 seconds before generating another log
            time.sleep(2)

    except KeyboardInterrupt:
        print("\nLog generator stopped.")
