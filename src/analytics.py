import csv
from collections import Counter

input_file = "output/processed_logs.csv"

status_count = Counter()
url_count = Counter()
ip_count = Counter()

total_response_time = 0
total_requests = 0

with open(input_file, "r") as file:

    reader = csv.DictReader(file)

    for row in reader:

        status_count[row["Status"]] += 1
        url_count[row["URL"]] += 1
        ip_count[row["IP"]] += 1

        total_response_time += int(row["Response_Time"])
        total_requests += 1

print("===== WEB SERVER LOG ANALYTICS =====")

print("\nTotal Requests:", total_requests)

if total_requests > 0:
    average = total_response_time / total_requests
    print("Average Response Time:", round(average, 2), "ms")

print("\nHTTP Status Counts:")
for status, count in status_count.items():
    print(status, ":", count)

print("\nMost Requested URLs:")
for url, count in url_count.most_common():
    print(url, ":", count)

print("\nRequests by IP:")
for ip, count in ip_count.most_common():
    print(ip, ":", count)