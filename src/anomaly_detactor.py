import csv

input_file = "output/processed_logs.csv"
output_file = "output/anomaly_report.csv"

with open(input_file, "r") as file:
    reader = csv.DictReader(file)

    anomalies = []

    for row in reader:

        status = int(row["Status"])
        response_time = int(row["Response_Time"])

        reason = ""

        if status == 500:
            reason = "Server Error"

        elif status == 404:
            reason = "Page Not Found"

        elif response_time > 800:
            reason = "High Response Time"

        if reason:
            anomalies.append([
                row["IP"],
                row["Timestamp"],
                row["Method"],
                row["URL"],
                row["Status"],
                row["Response_Time"],
                reason
            ])

with open(output_file, "w", newline="") as file:

    writer = csv.writer(file)

    writer.writerow([
        "IP",
        "Timestamp",
        "Method",
        "URL",
        "Status",
        "Response_Time",
        "Reason"
    ])

    writer.writerows(anomalies)

print("===== ANOMALY DETECTION =====")
print("Total anomalies detected:", len(anomalies))
print("Anomaly report saved to output/anomaly_report.csv")