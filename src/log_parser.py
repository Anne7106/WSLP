import csv

input_file = "data/server.log"
output_file = "output/processed_logs.csv"

with open(input_file, "r") as file:
    lines = file.readlines()

with open(output_file, "w", newline="") as csvfile:

    writer = csv.writer(csvfile)

    writer.writerow([
        "IP",
        "Timestamp",
        "Method",
        "URL",
        "Status",
        "Response_Time"
    ])

    for line in lines:

        parts = line.strip().split()

        if len(parts) == 7:
            ip = parts[0]
            timestamp = parts[1] + " " + parts[2]
            method = parts[3]
            url = parts[4]
            status = parts[5]
            response_time = parts[6]

            writer.writerow([
                ip,
                timestamp,
                method,
                url,
                status,
                response_time
            ])

print("Logs processed successfully.")
print("Output saved to output/processed_logs.csv")