import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

# Load PCAP file
FILE_PATH ="2018-07-31-15-15-09-192.168.100.113.pcap" #"2018-07-31-15-15-09-192.168.100.113.pcap"
cap = pyshark.FileCapture(FILE_PATH)

# Lists to store detected anomalies
http_requests = []
dns_queries = Counter()
ssh_attempts = Counter()
timestamps = []

# Loop through packets
for packet in cap:
    try:
        # Detect HTTP Requests
        if "HTTP" in packet:
            method = getattr(packet.http, "request_method", "UNKNOWN")
            host = getattr(packet.http, "host", "UNKNOWN")
            user_agent = getattr(packet.http, "User-Agent", "UNKNOWN")
            http_requests.append({"Method": method, "Host": host, "User-Agent": user_agent})

        # Detect DNS Queries
        if "DNS" in packet:
            query_name = getattr(packet.dns, "qry_name", None)
            if query_name:
                dns_queries[query_name] += 1

        # Detect SSH Attempts
        if "SSH" in packet:
            src_ip = getattr(packet.ip, "src", None)
            if src_ip:
                ssh_attempts[src_ip] += 1

        # Record Timestamp for Traffic Analysis
        timestamps.append(float(packet.sniff_timestamp))

    except AttributeError:
        continue

cap.close()  # Close the capture file

# Convert lists to DataFrame
df_http = pd.DataFrame(http_requests)
df_dns = pd.DataFrame(dns_queries.items(), columns=["Domain", "Count"])
df_ssh = pd.DataFrame(ssh_attempts.items(), columns=["IP", "Attempts"])

# Export to CSV & JSON
df_http.to_csv("http_requests.csv", index=False)
df_http.to_json("http_requests.json", orient="records")

df_dns.to_csv("dns_queries.csv", index=False)
df_dns.to_json("dns_queries.json", orient="records")

df_ssh.to_csv("ssh_attempts.csv", index=False)
df_ssh.to_json("ssh_attempts.json", orient="records")

# Convert timestamps to DataFrame for traffic analysis
df_traffic = pd.DataFrame(timestamps, columns=["Timestamp"])
df_traffic["Time"] = pd.to_datetime(df_traffic["Timestamp"], unit="s")
df_traffic.set_index("Time", inplace=True)
df_traffic = df_traffic.resample("1S").count()

# 📊 Visualization with Matplotlib & Seaborn
sns.set_theme(style="darkgrid")

# Traffic Volume Over Time
plt.figure(figsize=(12, 5))
sns.lineplot(data=df_traffic, x=df_traffic.index, y="Timestamp", color="blue")
plt.title("Network Traffic Volume Over Time")
plt.xlabel("Time")
plt.ylabel("Packets per Second")
plt.xticks(rotation=45)
plt.grid()
plt.show()

# Top DNS Queries
plt.figure(figsize=(12, 5))
sns.barplot(data=df_dns.nlargest(10, "Count"), x="Domain", y="Count", palette="viridis")
plt.title("Top 10 Queried Domains")
plt.xticks(rotation=45)
plt.xlabel("Domain")
plt.ylabel("Query Count")
plt.show()

# SSH Attackers
plt.figure(figsize=(12, 5))
sns.barplot(data=df_ssh.nlargest(10, "Attempts"), x="IP", y="Attempts", palette="magma")
plt.title("Top 10 SSH Attack Sources")
plt.xticks(rotation=45)
plt.xlabel("IP Address")
plt.ylabel("Failed Login Attempts")
plt.show()

print("✅ Analysis Complete! Results saved as CSV & JSON.")
