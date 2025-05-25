import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

# Define the two PCAP files
FILE_1 = "2018-07-31-15-15-09-192.168.100.113.pcap" #Original PCAP file
FILE_2 = "01-03-2025-01-25-192.168.100.23.pcap"  # Custom PCAP

def analyze_pcap(file_path):
    cap = pyshark.FileCapture(file_path)

    http_requests = []
    dns_queries = Counter()
    ssh_attempts = Counter()
    timestamps = []

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

    cap.close()

    # Convert to DataFrame
    df_http = pd.DataFrame(http_requests)
    df_dns = pd.DataFrame(dns_queries.items(), columns=["Domain", "Count"])
    df_ssh = pd.DataFrame(ssh_attempts.items(), columns=["IP", "Attempts"])
    df_traffic = pd.DataFrame(timestamps, columns=["Timestamp"])
    df_traffic["Time"] = pd.to_datetime(df_traffic["Timestamp"], unit="s")
    df_traffic.set_index("Time", inplace=True)
    df_traffic = df_traffic.resample("1S").count()

    return df_http, df_dns, df_ssh, df_traffic

# Analyze both PCAP files
df_http_1, df_dns_1, df_ssh_1, df_traffic_1 = analyze_pcap(FILE_1)
df_http_2, df_dns_2, df_ssh_2, df_traffic_2 = analyze_pcap(FILE_2)

# Compare DNS Queries
dns_diff = pd.merge(df_dns_1, df_dns_2, on="Domain", how="outer", suffixes=("_old", "_new")).fillna(0).infer_objects(copy=False)
dns_diff["Change"] = dns_diff["Count_new"] - dns_diff["Count_old"]
dns_diff = dns_diff.sort_values(by="Change", ascending=False)

# Compare SSH Attempts
ssh_diff = pd.merge(df_ssh_1, df_ssh_2, on="IP", how="outer", suffixes=("_old", "_new")).fillna(0).infer_objects(copy=False)
ssh_diff["Change"] = ssh_diff["Attempts_new"] - ssh_diff["Attempts_old"]
ssh_diff = ssh_diff.sort_values(by="Change", ascending=False)

# Compare Traffic Volume
traffic_combined = pd.concat([df_traffic_1.rename(columns={"Timestamp": "Old Traffic"}), 
                              df_traffic_2.rename(columns={"Timestamp": "New Traffic"})], axis=1).fillna(0)

# Save results to CSV
dns_diff.to_csv("dns_comparison.csv", index=False)
ssh_diff.to_csv("ssh_comparison.csv", index=False)
traffic_combined.to_csv("traffic_comparison.csv")

# Visualization
sns.set_theme(style="darkgrid")

# DNS Query Differences
plt.figure(figsize=(12, 5))
sns.barplot(data=dns_diff.nlargest(10, "Change"), x="Domain", y="Change", palette="coolwarm", legend=False)
plt.title("Top 10 DNS Query Changes")
plt.xticks(rotation=45)
plt.xlabel("Domain")
plt.ylabel("Change in Queries")
plt.show()

# SSH Attack Differences
plt.figure(figsize=(12, 5))
sns.barplot(data=ssh_diff.nlargest(10, "Change"), x="IP", y="Change", palette="magma", legend=False)
plt.title("Top 10 SSH Attack Source Changes")
plt.xticks(rotation=45)
plt.xlabel("IP Address")
plt.ylabel("Change in Attempts")
plt.show()

# Traffic Volume Over Time
plt.figure(figsize=(12, 5))
plt.plot(traffic_combined.index, traffic_combined["Old Traffic"], label="Old PCAP", color="blue")
plt.plot(traffic_combined.index, traffic_combined["New Traffic"], label="New PCAP", color="red")
plt.title("Traffic Volume Over Time (Old vs New PCAP)")
plt.xlabel("Time")
plt.ylabel("Packets per Second")
plt.legend()
plt.xticks(rotation=45)
plt.grid()
plt.show()

print("Comparison Complete! Results saved to CSV files.")
