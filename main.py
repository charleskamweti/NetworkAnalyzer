import pyshark
import matplotlib.pyplot as plt
from collections import Counter

# Load the capture file
capture = pyshark.FileCapture('path/to/capture.pcap')

# Data storage
packet_sizes = []
src_ip_counts = Counter()
anomalous_packets = []

# Thresholds
LARGE_PACKET_THRESHOLD = 1500
HIGH_TRAFFIC_THRESHOLD = 50  # Customize as needed

# Analyze packets
for packet in capture:
    try:
        if 'IP' in packet:
            src_ip = packet.ip.src
            packet_length = int(packet.length)

            # Store data
            packet_sizes.append(packet_length)
            src_ip_counts[src_ip] += 1

            # Mark anomalies
            if packet_length > LARGE_PACKET_THRESHOLD:
                anomalous_packets.append(packet_length)

    except AttributeError:
        continue

# Close capture to free resources
capture.close()

# Plot 1: Packet Size Distribution with Anomalies
plt.figure(figsize=(10, 5))

# Normal packet sizes
plt.hist(packet_sizes, bins=30, color='blue', alpha=0.7, edgecolor='black', label="Normal Packets")

# Highlight large packets
if anomalous_packets:
    plt.hist(anomalous_packets, bins=10, color='red', alpha=0.7, edgecolor='black', label="Large Packets (>1500 bytes)")

plt.xlabel('Packet Size (Bytes)')
plt.ylabel('Frequency')
plt.title('Packet Size Distribution')
plt.legend()
plt.grid(True)
plt.show()

# Plot 2: Top 10 Source IPs (Highlight Anomalies)
top_ips = src_ip_counts.most_common(10)
ip_labels, ip_counts = zip(*top_ips)

# Color-code high-traffic IPs
bar_colors = ['red' if count > HIGH_TRAFFIC_THRESHOLD else 'blue' for count in ip_counts]

plt.figure(figsize=(10, 5))
plt.bar(ip_labels, ip_counts, color=bar_colors, alpha=0.7)
plt.xlabel('Source IP')
plt.ylabel('Packet Count')
plt.title('Top 10 Source IPs (High Traffic Marked in Red)')
plt.xticks(rotation=45)
plt.grid(axis='y')

# Show anomaly labels
for i, count in enumerate(ip_counts):
    if count > HIGH_TRAFFIC_THRESHOLD:
        plt.text(i, count + 2, '⚠ High Traffic', ha='center', fontsize=10, color='orange')

plt.show()