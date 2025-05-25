# NetworkAnalyzer

**NetworkAnalyzer** is a Python-based tool for analyzing `.pcap` files to detect anomalies such as large packets and high-traffic IPs. It visualizes packet size distributions and highlights suspicious activity using simple plots.

## Requirements

Install the required packages using pip:

pip install pyshark matplotlib

Ensure that Wireshark and TShark are installed and available in your system PATH.

## Usage

Replace the path in main.py or Analyze.py with the path to your .pcap file:
capture = pyshark.FileCapture('path/to/capture.pcap')

## Run the script

python main.py

Two plots will be displayed:

- Packet Size Distribution, highlighting large packets.
- Top 10 Source IPs, with high-traffic IPs in red.

## Features

- Extracts packet sizes and source IP addresses from .pcap files.
- Highlights large packets (>1500 bytes) and IPs with excessive traffic.

## Visualizations using Matplotlib.

- CSV files for DNS, SSH, and traffic comparisons are included.

## Anomaly Detection Logic

- Large Packet Threshold: Packets over 1500 bytes are flagged.
- High Traffic IP: IPs sending more than 50 packets are highlighted.

LARGE_PACKET_THRESHOLD = 1500
HIGH_TRAFFIC_THRESHOLD = 50

## Sample Output

Packet size histogram with red bars for large packets.

Bar chart of top IPs with red bars for high traffic.

## Sample PCAPs

Sample .pcap files are included for testing:
01-03-2025-01-25-192.168.100.23.pcap
2018-07-31-15-15-09-192.168.100.113.pcap

## License

MIT License

## Author

Created by charleskamweti