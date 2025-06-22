# 🐍 Python Packet Sniffer

A flexible and user-friendly packet sniffer built in Python. This tool allows you to **capture live packets** on any available network interface or **analyze packets from a PCAP file** with powerful filtering options.

## ✨ Features

- 📡 **Live Packet Capture**
  - Select any available network interface
  - Set the number of packets to capture
  - Apply filters to focus on specific traffic
  - Display a summary of each captured packet

- 📁 **Read from PCAP File**
  - Load `.pcap` files for offline analysis
  - Apply advanced filters to narrow down results

## 🔍 Filtering Options

Filters can be applied during live capture or while reading a PCAP file. The supported filter options include:

- **Protocol**: `TCP` or `UDP`
- **Ports**:
  - Source Port (`sport`)
  - Destination Port (`dport`)
- **IP Addresses**:
  - Source IP (`srcIP`)
  - Destination IP (`dstIP`)

## 📦 Use Cases

- Network traffic analysis
- Packet inspection for security testing
- Learning and teaching network protocols

## 🚀 Getting Started

Make sure you have the required libraries installed (e.g., `scapy`) and run the script. Follow the prompts to select interface, set capture count, apply filters, or read from a PCAP file.

---

*Built for learning, analysis, and exploration of network traffic in real-time or from saved captures.*
