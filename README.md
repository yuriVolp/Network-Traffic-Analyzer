# Network Traffic Analyzer

This is a Python program for network traffic analysis using the Scapy library. It provides functionalities to monitor real-time network traffic, detect potential DDoS attacks and port scans, as well as scan ports on a given host.

## Requirements

- Python 3.x
- Scapy

## Installation

1. Clone this repository to your local system:

    ```
    git clone https://github.com/your-username/network-traffic-analyzer.git
    ```

2. Ensure you have Python 3.x installed on your system. If not installed, you can download it from [python.org](https://www.python.org/).

3. Install the Scapy library by running the following command:

    ```
    pip install scapy
    ```

## Usage

You can run the program using the following command:
python analyzer.py [-h] [-i INTERFACE] [-c COUNT] [-f FILE] [-F FILTER] [-o OUTPUT] [-v] [-t TARGET]

### Arguments:

- `-i INTERFACE, --interface INTERFACE`: Specifies the network interface to capture packets from (default: eth0).
- `-c COUNT, --count COUNT`: Number of packets to capture.
- `-f FILE, --file FILE`: PCAP file to analyze.
- `-F FILTER, --filter FILTER`: BPF filter to apply (e.g., 'tcp', 'udp').
- `-o OUTPUT, --output OUTPUT`: Output file to save the results.
- `-v, --verbose`: Enable detailed analysis.
- `-t TARGET, --target TARGET`: Target IP address to scan ports.

## Features

- **Real-time Monitoring**: The program monitors real-time network traffic and displays information about the captured packets, including protocols, source and destination ports, and IP addresses.
- **DDoS Attack Detection**: It detects potential Denial of Service (DDoS) attacks by monitoring the rate of incoming packets.
- **Port Scanning**: The program can scan ports on a specific host to check which ports are open.
- **Detailed Analysis**: The verbose option allows for more detailed analysis of the captured packets.

## Usage Examples

1. Monitor real-time network traffic:

    ```
    python analyzer.py
    ```

2. Monitor real-time network traffic and save results to a file:

    ```
    python analyzer.py -o output.txt
    ```

3. Analyze a PCAP file:

    ```
    python analyzer.py -f file.txt
    ```

4. Scan ports on a specific host:

    ```
    python analyzer.py -t 192.168.1.100
    ```


