# Analyzing Packet Traces
## Overview
This is a python script that dissects TCP packets. It takes in a .pcap file as input and parses this file. 
## Libraries Needed
```
dpkt --> "pip install dpkt"
```
## How to Execute
```
Step 1: Open your favorite IDE (preferably PyCharm).
Step 2: Navigate to and execute the main class: analysis_pcap_tcp.py.
Step 3: When prompted, enter the name of the .pcap file you would like to analyze.
```
## Output
```
The number of TCP flows.
For each TCP flow: source port, source IP address, destination port, destination IP address, sender throughput.
For the first two transactions after each TCP connection is set up: values of the sequence number, ack number, and receive window size.  
The first 3 congestion window sizes of each TCP flow.
The number of times a retransmission occurred due to triple duplicate ack and the number of times a retransmission occurred due to timeout.
```
