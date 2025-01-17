# Network Packet Analyzer

PROBLEM STATEMENT : Develop a packet sniffer tool that captures and analyzes network packets. 
Display relevant information such as source and destination IP addresses, 
protocols, and payload data. Ensure the ethical use of the tool for educational purposes.

Problem Statement Overview: A packet sniffer is a tool that captures and analyzes network packets transmitted over a network. It is typically used to inspect the data being transferred between devices, allowing users to examine packet details such as source and destination IP addresses, protocols, and the data payload. The primary use of a packet sniffer is for network diagnostics, security analysis, and educational purposes.

Ethical Considerations:

  Consent and Authorization: Always ensure that you have explicit consent to capture and analyze network traffic. Unauthorized monitoring of network traffic is illegal and unethical.
  Educational Use: This tool should only be used for educational purposes, network troubleshooting, or security analysis with permission from the network owner.

 How the Packet Sniffer Works:

 Capturing Network Packets:
 The packet sniffer listens to network interfaces (e.g., Ethernet or Wi-Fi) and captures packets that are transmitted over the network.
  These packets include all sorts of data exchanged between devices on the network, such as HTTP requests, DNS queries, file transfers, and more.

 Analyzing Packet Details:
 Once captured, each packet is analyzed to extract key information:
       
 Source IP Address: The IP address of the device sending the packet.
            
 Destination IP Address: The IP address of the device receiving the packet.
            
 Protocol: The protocol used in the packet (e.g., TCP, UDP, HTTP).
            
 Payload: The actual data transmitted within the packet (e.g., HTTP headers, text, or binary data).

 Displaying Captured Information:

 The tool displays the captured packet details, including:

 Timestamp of when the packet was captured.
 
 Source IP and Destination IP addresses.
 
 Protocol being used (e.g., TCP, UDP, ICMP).
 
 Payload Data (the actual content or message within the packet).

Saving and Exporting Data:

Captured packets can be saved to a log file for later analysis, or exported in a format like PCAP (Packet Capture) that can be analyzed using other tools like Wireshark.

Key Features:

Real-time Packet Capture: The tool listens to the network interface and captures packets in real-time.

Packet Details: Displays essential information like source and destination IP addresses, protocol, and payload.

Protocol Filtering: Allows filtering based on specific protocols (e.g., TCP, UDP, ICMP).

Payload Data Extraction: Extracts and displays the data within the packet to understand the content of the network communication.

Saving Data: Captured packets can be saved for further analysis or exported to file formats.
