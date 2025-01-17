# Network Packet Analyzer

PROBLEM STATEMENT : Develop a packet sniffer tool that captures and analyzes network packets. 
Display relevant information such as source and destination IP addresses, 
protocols, and payload data. Ensure the ethical use of the tool for educational purposes.

VIDEO LINK => https://imagekit.io/tools/asset-public-link?detail=%7B%22name%22%3A%22npa.py%20-%20task5%20-%20Visual%20Studio%20Code%202025-01-10%2000-56-39.mp4%22%2C%22type%22%3A%22video%2Fmp4%22%2C%22signedurl_expire%22%3A%222028-01-09T19%3A54%3A46.954Z%22%2C%22signedUrl%22%3A%22https%3A%2F%2Fmedia-hosting.imagekit.io%2F%2Fb5bd1b9f5d174340%2Fnpa.py%2520-%2520task5%2520-%2520Visual%2520Studio%2520Code%25202025-01-10%252000-56-39.mp4%3FExpires%3D1831060487%26Key-Pair-Id%3DK2ZIVPTIP2VGHC%26Signature%3DxksL96mHnXjatSe~l-eg0sys4vNILr2ki8khFUn4cMfCuYPHIrhqXF~xEJ1T8DzBBT4BmPz1PSk33WmKjGlSrSGPr2CWwEl-jsoFh606WoA9e7HGYYELdo~6PlsAeVDhps~5KRnKBseGPz7r5972JFggIwesRxPnjozKbFirLeWZ6ojg9N0wH8p5vpNgMe6dYePvqMBAqE4mRxVjVq1IWGgRyw~u7lQhsIXjrRNba-TOBlmwuzv7V01IB~zv08jlbrI57~c9XkbgojLkq2qyb7CdPsUIdMcTSYqdMo7XvT8n6BvFTzpY5ZNOBwkvcSPUpuNAo5YKxBvwAHtd9ah4Aw__%22%7D

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
