import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime

def print_packet_info(packet):
    """Extracts and prints relevant information from the captured packet"""
    
    # If the packet has an IP layer, we process it
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Display basic packet information
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {get_protocol_name(protocol)}")

        # Display payload data (if available)
        if packet.haslayer(TCP):
            print("Protocol Detail: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print("Protocol Detail: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print("Protocol Detail: ICMP")
            print(f"Type: {packet[ICMP].type}")
            print(f"Code: {packet[ICMP].code}")
        
        # Print payload data if available
        if packet.haslayer(scapy.Raw):
            print(f"Payload Data: {packet[scapy.Raw].load}")
        
        print("-" * 50)

def get_protocol_name(proto_number):
    """Returns the name of the protocol based on its number"""
    if proto_number == 1:
        return "ICMP"
    elif proto_number == 6:
        return "TCP"
    elif proto_number == 17:
        return "UDP"
    else:
        return f"Unknown (Protocol Number: {proto_number})"

def start_sniffing(interface=None):
    """Starts sniffing packets on the network interface"""
    print(f"Starting packet capture on interface: {interface or 'Default'}")
    scapy.sniff(iface=interface, prn=print_packet_info, store=False)

if __name__ == "__main__":
    interface = input("Enter network interface to sniff on (leave empty for default): ").strip() or None
    start_sniffing(interface)
