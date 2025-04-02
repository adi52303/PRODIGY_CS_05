import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import argparse
import datetime

def log_packet(packet, log_file):
    with open(log_file, "a") as file:
        file.write(packet + "\n")

def packet_callback(packet, log_file):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        log_entry = f"[{datetime.datetime.now()}] Source IP: {ip_layer.src} -> Destination IP: {ip_layer.dst}"
        
        if packet.haslayer(TCP):
            log_entry += f" | Protocol: TCP | Src Port: {packet[TCP].sport} -> Dst Port: {packet[TCP].dport}"
        elif packet.haslayer(UDP):
            log_entry += f" | Protocol: UDP | Src Port: {packet[UDP].sport} -> Dst Port: {packet[UDP].dport}"
        
        log_entry += f" | Payload: {bytes(packet[IP].payload)}"
        print(log_entry)
        log_packet(log_entry, log_file)
        print("-" * 50)

def start_sniffing(interface, log_file, filter_protocol):
    print(f"Starting packet sniffing on {interface}...")
    scapy.sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, log_file), store=False, filter=filter_protocol)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Packet Sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("-o", "--output", default="packet_log.txt", help="Log file to save captured packets")
    parser.add_argument("-f", "--filter", default="", help="BPF filter (e.g., 'tcp', 'udp', 'port 80')")
    args = parser.parse_args()
    
    start_sniffing(args.interface, args.output, args.filter)
