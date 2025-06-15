✅ Packet Sniffer Tool in Python (Task 5 - Prodigy InfoTech)
🔧 Requirements:
scapy library
Install via pip if not already:

bash
pip install scapy

🧠 Python Code:
from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    print("\n=== New Packet Captured ===")

    # Extract IP information
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

    # TCP or UDP layer
    if TCP in packet:
        tcp_layer = packet[TCP]
        print(f"Source Port: {tcp_layer.sport}")
        print(f"Destination Port: {tcp_layer.dport}")
    elif UDP in packet:
        udp_layer = packet[UDP]
        print(f"Source Port: {udp_layer.sport}")
        print(f"Destination Port: {udp_layer.dport}")

    # Display raw payload (if available)
    if Raw in packet:
        payload = packet[Raw].load
        try:
            print(f"Payload: {payload.decode('utf-8', errors='replace')}")
        except:
            print("Payload: <Binary Data>")

# Start sniffing (You may need root/admin privileges)
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=process_packet, count=10)  # Captures 10 packets for demo
⚠️ Ethical & Legal Disclaimer:
This tool should only be used on networks you own or have explicit permission to analyze. Unauthorized packet sniffing can be illegal and unethical.
