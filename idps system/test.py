from scapy.all import sniff, TCP, Raw, IP

def packet_callback(packet):
    if packet.haslayer(TCP):
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            payload_content = payload.decode(errors='ignore')
        else:
            payload_content = None

        print(f"Source Port: {tcp_sport}, Destination Port: {tcp_dport}, Payload: {payload_content}")
    else:
        print("Non-TCP packet received")

# Start sniffing with a broad filter
print("Starting packet capture. Make sure to start the server and client now.")
sniff(prn=packet_callback, store=0)
