import logging
import sys
from scapy.all import sniff, IP, TCP, UDP
import argparse
from datetime import datetime

# Generate the log filename with the current date
log_filename = f"packetcapture_{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.log"

# Configure logging
logging.basicConfig(filename=log_filename, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def packet_handler(packet):
    print("Packet received")  # Debugging statement
    try:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            now_time = datetime.now().replace(microsecond=0)
            
            if proto == 6:  # TCP
                if TCP in packet:
                    tcp_sport = packet[TCP].sport
                    tcp_dport = packet[TCP].dport
                    log_msg = f"TCP Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport} :{now_time}"
                    print(log_msg)
                    logging.info(log_msg)
            
            elif proto == 17:  # UDP
                if UDP in packet:
                    udp_sport = packet[UDP].sport
                    udp_dport = packet[UDP].dport
                    log_msg = f"UDP Packet: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport} :{now_time}"
                    print(log_msg)
                    logging.info(log_msg)
            
            else:
                log_msg = f"Other IP Packet: {ip_src} -> {ip_dst} (Protocol: {proto}) :{now_time}"
                print(log_msg)
                logging.info(log_msg)
    except Exception as e:
        print(f"Error processing packet: {e}")
        logging.error(f"Error processing packet: {e}")

def start_packet_capture(interface, filter_exp):
    print(f"Starting packet capture on {interface} with filter '{filter_exp}'")
    logging.info(f"Starting packet capture on {interface} with filter '{filter_exp}'")
    try:
        sniff(iface=interface, filter=filter_exp, prn=packet_handler, store=False)
    except Exception as e:
        print(f"Error during packet capture: {e}")
        logging.error(f"Error during packet capture: {e}")

if __name__ == "__main__":
    print("Script started")
    logging.info("Script started")

    parser = argparse.ArgumentParser(description='Packet capture module for IDS')
    parser.add_argument('-i', '--interface', type=str, required=True, help='Network interface to capture packets from')
    parser.add_argument('-f', '--filter', type=str, default='', help='Filter expression for packet capture (e.g., "tcp", "udp")')
    
    try:
        args = parser.parse_args()
        print(f"Arguments parsed. Interface: {args.interface}, Filter: {args.filter}")
        logging.info(f"Arguments parsed. Interface: {args.interface}, Filter: {args.filter}")
    except Exception as e:
        print(f"Error parsing arguments: {e}")
        logging.error(f"Error parsing arguments: {e}")
        sys.exit(1)

    try:
        start_packet_capture(interface=args.interface, filter_exp=args.filter)
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user")
        logging.info("Packet capture stopped by user")
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")
