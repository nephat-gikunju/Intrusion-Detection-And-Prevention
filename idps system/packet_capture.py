import logging
import sys
from scapy.all import sniff, IP, TCP, UDP ,Raw
import argparse
from datetime import datetime

# Generate the log filename with the current date
log_filename = f"packetcapture_{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.log"

# Configure logging
logging.basicConfig(filename=log_filename, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def packet_handler(packet):
    #print("Packet received")  # Debugging statement
    try:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            now_time = datetime.now().replace(microsecond=0)
            packet_len = len(packet)            
 
        log_msg = f"{ip_src} -- [{now_time}] {ip_src} --> {ip_dst} (Protocol: {proto}) len={packet_len} "
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
