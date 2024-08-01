import logging
import sys
from scapy.all import sniff, IP, TCP, UDP, Raw
import argparse
from datetime import datetime

# Generate the log filename with the current date
log_filename = f"packetcapture_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"

# Configure logging
logging.basicConfig(filename=log_filename, level=logging.INFO, 
                    format='%(asctime)s - %(message)s', datefmt='%d/%b/%Y %H:%M:%S')

def packet_handler(packet):
    try:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            packet_len = len(packet)
            now_time = datetime.now().strftime('%d/%b/%Y %H:%M:%S')

            if proto == 6:  # TCP
                if TCP in packet:
                    tcp_sport = packet[TCP].sport
                    tcp_dport = packet[TCP].dport
                    if Raw in packet:
                        payload = packet[Raw].load
                        payload_content = payload.decode(errors='ignore')
                    else:
                        payload_content = None

                    status = "200" if payload_content else "404"
                    request_line = f"{ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}"
                    log_msg = f"{ip_src} - - [{now_time}] \"{request_line}\" {status} -"

                    print(log_msg)
                    logging.info(log_msg)
            
            elif proto == 17:  # UDP
                if UDP in packet:
                    udp_sport = packet[UDP].sport
                    udp_dport = packet[UDP].dport
                    request_line = f"{ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}"
                    log_msg = f"{ip_src} - - [{now_time}] \"{request_line}\" 200 -"

                    print(log_msg)
                    logging.info(log_msg)
            
            else:
                request_line = f"{ip_src} -> {ip_dst} (Protocol: {proto})"
                log_msg = f"{ip_src} - - [{now_time}] \"{request_line}\" 200 -"

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
