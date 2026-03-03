from scapy.all import IP, TCP
from collections import defaultdict
import time
from config import *
from logger import log_alert

port_scan_tracker = defaultdict(set)
request_tracker = defaultdict(list)

def process_packet(packet, output_callback, alert_callback):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = time.time()

        output_callback(f"Packet: {src_ip} → Port {dst_port}\n")

        # Suspicious Port Detection
        if dst_port in suspicious_ports:
            alert = f"⚠ Suspicious port access from {src_ip}"
            alert_callback(alert + "\n")
            log_alert(alert)

        # Port Scan Detection
        port_scan_tracker[src_ip].add(dst_port)
        if len(port_scan_tracker[src_ip]) >= port_scan_threshold:
            alert = f"🚨 Port Scan detected from {src_ip}"
            alert_callback(alert + "\n")
            log_alert(alert)

        # Flood Detection
        request_tracker[src_ip].append(current_time)
        request_tracker[src_ip] = [
            t for t in request_tracker[src_ip]
            if current_time - t < time_window
        ]

        if len(request_tracker[src_ip]) >= flood_threshold:
            alert = f"🔥 Flood attack detected from {src_ip}"
            alert_callback(alert + "\n")
            log_alert(alert)