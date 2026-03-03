import threading
import time
import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP
import tkinter as tk
from tkinter import scrolledtext

# ----------------------------
# Configuration
# ----------------------------

suspicious_ports = [21, 22, 23, 445]
port_scan_threshold = 4
flood_threshold = 20
time_window = 5

port_scan_tracker = defaultdict(set)
request_tracker = defaultdict(list)

sniffing = False

# ----------------------------
# Logging
# ----------------------------

def log_alert(message):
    with open("alerts.log", "a") as file:
        timestamp = datetime.datetime.now()
        file.write(f"[{timestamp}] {message}\n")

# ----------------------------
# Packet Processing
# ----------------------------

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = time.time()

        output_text.insert(tk.END, f"Packet: {src_ip} → Port {dst_port}\n")
        output_text.see(tk.END)

        # Suspicious Port
        if dst_port in suspicious_ports:
            alert = f"⚠ Suspicious port access from {src_ip}\n"
            alert_text.insert(tk.END, alert)
            alert_text.see(tk.END)
            log_alert(alert)

        # Port Scan Detection
        port_scan_tracker[src_ip].add(dst_port)
        if len(port_scan_tracker[src_ip]) >= port_scan_threshold:
            alert = f"🚨 Port Scan detected from {src_ip}\n"
            alert_text.insert(tk.END, alert)
            alert_text.see(tk.END)
            log_alert(alert)

        # Flood Detection
        request_tracker[src_ip].append(current_time)
        request_tracker[src_ip] = [
            t for t in request_tracker[src_ip]
            if current_time - t < time_window
        ]

        if len(request_tracker[src_ip]) >= flood_threshold:
            alert = f"🔥 Flood attack detected from {src_ip}\n"
            alert_text.insert(tk.END, alert)
            alert_text.see(tk.END)
            log_alert(alert)

# ----------------------------
# Sniffing Thread
# ----------------------------

def start_sniffing():
    global sniffing
    sniffing = True
    sniff(prn=packet_callback, store=False)

def run_sniffer():
    thread = threading.Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()

# ----------------------------
# GUI Setup
# ----------------------------

root = tk.Tk()
root.title("🛡 Python Intrusion Detection System")
root.geometry("800x600")

# Packet Display
tk.Label(root, text="Live Network Traffic", font=("Arial", 14)).pack()
output_text = scrolledtext.ScrolledText(root, height=15)
output_text.pack(fill=tk.BOTH, padx=10, pady=5)

# Alert Display
tk.Label(root, text="Security Alerts", font=("Arial", 14), fg="red").pack()
alert_text = scrolledtext.ScrolledText(root, height=10)
alert_text.pack(fill=tk.BOTH, padx=10, pady=5)

# Start Button
start_button = tk.Button(root, text="Start IDS", command=run_sniffer, bg="green", fg="white")
start_button.pack(pady=10)

root.mainloop()