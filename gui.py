import tkinter as tk
from tkinter import scrolledtext
import threading
from scapy.all import sniff
from detector import process_packet


class IDS_GUI:

    def __init__(self, root):
        self.root = root
        self.root.title("Professional IDS")
        self.root.geometry("950x700")

        self.sniffing = False
        self.dark_mode = True

        # ----------- TITLE -----------
        self.title = tk.Label(root, font=("Consolas", 18, "bold"))
        self.title.pack(pady=10)

        # ----------- LIVE TRAFFIC -----------
        self.live_label = tk.Label(root, font=("Consolas", 14))
        self.live_label.pack()

        self.output_text = scrolledtext.ScrolledText(root, height=15)
        self.output_text.pack(fill=tk.BOTH, padx=15, pady=5)

        # ----------- ALERTS -----------
        self.alert_label = tk.Label(root, font=("Consolas", 14))
        self.alert_label.pack()

        self.alert_text = scrolledtext.ScrolledText(root, height=10)
        self.alert_text.pack(fill=tk.BOTH, padx=15, pady=5)

        # ----------- BUTTON FRAME -----------
        self.button_frame = tk.Frame(root)
        self.button_frame.pack(pady=10)

        self.start_button = tk.Button(
            self.button_frame, text="Start IDS",
            command=self.start_sniffer, width=15
        )
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = tk.Button(
            self.button_frame, text="Stop IDS",
            command=self.stop_sniffer, width=15
        )
        self.stop_button.grid(row=0, column=1, padx=5)

        self.clear_traffic_button = tk.Button(
            self.button_frame, text="Clear Traffic",
            command=self.clear_traffic, width=15
        )
        self.clear_traffic_button.grid(row=0, column=2, padx=5)

        self.clear_alert_button = tk.Button(
            self.button_frame, text="Clear Alerts",
            command=self.clear_alerts, width=15
        )
        self.clear_alert_button.grid(row=0, column=3, padx=5)

        self.theme_button = tk.Button(
            self.button_frame, text="Toggle Theme",
            command=self.toggle_theme, width=15
        )
        self.theme_button.grid(row=0, column=4, padx=5)

        self.apply_theme()

    # ----------- THEME FUNCTION -----------

    def apply_theme(self):
        if self.dark_mode:
            bg = "#1e1e1e"
            fg = "white"
            traffic_bg = "black"
            traffic_fg = "#00ff00"
            alert_fg = "red"
        else:
            bg = "white"
            fg = "black"
            traffic_bg = "white"
            traffic_fg = "black"
            alert_fg = "red"

        self.root.configure(bg=bg)
        self.button_frame.configure(bg=bg)

        self.title.config(text="Intrusion Detection System", bg=bg, fg=traffic_fg)
        self.live_label.config(text="Live Traffic", bg=bg, fg=fg)
        self.alert_label.config(text="Security Alerts", bg=bg, fg=alert_fg)

        self.output_text.config(bg=traffic_bg, fg=traffic_fg, insertbackground=fg)
        self.alert_text.config(bg=traffic_bg, fg=alert_fg, insertbackground=fg)

        for widget in self.button_frame.winfo_children():
            widget.config(bg="#007acc" if self.dark_mode else "#dddddd",
                          fg="white" if self.dark_mode else "black")

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.apply_theme()

    # ----------- DISPLAY FUNCTIONS -----------

    def display_output(self, message):
        self.output_text.insert(tk.END, message)
        self.output_text.see(tk.END)

    def display_alert(self, message):
        self.alert_text.insert(tk.END, message)
        self.alert_text.see(tk.END)

    # ----------- CLEAR FUNCTIONS -----------

    def clear_traffic(self):
        self.output_text.delete(1.0, tk.END)

    def clear_alerts(self):
        self.alert_text.delete(1.0, tk.END)

    # ----------- SNIFF CONTROL -----------

    def start_sniffer(self):
        if not self.sniffing:
            self.sniffing = True
            thread = threading.Thread(target=self.run_sniff)
            thread.daemon = True
            thread.start()

    def run_sniff(self):
        sniff(
            prn=lambda pkt: process_packet(
                pkt,
                self.display_output,
                self.display_alert
            ),
            stop_filter=lambda x: not self.sniffing,
            store=False
        )

    def stop_sniffer(self):
        self.sniffing = False