#!/usr/bin/env python3
import sys
import socket
import threading
import time
import subprocess
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import psutil
import nmap
import dpkt
from collections import defaultdict
import platform
import netifaces
import json
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
import numpy as np
import random
import queue

# Constants
VERSION = "1.0.0"
CONFIG_FILE = "cyber_monitor_config.json"
THREAT_DB = "threat_signatures.json"
MAX_LOG_LINES = 1000
UPDATE_INTERVAL = 2  # seconds

# Threat detection thresholds
DOS_THRESHOLD = 100  # packets per second
PORT_SCAN_THRESHOLD = 50  # ports per minute
SYN_FLOOD_THRESHOLD = 200  # SYN packets per minute

class ThreatDetector:
    def __init__(self):
        self.packet_counts = defaultdict(int)
        self.port_scan_counts = defaultdict(int)
        self.syn_counts = defaultdict(int)
        self.icmp_counts = defaultdict(int)
        self.udp_flood_counts = defaultdict(int)
        self.threat_log = []
        self.load_threat_signatures()
        
    def load_threat_signatures(self):
        try:
            with open(THREAT_DB, 'r') as f:
                self.threat_signatures = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.threat_signatures = {
                "dos_ips": [],
                "port_scanners": [],
                "known_malicious": []
            }
    
    def save_threat_signatures(self):
        with open(THREAT_DB, 'w') as f:
            json.dump(self.threat_signatures, f, indent=4)
    
    def analyze_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Count packets per source IP
            self.packet_counts[src_ip] += 1
            
            # Check for known malicious IPs
            if src_ip in self.threat_signatures["known_malicious"]:
                self.log_threat(f"Known malicious IP detected: {src_ip}", "High")
            
            # Check for DOS attacks
            if self.packet_counts[src_ip] > DOS_THRESHOLD:
                if src_ip not in self.threat_signatures["dos_ips"]:
                    self.threat_signatures["dos_ips"].append(src_ip)
                self.log_threat(f"Possible DOS attack from {src_ip}", "High")
            
            # TCP specific checks
            if TCP in packet:
                dst_port = packet[TCP].dport
                
                # SYN flood detection
                if packet[TCP].flags == 'S':  # SYN flag
                    self.syn_counts[src_ip] += 1
                    if self.syn_counts[src_ip] > SYN_FLOOD_THRESHOLD:
                        self.log_threat(f"Possible SYN flood from {src_ip}", "High")
                
                # Port scan detection
                self.port_scan_counts[(src_ip, dst_port)] += 1
                if self.port_scan_counts[(src_ip, dst_port)] > PORT_SCAN_THRESHOLD:
                    if src_ip not in self.threat_signatures["port_scanners"]:
                        self.threat_signatures["port_scanners"].append(src_ip)
                    self.log_threat(f"Possible port scan from {src_ip} to port {dst_port}", "Medium")
            
            # ICMP specific checks
            elif ICMP in packet:
                self.icmp_counts[src_ip] += 1
                if self.icmp_counts[src_ip] > DOS_THRESHOLD/2:
                    self.log_threat(f"Possible ICMP flood (Ping of Death) from {src_ip}", "Medium")
            
            # UDP specific checks
            elif UDP in packet:
                self.udp_flood_counts[src_ip] += 1
                if self.udp_flood_counts[src_ip] > DOS_THRESHOLD:
                    self.log_threat(f"Possible UDP flood from {src_ip}", "High")
    
    def log_threat(self, message, severity):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{severity}] {message}"
        self.threat_log.append(log_entry)
        if len(self.threat_log) > MAX_LOG_LINES:
            self.threat_log.pop(0)
        self.save_threat_signatures()
        return log_entry

class NetworkMonitor:
    def __init__(self, detector):
        self.detector = detector
        self.is_monitoring = False
        self.sniffer_thread = None
        self.packet_queue = queue.Queue()
        self.stats = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "threats_detected": 0,
            "ports_scanned": 0,
            "dos_attempts": 0
        }
        self.interface = None
    
    def start_monitoring(self, interface=None, ip_address=None):
        if self.is_monitoring:
            return False
        
        self.interface = interface
        self.target_ip = ip_address
        self.is_monitoring = True
        
        # Start packet processing thread
        self.process_thread = threading.Thread(target=self.process_packets, daemon=True)
        self.process_thread.start()
        
        # Start sniffer in a separate thread
        self.sniffer_thread = threading.Thread(
            target=self.start_sniffing,
            daemon=True
        )
        self.sniffer_thread.start()
        return True
    
    def start_sniffing(self):
        filter_str = f"host {self.target_ip}" if self.target_ip else ""
        sniff(
            prn=lambda x: self.packet_queue.put(x),
            filter=filter_str,
            iface=self.interface,
            store=False
        )
    
    def process_packets(self):
        while self.is_monitoring:
            try:
                packet = self.packet_queue.get(timeout=1)
                self.analyze_packet(packet)
            except queue.Empty:
                continue
    
    def analyze_packet(self, packet):
        self.stats["total_packets"] += 1
        
        if IP in packet:
            if TCP in packet:
                self.stats["tcp_packets"] += 1
            elif UDP in packet:
                self.stats["udp_packets"] += 1
            elif ICMP in packet:
                self.stats["icmp_packets"] += 1
            
            # Detect threats
            threat_detected = self.detector.analyze_packet(packet)
            if threat_detected:
                self.stats["threats_detected"] += 1
    
    def stop_monitoring(self):
        self.is_monitoring = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1)
        if self.process_thread and self.process_thread.is_alive():
            self.process_thread.join(timeout=1)
        return True
    
    def get_stats(self):
        return self.stats.copy()

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Network Based Intrusion Detection System v{VERSION}")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Configuration
        self.config = self.load_config()
        self.dark_mode = self.config.get("dark_mode", False)
        self.recent_ips = self.config.get("recent_ips", [])
        
        # Threat detector and monitor
        self.detector = ThreatDetector()
        self.monitor = NetworkMonitor(self.detector)
        
        # Setup GUI
        self.setup_menu()
        self.setup_main_frame()
        self.setup_dashboard()
        self.setup_terminal()
        self.setup_status_bar()
        
        # Apply theme
        self.apply_theme()
        
        # Start stats update loop
        self.update_stats()
    
    def load_config(self):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump({
                "dark_mode": self.dark_mode,
                "recent_ips": self.recent_ips
            }, f, indent=4)
    
    def setup_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Monitoring Session", command=self.new_session)
        file_menu.add_command(label="Save Threat Log", command=self.save_threat_log)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Toggle Dark Mode", command=self.toggle_dark_mode)
        view_menu.add_command(label="Reset Dashboard", command=self.reset_dashboard)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Network Scanner", command=self.open_network_scanner)
        tools_menu.add_command(label="Vulnerability Scanner", command=self.open_vulnerability_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self.open_packet_analyzer)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def setup_main_frame(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create paned window for resizable sections
        self.paned_window = ttk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)
        
        # Left pane (dashboard)
        self.left_pane = ttk.Frame(self.paned_window, width=400)
        self.paned_window.add(self.left_pane, weight=1)
        
        # Right pane (terminal and logs)
        self.right_pane = ttk.Frame(self.paned_window)
        self.paned_window.add(self.right_pane, weight=1)
    
    def setup_dashboard(self):
        # Notebook for multiple dashboard tabs
        self.dashboard_notebook = ttk.Notebook(self.left_pane)
        self.dashboard_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Overview tab
        self.overview_tab = ttk.Frame(self.dashboard_notebook)
        self.dashboard_notebook.add(self.overview_tab, text="Overview")
        
        # Stats frame
        stats_frame = ttk.LabelFrame(self.overview_tab, text="Current Statistics")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.stats_labels = {}
        stats = [
            ("Total Packets", "total_packets"),
            ("TCP Packets", "tcp_packets"),
            ("UDP Packets", "udp_packets"),
            ("ICMP Packets", "icmp_packets"),
            ("Threats Detected", "threats_detected"),
            ("DOS Attempts", "dos_attempts"),
            ("Port Scans", "ports_scanned")
        ]
        
        for i, (label, key) in enumerate(stats):
            frame = ttk.Frame(stats_frame)
            frame.grid(row=i//2, column=i%2, sticky="ew", padx=5, pady=2)
            ttk.Label(frame, text=f"{label}:").pack(side=tk.LEFT)
            self.stats_labels[key] = ttk.Label(frame, text="0", width=10)
            self.stats_labels[key].pack(side=tk.RIGHT)
        
        # Monitoring controls
        control_frame = ttk.LabelFrame(self.overview_tab, text="Monitoring Controls")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5)
        self.ip_entry = ttk.Combobox(control_frame, values=self.recent_ips)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(control_frame, text="Interface:").grid(row=1, column=0, padx=5, pady=5)
        self.interface_var = tk.StringVar()
        interfaces = self.get_network_interfaces()
        self.interface_combobox = ttk.Combobox(
            control_frame, 
            textvariable=self.interface_var,
            values=interfaces,
            state="readonly"
        )
        if interfaces:
            self.interface_var.set(interfaces[0])
        self.interface_combobox.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        self.start_button = ttk.Button(
            control_frame, 
            text="Start Monitoring", 
            command=self.start_monitoring
        )
        self.start_button.grid(row=2, column=0, padx=5, pady=5, sticky="ew")
        
        self.stop_button = ttk.Button(
            control_frame, 
            text="Stop Monitoring", 
            command=self.stop_monitoring,
            state=tk.DISABLED
        )
        self.stop_button.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        
        # Charts frame
        charts_frame = ttk.Frame(self.overview_tab)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Packet type pie chart
        self.pie_frame = ttk.LabelFrame(charts_frame, text="Packet Types Distribution")
        self.pie_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.pie_fig, self.pie_ax = plt.subplots(figsize=(4, 3), dpi=80)
        self.pie_canvas = FigureCanvasTkAgg(self.pie_fig, master=self.pie_frame)
        self.pie_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Threats bar chart
        self.bar_frame = ttk.LabelFrame(charts_frame, text="Threats Detected")
        self.bar_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.bar_fig, self.bar_ax = plt.subplots(figsize=(4, 3), dpi=80)
        self.bar_canvas = FigureCanvasTkAgg(self.bar_fig, master=self.bar_frame)
        self.bar_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Threats tab
        self.threats_tab = ttk.Frame(self.dashboard_notebook)
        self.dashboard_notebook.add(self.threats_tab, text="Threat Log")
        
        self.threat_log = scrolledtext.ScrolledText(
            self.threats_tab,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.threat_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Update charts with initial data
        self.update_charts()
    
    def setup_terminal(self):
        terminal_frame = ttk.LabelFrame(self.right_pane, text="Command Terminal")
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Terminal output
        self.terminal_output = scrolledtext.ScrolledText(
            terminal_frame,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Command input
        input_frame = ttk.Frame(terminal_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Label(input_frame, text=">").pack(side=tk.LEFT)
        self.command_entry = ttk.Entry(input_frame)
        self.command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.command_entry.bind("<Return>", self.execute_command)
        
        # Add some help text
        self.print_to_terminal("Type 'help' for available commands\n")
    
    def setup_status_bar(self):
        self.status_bar = ttk.Frame(self.root, height=20)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = ttk.Label(
            self.status_bar, 
            text="Ready", 
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_label.pack(fill=tk.X)
        
        self.monitoring_status = ttk.Label(
            self.status_bar,
            text="Not Monitoring",
            relief=tk.SUNKEN,
            anchor=tk.W,
            width=20
        )
        self.monitoring_status.pack(side=tk.RIGHT, fill=tk.Y)
    
    def apply_theme(self):
        if self.dark_mode:
            self.root.tk_setPalette(
                background='#1e1e1e',
                foreground='#ffffff',
                activeBackground='#3e3e3e',
                activeForeground='#ffffff'
            )
            style = ttk.Style()
            style.theme_use('clam')
            style.configure('.', background='#1e1e1e', foreground='#ffffff')
            style.configure('TFrame', background='#1e1e1e')
            style.configure('TLabel', background='#1e1e1e', foreground='#ffffff')
            style.configure('TButton', background='#333333', foreground='#ffffff')
            style.configure('TEntry', fieldbackground='#333333', foreground='#ffffff')
            style.configure('TCombobox', fieldbackground='#333333', foreground='#ffffff')
            style.configure('TNotebook', background='#1e1e1e')
            style.configure('TNotebook.Tab', background='#333333', foreground='#ffffff')
            style.map('TButton',
                background=[('active', '#4e4e4e'), ('disabled', '#2e2e2e')],
                foreground=[('active', '#ffffff'), ('disabled', '#7f7f7f')]
            )
            
            # Configure text widgets
            self.terminal_output.config(
                bg='#1e1e1e',
                fg='#00ff00',
                insertbackground='#00ff00'
            )
            self.threat_log.config(
                bg='#1e1e1e',
                fg='#ffffff',
                insertbackground='#ffffff'
            )
            self.command_entry.config(
                style='Dark.TEntry'
            )
            
            # Configure matplotlib charts
            self.pie_ax.set_facecolor('#1e1e1e')
            self.pie_fig.patch.set_facecolor('#1e1e1e')
            self.pie_ax.tick_params(colors='white')
            self.pie_ax.title.set_color('white')
            
            self.bar_ax.set_facecolor('#1e1e1e')
            self.bar_fig.patch.set_facecolor('#1e1e1e')
            self.bar_ax.tick_params(colors='white')
            self.bar_ax.title.set_color('white')
        else:
            self.root.tk_setPalette(background='#f0f0f0')
            style = ttk.Style()
            style.theme_use('default')
            
            # Reset text widgets
            self.terminal_output.config(
                bg='black',
                fg='#00ff00',
                insertbackground='#00ff00'
            )
            self.threat_log.config(
                bg='white',
                fg='black',
                insertbackground='black'
            )
            
            # Reset matplotlib charts
            self.pie_ax.set_facecolor('white')
            self.pie_fig.patch.set_facecolor('white')
            self.pie_ax.tick_params(colors='black')
            self.pie_ax.title.set_color('black')
            
            self.bar_ax.set_facecolor('white')
            self.bar_fig.patch.set_facecolor('white')
            self.bar_ax.tick_params(colors='black')
            self.bar_ax.title.set_color('black')
        
        self.pie_canvas.draw()
        self.bar_canvas.draw()
    
    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        self.save_config()
        self.apply_theme()
    
    def get_network_interfaces(self):
        try:
            interfaces = netifaces.interfaces()
            return [iface for iface in interfaces if iface != 'lo']
        except:
            return []
    
    def start_monitoring(self):
        ip_address = self.ip_entry.get().strip()
        if not ip_address:
            messagebox.showerror("Error", "Please enter a target IP address")
            return
        
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface")
            return
        
        if ip_address not in self.recent_ips:
            self.recent_ips.append(ip_address)
            self.ip_entry['values'] = self.recent_ips
            self.save_config()
        
        if self.monitor.start_monitoring(interface, ip_address):
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.monitoring_status.config(text=f"Monitoring {ip_address}")
            self.print_to_terminal(f"Started monitoring {ip_address} on interface {interface}")
            self.update_status(f"Monitoring {ip_address}")
        else:
            messagebox.showerror("Error", "Monitoring is already in progress")
    
    def stop_monitoring(self):
        if self.monitor.stop_monitoring():
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.monitoring_status.config(text="Not Monitoring")
            self.print_to_terminal("Monitoring stopped")
            self.update_status("Ready")
    
    def update_stats(self):
        if self.monitor.is_monitoring:
            stats = self.monitor.get_stats()
            
            # Update stats labels
            for key, label in self.stats_labels.items():
                label.config(text=str(stats.get(key, 0)))
            
            # Update charts
            self.update_charts()
            
            # Update threat log
            self.update_threat_log()
        
        # Schedule next update
        self.root.after(UPDATE_INTERVAL * 1000, self.update_stats)
    
    def update_charts(self):
        stats = self.monitor.get_stats()
        
        # Update pie chart
        self.pie_ax.clear()
        if stats["total_packets"] > 0:
            labels = ['TCP', 'UDP', 'ICMP', 'Other']
            sizes = [
                stats["tcp_packets"],
                stats["udp_packets"],
                stats["icmp_packets"],
                max(0, stats["total_packets"] - stats["tcp_packets"] - stats["udp_packets"] - stats["icmp_packets"])
            ]
            self.pie_ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            self.pie_ax.axis('equal')
            self.pie_ax.set_title('Packet Types Distribution')
        
        # Update bar chart
        self.bar_ax.clear()
        if stats["threats_detected"] > 0:
            threats = ['DOS', 'Port Scans', 'SYN Flood', 'UDP Flood']
            counts = [
                stats.get("dos_attempts", 0),
                stats.get("ports_scanned", 0),
                stats.get("syn_floods", 0),
                stats.get("udp_floods", 0)
            ]
            self.bar_ax.bar(threats, counts)
            self.bar_ax.set_title('Detected Threats')
            self.bar_ax.set_ylabel('Count')
        
        self.pie_canvas.draw()
        self.bar_canvas.draw()
    
    def update_threat_log(self):
        if not self.detector.threat_log:
            return
        
        self.threat_log.config(state=tk.NORMAL)
        self.threat_log.delete(1.0, tk.END)
        
        for entry in self.detector.threat_log[-MAX_LOG_LINES:]:
            self.threat_log.insert(tk.END, entry + "\n")
        
        self.threat_log.config(state=tk.DISABLED)
        self.threat_log.see(tk.END)
    
    def print_to_terminal(self, text):
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, text + "\n")
        self.terminal_output.config(state=tk.DISABLED)
        self.terminal_output.see(tk.END)
    
    def update_status(self, message):
        self.status_label.config(text=message)
    
    def execute_command(self, event=None):
        command = self.command_entry.get().strip()
        self.command_entry.delete(0, tk.END)
        
        if not command:
            return
        
        self.print_to_terminal(f"> {command}")
        
        if command.lower() == "help":
            self.show_help()
        elif command.lower().startswith("start monitoring"):
            parts = command.split()
            if len(parts) >= 3:
                ip = parts[2]
                self.ip_entry.set(ip)
                self.start_monitoring()
            else:
                self.print_to_terminal("Usage: start monitoring <IP_ADDRESS>")
        elif command.lower() == "stop":
            self.stop_monitoring()
        elif command.lower() == "netstat":
            self.run_netstat()
        elif command.lower() == "net share":
            self.run_net_share()
        elif command.lower().startswith("ifconfig"):
            self.run_ifconfig("/all" in command)
        elif command.lower().startswith("nmap --script vuln"):
            target = command.split()[-1]
            self.run_nmap_vuln_scan(target)
        elif command.lower() == "msfconsole":
            self.print_to_terminal("Metasploit Framework is not integrated in this GUI version.")
        elif command.lower().startswith("nc -lvp 4444"):
            self.print_to_terminal("Netcat listener is not implemented in this GUI version.")
        elif command.lower().startswith("nc ") and "4444 -e cmd.exe" in command:
            self.print_to_terminal("Netcat reverse shell is not implemented in this GUI version.")
        elif command.lower().startswith("ping"):
            self.run_ping(command[4:].strip())
        else:
            self.print_to_terminal(f"Unknown command: {command}")
    
    def show_help(self):
        help_text = """
Available Commands:
  help                           - Show this help message
  start monitoring <IP_ADDRESS>  - Start monitoring a specific IP address
  stop                           - Stop monitoring
  netstat                        - Show network statistics
  net share                      - Show shared resources
  ifconfig [/all]                - Show network interface configuration
  nmap --script vuln <target>    - Scan for vulnerabilities on target system
  ping <IP_ADDRESS>              - Ping a network host
"""
        self.print_to_terminal(help_text)
    
    def run_netstat(self):
        try:
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                check=True
            )
            self.print_to_terminal(result.stdout)
        except subprocess.CalledProcessError as e:
            self.print_to_terminal(f"Error running netstat: {e.stderr}")
        except FileNotFoundError:
            self.print_to_terminal("netstat command not available on this system")
    
    def run_net_share(self):
        if platform.system() != "Windows":
            self.print_to_terminal("net share is only available on Windows")
            return
        
        try:
            result = subprocess.run(
                ["net", "share"],
                capture_output=True,
                text=True,
                check=True
            )
            self.print_to_terminal(result.stdout)
        except subprocess.CalledProcessError as e:
            self.print_to_terminal(f"Error running net share: {e.stderr}")
    
    def run_ifconfig(self, show_all=False):
        if platform.system() == "Windows":
            cmd = ["ipconfig", "/all"] if show_all else ["ipconfig"]
        else:
            cmd = ["ifconfig", "-a"] if show_all else ["ifconfig"]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            self.print_to_terminal(result.stdout)
        except subprocess.CalledProcessError as e:
            self.print_to_terminal(f"Error running ifconfig/ipconfig: {e.stderr}")
        except FileNotFoundError:
            self.print_to_terminal("ifconfig/ipconfig command not available on this system")
    
    def run_nmap_vuln_scan(self, target):
        self.print_to_terminal(f"Starting Nmap vulnerability scan on {target}...")
        
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments='--script vuln')
            
            for host in nm.all_hosts():
                self.print_to_terminal(f"Results for {host}:")
                for proto in nm[host].all_protocols():
                    self.print_to_terminal(f"Protocol: {proto}")
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        self.print_to_terminal(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
                        if 'script' in nm[host][proto][port]:
                            for script, output in nm[host][proto][port]['script'].items():
                                self.print_to_terminal(f"  {script}: {output}")
        except Exception as e:
            self.print_to_terminal(f"Error running Nmap scan: {str(e)}")
    
    def run_ping(self, target):
        if not target:
            self.print_to_terminal("Usage: ping <IP_ADDRESS_OR_HOSTNAME>")
            return
        
        self.print_to_terminal(f"Pinging {target}...")
        
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            count = "4"
            result = subprocess.run(
                ["ping", param, count, target],
                capture_output=True,
                text=True,
                check=True
            )
            self.print_to_terminal(result.stdout)
        except subprocess.CalledProcessError as e:
            self.print_to_terminal(f"Ping failed: {e.stderr}")
    
    def new_session(self):
        if self.monitor.is_monitoring:
            if not messagebox.askyesno("Confirm", "Stop current monitoring session?"):
                return
            self.stop_monitoring()
        
        self.ip_entry.set("")
        self.monitor = NetworkMonitor(self.detector)
        self.print_to_terminal("New session created")
        self.update_status("New session ready")
    
    def save_threat_log(self):
        if not self.detector.threat_log:
            messagebox.showinfo("Info", "No threat log entries to save")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save Threat Log"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("\n".join(self.detector.threat_log))
                self.print_to_terminal(f"Threat log saved to {filename}")
            except IOError as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def reset_dashboard(self):
        for key, label in self.stats_labels.items():
            label.config(text="0")
        
        self.pie_ax.clear()
        self.bar_ax.clear()
        self.pie_canvas.draw()
        self.bar_canvas.draw()
        
        self.threat_log.config(state=tk.NORMAL)
        self.threat_log.delete(1.0, tk.END)
        self.threat_log.config(state=tk.DISABLED)
        
        self.print_to_terminal("Dashboard reset")
    
    def open_network_scanner(self):
        self.print_to_terminal("Opening network scanner... (placeholder)")
        # Implementation would go here
    
    def open_vulnerability_scanner(self):
        self.print_to_terminal("Opening vulnerability scanner... (placeholder)")
        # Implementation would go here
    
    def open_packet_analyzer(self):
        self.print_to_terminal("Opening packet analyzer... (placeholder)")
        # Implementation would go here
    
    def show_user_guide(self):
        guide = """
Advanced Cyber Security Monitor User Guide

1. Monitoring:
   - Enter target IP address and select network interface
   - Click "Start Monitoring" to begin
   - Click "Stop Monitoring" to stop

2. Dashboard:
   - Overview tab shows real-time statistics and charts
   - Threat Log tab shows detected security threats

3. Terminal Commands:
   - Use the terminal to run network diagnostic commands
   - Type 'help' for available commands

4. Tools:
   - Access additional security tools from the Tools menu
"""
        messagebox.showinfo("User Guide", guide)
    
    def show_about(self):
        about = f"""
Network Based Intrusion Detection System v{VERSION}
Author:Ian Carter Kulani
E-mail:iancarterkulani@gmail.com
Phone:+265(0)988061969

A comprehensive network monitoring and threat detection tool.

Features:
- Real-time network traffic monitoring
- DOS/DDOS attack detection
- Port scan detection
- Vulnerability scanning
- Interactive command terminal
- Data visualization

Developed for educational and professional security purposes.
"""
        messagebox.showinfo("About", about)
    
    def on_closing(self):
        if self.monitor.is_monitoring:
            if messagebox.askyesno("Confirm", "Monitoring is active. Stop monitoring and exit?"):
                self.monitor.stop_monitoring()
                self.root.destroy()
        else:
            self.root.destroy()

def main():
    root = tk.Tk()
    app = CyberSecurityTool(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()