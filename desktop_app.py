#!/usr/bin/env python3
import os
import sys
import threading
import queue
import time
import tkinter as tk
import customtkinter as ctk
from datetime import datetime
import subprocess
import psutil
import webbrowser
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import networkx as nx

# Set appearance mode and default color theme
ctk.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

# Import local modules
from network_capture import start_packet_capture, process_packets, get_interface_list
from visualization import plot_protocol_distribution, create_network_graph
from anomaly_detection import detect_anomalies, TrafficStatistics
from device_identification import identify_devices

class NetworkAnalyzerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("Network Traffic Analyzer")
        self.geometry("1200x800")
        self.minsize(1000, 700)
        
        # Initialize session variables
        self.capture_running = False
        self.packet_data = pd.DataFrame()
        self.traffic_stats = TrafficStatistics()
        self.captured_packets_count = 0
        self.detected_anomalies = []
        self.detected_devices = []
        self.packet_queue = queue.Queue()
        self.stop_event = threading.Event()
        
        # Set up grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=4)
        self.grid_rowconfigure(0, weight=1)
        
        # Set up sidebar frame
        self.sidebar_frame = ctk.CTkFrame(self, width=300, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(13, weight=1)
        
        # Logo and name
        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="Network Traffic Analyzer", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        # Interface selection
        self.interface_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="Network Interface:", 
            anchor="w",
            font=ctk.CTkFont(size=14)
        )
        self.interface_label.grid(row=1, column=0, padx=20, pady=(10, 0), sticky="w")
        
        # Get available interfaces
        self.interfaces = get_interface_list()
        self.interface_var = tk.StringVar(value=self.interfaces[0] if self.interfaces else "")
        
        self.interface_menu = ctk.CTkOptionMenu(
            self.sidebar_frame,
            values=self.interfaces,
            variable=self.interface_var,
            width=200
        )
        self.interface_menu.grid(row=2, column=0, padx=20, pady=(5, 10))
        
        # Packet limit
        self.packet_limit_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="Packet Limit (0 for unlimited):", 
            anchor="w",
            font=ctk.CTkFont(size=14)
        )
        self.packet_limit_label.grid(row=3, column=0, padx=20, pady=(10, 0), sticky="w")
        
        self.packet_limit_var = tk.IntVar(value=1000)
        self.packet_limit_entry = ctk.CTkEntry(
            self.sidebar_frame,
            textvariable=self.packet_limit_var,
            width=200
        )
        self.packet_limit_entry.grid(row=4, column=0, padx=20, pady=(5, 10))
        
        # BPF Filter
        self.filter_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="Capture Filter (BPF syntax):", 
            anchor="w",
            font=ctk.CTkFont(size=14)
        )
        self.filter_label.grid(row=5, column=0, padx=20, pady=(10, 0), sticky="w")
        
        self.filter_var = tk.StringVar(value="")
        self.filter_entry = ctk.CTkEntry(
            self.sidebar_frame,
            textvariable=self.filter_var,
            width=200
        )
        self.filter_entry.grid(row=6, column=0, padx=20, pady=(5, 10))
        
        # Filter help text
        self.filter_help = ctk.CTkLabel(
            self.sidebar_frame, 
            text="Example: 'tcp', 'port 80', 'host 192.168.1.1'", 
            text_color="gray",
            anchor="w"
        )
        self.filter_help.grid(row=7, column=0, padx=20, pady=(0, 10), sticky="w")
        
        # Protocol checkboxes
        self.protocols_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="Protocols to Capture:", 
            anchor="w",
            font=ctk.CTkFont(size=14)
        )
        self.protocols_label.grid(row=8, column=0, padx=20, pady=(10, 5), sticky="w")
        
        # Protocol checkboxes container
        self.protocols_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.protocols_frame.grid(row=9, column=0, padx=20, pady=(0, 10), sticky="w")
        
        self.tcp_var = tk.BooleanVar(value=True)
        self.tcp_checkbox = ctk.CTkCheckBox(
            self.protocols_frame, 
            text="TCP", 
            variable=self.tcp_var
        )
        self.tcp_checkbox.grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
        
        self.udp_var = tk.BooleanVar(value=True)
        self.udp_checkbox = ctk.CTkCheckBox(
            self.protocols_frame, 
            text="UDP", 
            variable=self.udp_var
        )
        self.udp_checkbox.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        
        self.icmp_var = tk.BooleanVar(value=True)
        self.icmp_checkbox = ctk.CTkCheckBox(
            self.protocols_frame, 
            text="ICMP", 
            variable=self.icmp_var
        )
        self.icmp_checkbox.grid(row=1, column=0, padx=(0, 10), pady=5, sticky="w")
        
        self.dns_var = tk.BooleanVar(value=True)
        self.dns_checkbox = ctk.CTkCheckBox(
            self.protocols_frame, 
            text="DNS", 
            variable=self.dns_var
        )
        self.dns_checkbox.grid(row=1, column=1, padx=10, pady=5, sticky="w")
        
        # Status display
        self.status_frame = ctk.CTkFrame(self.sidebar_frame)
        self.status_frame.grid(row=10, column=0, padx=20, pady=(10, 20), sticky="ew")
        
        self.status_label = ctk.CTkLabel(
            self.status_frame, 
            text="Status: Stopped", 
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.status_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        self.packet_count_label = ctk.CTkLabel(
            self.status_frame, 
            text="Packets: 0", 
            font=ctk.CTkFont(size=14)
        )
        self.packet_count_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        
        # Start / Stop buttons
        self.button_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.button_frame.grid(row=11, column=0, padx=20, pady=(10, 10))
        
        self.start_button = ctk.CTkButton(
            self.button_frame, 
            text="Start Capture", 
            command=self.start_capture,
            fg_color="green",
            width=120
        )
        self.start_button.grid(row=0, column=0, padx=(0, 10))
        
        self.stop_button = ctk.CTkButton(
            self.button_frame, 
            text="Stop Capture", 
            command=self.stop_capture,
            fg_color="firebrick",
            width=120,
            state="disabled"
        )
        self.stop_button.grid(row=0, column=1)
        
        # Reset button
        self.reset_button = ctk.CTkButton(
            self.sidebar_frame, 
            text="Reset All Data", 
            command=self.reset_data,
            fg_color="gray40"
        )
        self.reset_button.grid(row=12, column=0, padx=20, pady=(5, 20))
        
        # Start Streamlit button
        self.streamlit_button = ctk.CTkButton(
            self.sidebar_frame, 
            text="Open Full Dashboard", 
            command=self.open_streamlit_dashboard
        )
        self.streamlit_button.grid(row=13, column=0, padx=20, pady=(5, 20), sticky="s")
        
        # Create main content area with tabs
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=0, column=1, padx=(20, 20), pady=(20, 20), sticky="nsew")
        
        # Add tabs
        self.tab_overview = self.tabview.add("Overview")
        self.tab_network = self.tabview.add("Network Graph")
        self.tab_anomalies = self.tabview.add("Anomalies")
        self.tab_devices = self.tabview.add("Devices")
        
        # Configure tab grid
        for tab in [self.tab_overview, self.tab_network, self.tab_anomalies, self.tab_devices]:
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0, weight=1)
        
        # Initialize tabs
        self.setup_overview_tab()
        self.setup_network_tab()
        self.setup_anomalies_tab()
        self.setup_devices_tab()
        
        # Set up the update timer
        self.after(1000, self.update_ui)
    
    def setup_overview_tab(self):
        """Set up the Overview tab"""
        self.overview_frame = ctk.CTkScrollableFrame(self.tab_overview)
        self.overview_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.overview_frame.grid_columnconfigure(0, weight=1)
        
        # Title
        self.overview_title = ctk.CTkLabel(
            self.overview_frame, 
            text="Network Traffic Overview", 
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.overview_title.grid(row=0, column=0, padx=10, pady=(10, 20))
        
        # Metrics Frame
        self.metrics_frame = ctk.CTkFrame(self.overview_frame)
        self.metrics_frame.grid(row=1, column=0, padx=10, pady=(0, 20), sticky="ew")
        self.metrics_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Total Data
        self.total_data_label = ctk.CTkLabel(
            self.metrics_frame, 
            text="Total Data:", 
            font=ctk.CTkFont(size=14)
        )
        self.total_data_label.grid(row=0, column=0, padx=10, pady=5)
        
        self.total_data_value = ctk.CTkLabel(
            self.metrics_frame, 
            text="0 KB", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.total_data_value.grid(row=1, column=0, padx=10, pady=5)
        
        # Average Packet Size
        self.avg_size_label = ctk.CTkLabel(
            self.metrics_frame, 
            text="Avg Packet Size:", 
            font=ctk.CTkFont(size=14)
        )
        self.avg_size_label.grid(row=0, column=1, padx=10, pady=5)
        
        self.avg_size_value = ctk.CTkLabel(
            self.metrics_frame, 
            text="0 bytes", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.avg_size_value.grid(row=1, column=1, padx=10, pady=5)
        
        # Unique IPs
        self.unique_ips_label = ctk.CTkLabel(
            self.metrics_frame, 
            text="Unique IPs:", 
            font=ctk.CTkFont(size=14)
        )
        self.unique_ips_label.grid(row=0, column=2, padx=10, pady=5)
        
        self.unique_ips_value = ctk.CTkLabel(
            self.metrics_frame, 
            text="0", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.unique_ips_value.grid(row=1, column=2, padx=10, pady=5)
        
        # Protocol Distribution Chart
        self.proto_chart_label = ctk.CTkLabel(
            self.overview_frame, 
            text="Protocol Distribution", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.proto_chart_label.grid(row=2, column=0, padx=10, pady=(20, 10))
        
        self.proto_chart_frame = ctk.CTkFrame(self.overview_frame)
        self.proto_chart_frame.grid(row=3, column=0, padx=10, pady=(0, 20), sticky="ew")
        
        # Placeholder for protocol chart
        self.protocol_canvas = None
    
    def setup_network_tab(self):
        """Set up the Network Graph tab"""
        self.network_frame = ctk.CTkFrame(self.tab_network)
        self.network_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.network_frame.grid_columnconfigure(0, weight=1)
        self.network_frame.grid_rowconfigure(2, weight=1)
        
        # Title
        self.network_title = ctk.CTkLabel(
            self.network_frame, 
            text="Network Communication Graph", 
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.network_title.grid(row=0, column=0, padx=10, pady=(10, 20))
        
        # Controls
        self.network_controls = ctk.CTkFrame(self.network_frame, fg_color="transparent")
        self.network_controls.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="ew")
        
        self.max_connections_label = ctk.CTkLabel(
            self.network_controls, 
            text="Maximum connections:"
        )
        self.max_connections_label.grid(row=0, column=0, padx=(10, 10), pady=10)
        
        self.max_connections_var = tk.IntVar(value=20)
        self.max_connections_slider = ctk.CTkSlider(
            self.network_controls,
            from_=5,
            to=100,
            number_of_steps=19,
            variable=self.max_connections_var
        )
        self.max_connections_slider.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="ew")
        
        self.connections_value_label = ctk.CTkLabel(
            self.network_controls, 
            text="20"
        )
        self.connections_value_label.grid(row=0, column=2, padx=(0, 10), pady=10)
        
        # Update the label when slider changes
        self.max_connections_var.trace_add("write", lambda *args: self.connections_value_label.configure(
            text=str(self.max_connections_var.get())
        ))
        
        # Refresh button
        self.refresh_graph_button = ctk.CTkButton(
            self.network_controls, 
            text="Refresh Graph", 
            command=self.refresh_network_graph,
            width=120
        )
        self.refresh_graph_button.grid(row=0, column=3, padx=10, pady=10)
        
        # Network Graph Canvas
        self.graph_canvas_frame = ctk.CTkFrame(self.network_frame)
        self.graph_canvas_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
        
        # Placeholder for network graph
        self.network_canvas = None
    
    def setup_anomalies_tab(self):
        """Set up the Anomalies tab"""
        self.anomalies_frame = ctk.CTkScrollableFrame(self.tab_anomalies)
        self.anomalies_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.anomalies_frame.grid_columnconfigure(0, weight=1)
        
        # Title
        self.anomalies_title = ctk.CTkLabel(
            self.anomalies_frame, 
            text="Anomaly Detection", 
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.anomalies_title.grid(row=0, column=0, padx=10, pady=(10, 20))
        
        # Configuration frame
        self.anomaly_config_frame = ctk.CTkFrame(self.anomalies_frame)
        self.anomaly_config_frame.grid(row=1, column=0, padx=10, pady=(0, 20), sticky="ew")
        
        # Traffic spike threshold
        self.traffic_threshold_label = ctk.CTkLabel(
            self.anomaly_config_frame, 
            text="Traffic Spike Threshold (standard deviations):"
        )
        self.traffic_threshold_label.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="w")
        
        self.traffic_threshold_var = tk.DoubleVar(value=3.0)
        self.traffic_threshold_slider = ctk.CTkSlider(
            self.anomaly_config_frame,
            from_=1.0,
            to=10.0,
            number_of_steps=18,
            variable=self.traffic_threshold_var
        )
        self.traffic_threshold_slider.grid(row=1, column=0, padx=10, pady=(5, 5), sticky="ew")
        
        self.threshold_value_label = ctk.CTkLabel(
            self.anomaly_config_frame, 
            text="3.0"
        )
        self.threshold_value_label.grid(row=1, column=1, padx=(0, 10), pady=(5, 5))
        
        # Update the label when slider changes
        self.traffic_threshold_var.trace_add("write", lambda *args: self.threshold_value_label.configure(
            text=f"{self.traffic_threshold_var.get():.1f}"
        ))
        
        # Port scan threshold
        self.port_scan_label = ctk.CTkLabel(
            self.anomaly_config_frame, 
            text="Port Scan Detection (unique ports per minute):"
        )
        self.port_scan_label.grid(row=2, column=0, padx=10, pady=(10, 0), sticky="w")
        
        self.port_scan_var = tk.IntVar(value=20)
        self.port_scan_slider = ctk.CTkSlider(
            self.anomaly_config_frame,
            from_=5,
            to=100,
            number_of_steps=19,
            variable=self.port_scan_var
        )
        self.port_scan_slider.grid(row=3, column=0, padx=10, pady=(5, 10), sticky="ew")
        
        self.port_scan_value_label = ctk.CTkLabel(
            self.anomaly_config_frame, 
            text="20"
        )
        self.port_scan_value_label.grid(row=3, column=1, padx=(0, 10), pady=(5, 10))
        
        # Update the label when slider changes
        self.port_scan_var.trace_add("write", lambda *args: self.port_scan_value_label.configure(
            text=str(self.port_scan_var.get())
        ))
        
        # Anomalies List Label
        self.anomalies_list_label = ctk.CTkLabel(
            self.anomalies_frame, 
            text="Detected Anomalies", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.anomalies_list_label.grid(row=2, column=0, padx=10, pady=(10, 10))
        
        # Anomalies container
        self.anomalies_container = ctk.CTkFrame(self.anomalies_frame)
        self.anomalies_container.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="ew")
        
        # If no anomalies yet
        self.no_anomalies_label = ctk.CTkLabel(
            self.anomalies_container, 
            text="No anomalies detected yet.", 
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        self.no_anomalies_label.grid(row=0, column=0, padx=20, pady=20)
    
    def setup_devices_tab(self):
        """Set up the Devices tab"""
        self.devices_frame = ctk.CTkScrollableFrame(self.tab_devices)
        self.devices_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.devices_frame.grid_columnconfigure(0, weight=1)
        
        # Title
        self.devices_title = ctk.CTkLabel(
            self.devices_frame, 
            text="Connected Devices", 
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.devices_title.grid(row=0, column=0, padx=10, pady=(10, 20))
        
        # Devices table header
        self.devices_header = ctk.CTkFrame(self.devices_frame)
        self.devices_header.grid(row=1, column=0, padx=10, pady=(0, 5), sticky="ew")
        
        headers = ["MAC Address", "IP Address", "Hostname", "Vendor", "First Seen", "Last Seen", "Packets", "Data"]
        widths = [150, 120, 120, 120, 100, 100, 70, 80]
        
        for i, header in enumerate(headers):
            label = ctk.CTkLabel(
                self.devices_header, 
                text=header, 
                font=ctk.CTkFont(weight="bold"),
                width=widths[i]
            )
            label.grid(row=0, column=i, padx=5, pady=5, sticky="w")
        
        # Devices container
        self.devices_container = ctk.CTkFrame(self.devices_frame)
        self.devices_container.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        
        # If no devices yet
        self.no_devices_label = ctk.CTkLabel(
            self.devices_container, 
            text="No devices detected yet.", 
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        self.no_devices_label.grid(row=0, column=0, padx=20, pady=20)
        
        # Export button
        self.export_button = ctk.CTkButton(
            self.devices_frame, 
            text="Export Devices to CSV", 
            command=self.export_devices_csv,
            state="disabled"
        )
        self.export_button.grid(row=3, column=0, padx=10, pady=(10, 20))
    
    def start_capture(self):
        """Start packet capture"""
        if self.capture_running:
            return
        
        # Get the selected interface
        selected_interface = self.interface_var.get()
        if not selected_interface:
            self.show_error("No interface selected", "Please select a network interface to capture on.")
            return
        
        # Get filter string
        protocol_filters = []
        if self.tcp_var.get():
            protocol_filters.append("tcp")
        if self.udp_var.get():
            protocol_filters.append("udp")
        if self.icmp_var.get():
            protocol_filters.append("icmp")
        if self.dns_var.get():
            protocol_filters.append("port 53")
        
        filter_parts = []
        custom_filter = self.filter_var.get().strip()
        if custom_filter:
            filter_parts.append(f"({custom_filter})")
        
        if protocol_filters:
            filter_parts.append("(" + " or ".join(protocol_filters) + ")")
        
        final_filter = " and ".join(filter_parts) if filter_parts else ""
        
        # Get packet limit
        try:
            packet_limit = int(self.packet_limit_var.get())
        except ValueError:
            packet_limit = 0
        
        # Reset the stop event
        self.stop_event.clear()
        self.capture_running = True
        
        # Start packet capture in a separate thread
        capture_thread = threading.Thread(
            target=start_packet_capture,
            args=(
                selected_interface,
                self.packet_queue,
                self.stop_event,
                final_filter,
                packet_limit,
                0
            )
        )
        capture_thread.daemon = True
        capture_thread.start()
        
        # Start data processing thread
        update_thread = threading.Thread(
            target=self.update_data
        )
        update_thread.daemon = True
        update_thread.start()
        
        # Update UI
        self.status_label.configure(text="Status: Running")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
    
    def stop_capture(self):
        """Stop packet capture"""
        if not self.capture_running:
            return
        
        self.stop_event.set()
        self.capture_running = False
        
        # Update UI
        self.status_label.configure(text="Status: Stopped")
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
    
    def update_data(self):
        """Function to continuously update data from the packet capture queue"""
        while not self.stop_event.is_set():
            try:
                # Get new packet data from the queue
                packet_batch = []
                while not self.packet_queue.empty() and len(packet_batch) < 100:
                    packet_batch.append(self.packet_queue.get(block=False))
                    
                if packet_batch:
                    # Process packet batch into DataFrame format
                    new_data = process_packets(packet_batch)
                    
                    # Update the packet data
                    if self.packet_data.empty:
                        self.packet_data = new_data
                    else:
                        self.packet_data = pd.concat([self.packet_data, new_data])
                        
                    # Keep only the last 10,000 packets to limit memory usage
                    if len(self.packet_data) > 10000:
                        self.packet_data = self.packet_data.iloc[-10000:]
                    
                    # Update traffic statistics
                    self.traffic_stats.update(new_data)
                    
                    # Update captured packets count
                    self.captured_packets_count += len(new_data)
                    
                    # Run anomaly detection
                    anomalies = detect_anomalies(
                        new_data, 
                        self.traffic_stats, 
                        self.traffic_threshold_var.get(),
                        self.port_scan_var.get()
                    )
                    if anomalies:
                        self.detected_anomalies.extend(anomalies)
                        # Keep only the most recent 50 anomalies
                        self.detected_anomalies = self.detected_anomalies[-50:]
                    
                    # Update device information
                    devices = identify_devices(new_data)
                    if devices:
                        current_macs = {d['mac'] for d in self.detected_devices}
                        for device in devices:
                            if device['mac'] not in current_macs:
                                self.detected_devices.append(device)
                                current_macs.add(device['mac'])
                
                time.sleep(1)  # Short sleep to prevent high CPU usage
                    
            except Exception as e:
                print(f"Error in update_data: {e}")
                time.sleep(1)  # Sleep and retry on error
    
    def update_ui(self):
        """Update the UI with current data"""
        # Update packet count label
        self.packet_count_label.configure(text=f"Packets: {self.captured_packets_count}")
        
        # Update metrics if we have data
        if not self.packet_data.empty:
            # Total data
            total_bytes = self.packet_data['length'].sum()
            self.total_data_value.configure(text=f"{total_bytes/1024:.2f} KB")
            
            # Average packet size
            avg_packet_size = self.packet_data['length'].mean()
            self.avg_size_value.configure(text=f"{avg_packet_size:.2f} bytes")
            
            # Unique IPs
            unique_ips = len(
                set(self.packet_data['src_ip'].tolist() + 
                    self.packet_data['dst_ip'].tolist())
            )
            self.unique_ips_value.configure(text=str(unique_ips))
            
            # Update protocol chart
            self.update_protocol_chart()
            
            # Enable export button if we have devices
            if self.detected_devices:
                self.export_button.configure(state="normal")
                self.update_devices_table()
            
            # Update anomalies list
            if self.detected_anomalies:
                self.update_anomalies_list()
        
        # Schedule next update
        self.after(1000, self.update_ui)
    
    def update_protocol_chart(self):
        """Update the protocol distribution chart"""
        if self.packet_data.empty:
            return
        
        # Create figure for protocol distribution
        fig = plot_protocol_distribution(self.packet_data)
        
        # Clear existing canvas if it exists
        if self.protocol_canvas:
            self.protocol_canvas.get_tk_widget().destroy()
        
        # Create new canvas with the chart
        self.protocol_canvas = FigureCanvasTkAgg(fig, master=self.proto_chart_frame)
        self.protocol_canvas.draw()
        self.protocol_canvas.get_tk_widget().pack(fill="both", expand=True)
    
    def refresh_network_graph(self):
        """Refresh the network graph visualization"""
        if self.packet_data.empty or len(self.packet_data) <= 1:
            self.show_info("Not enough data", "Not enough data to generate a network graph.")
            return
        
        max_connections = self.max_connections_var.get()
        
        # Create figure for network graph
        fig = create_network_graph(self.packet_data, max_connections)
        
        # Clear existing canvas if it exists
        if self.network_canvas:
            self.network_canvas.get_tk_widget().destroy()
        
        # Create new canvas with the chart
        self.network_canvas = FigureCanvasTkAgg(fig, master=self.graph_canvas_frame)
        self.network_canvas.draw()
        self.network_canvas.get_tk_widget().pack(fill="both", expand=True)
    
    def update_anomalies_list(self):
        """Update the list of detected anomalies"""
        # Remove the "no anomalies" label if it exists
        if hasattr(self, 'no_anomalies_label'):
            self.no_anomalies_label.destroy()
        
        # Clear existing anomalies
        for widget in self.anomalies_container.winfo_children():
            widget.destroy()
        
        # Add anomalies in reverse order (newest first)
        for i, anomaly in enumerate(reversed(self.detected_anomalies[:10])):
            anomaly_frame = ctk.CTkFrame(self.anomalies_container)
            anomaly_frame.grid(row=i, column=0, padx=10, pady=5, sticky="ew")
            
            # Determine severity color
            severity_color = {
                "High": "firebrick",
                "Medium": "darkorange",
                "Low": "gold"
            }.get(anomaly['severity'], "gray")
            
            # Severity indicator
            severity_indicator = ctk.CTkFrame(anomaly_frame, width=10, fg_color=severity_color)
            severity_indicator.grid(row=0, column=0, rowspan=3, padx=(5, 10), pady=5, sticky="ns")
            
            # Type and timestamp
            header_text = f"{anomaly['type']} - {anomaly['timestamp'].strftime('%H:%M:%S')}"
            header = ctk.CTkLabel(
                anomaly_frame, 
                text=header_text, 
                font=ctk.CTkFont(weight="bold")
            )
            header.grid(row=0, column=1, padx=5, pady=(5, 0), sticky="w")
            
            # Description
            description = ctk.CTkLabel(
                anomaly_frame, 
                text=anomaly['description'],
                wraplength=500
            )
            description.grid(row=1, column=1, padx=5, pady=(0, 0), sticky="w")
            
            # Involved IPs
            ips_text = f"Involved IPs: {', '.join(anomaly['ips'])}"
            ips = ctk.CTkLabel(
                anomaly_frame, 
                text=ips_text,
                text_color="gray"
            )
            ips.grid(row=2, column=1, padx=5, pady=(0, 5), sticky="w")
    
    def update_devices_table(self):
        """Update the table of detected devices"""
        # Remove the "no devices" label if it exists
        if hasattr(self, 'no_devices_label'):
            self.no_devices_label.destroy()
        
        # Clear existing devices
        for widget in self.devices_container.winfo_children():
            widget.destroy()
        
        # Add devices (show maximum 20 for performance)
        for i, device in enumerate(self.detected_devices[:20]):
            row_bg = "gray90" if i % 2 == 0 else "gray95"
            row_frame = ctk.CTkFrame(self.devices_container)
            row_frame.grid(row=i, column=0, padx=5, pady=2, sticky="ew")
            
            # MAC Address
            mac_label = ctk.CTkLabel(
                row_frame, 
                text=device['mac'],
                width=150
            )
            mac_label.grid(row=0, column=0, padx=5, pady=2, sticky="w")
            
            # IP Address
            ip_label = ctk.CTkLabel(
                row_frame, 
                text=device['ip'] if device['ip'] else "Unknown",
                width=120
            )
            ip_label.grid(row=0, column=1, padx=5, pady=2, sticky="w")
            
            # Hostname
            hostname_label = ctk.CTkLabel(
                row_frame, 
                text=device['hostname'] if device['hostname'] else "Unknown",
                width=120
            )
            hostname_label.grid(row=0, column=2, padx=5, pady=2, sticky="w")
            
            # Vendor
            vendor_label = ctk.CTkLabel(
                row_frame, 
                text=device['vendor'] if device['vendor'] else "Unknown",
                width=120
            )
            vendor_label.grid(row=0, column=3, padx=5, pady=2, sticky="w")
            
            # First Seen
            first_seen_label = ctk.CTkLabel(
                row_frame, 
                text=device['first_seen'].strftime('%H:%M:%S'),
                width=100
            )
            first_seen_label.grid(row=0, column=4, padx=5, pady=2, sticky="w")
            
            # Last Seen
            last_seen_label = ctk.CTkLabel(
                row_frame, 
                text=device['last_seen'].strftime('%H:%M:%S'),
                width=100
            )
            last_seen_label.grid(row=0, column=5, padx=5, pady=2, sticky="w")
            
            # Packets
            packets_label = ctk.CTkLabel(
                row_frame, 
                text=str(device['packets']),
                width=70
            )
            packets_label.grid(row=0, column=6, padx=5, pady=2, sticky="w")
            
            # Data
            data_label = ctk.CTkLabel(
                row_frame, 
                text=f"{device['bytes']/1024:.2f} KB",
                width=80
            )
            data_label.grid(row=0, column=7, padx=5, pady=2, sticky="w")
    
    def reset_data(self):
        """Reset all collected data"""
        self.packet_data = pd.DataFrame()
        self.traffic_stats = TrafficStatistics()
        self.captured_packets_count = 0
        self.detected_anomalies = []
        self.detected_devices = []
        
        # Reset UI
        self.total_data_value.configure(text="0 KB")
        self.avg_size_value.configure(text="0 bytes")
        self.unique_ips_value.configure(text="0")
        self.packet_count_label.configure(text="Packets: 0")
        
        # Clear charts
        if self.protocol_canvas:
            self.protocol_canvas.get_tk_widget().destroy()
            self.protocol_canvas = None
        
        if self.network_canvas:
            self.network_canvas.get_tk_widget().destroy()
            self.network_canvas = None
        
        # Reset anomalies list
        for widget in self.anomalies_container.winfo_children():
            widget.destroy()
        
        self.no_anomalies_label = ctk.CTkLabel(
            self.anomalies_container, 
            text="No anomalies detected yet.", 
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        self.no_anomalies_label.grid(row=0, column=0, padx=20, pady=20)
        
        # Reset devices table
        for widget in self.devices_container.winfo_children():
            widget.destroy()
        
        self.no_devices_label = ctk.CTkLabel(
            self.devices_container, 
            text="No devices detected yet.", 
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        self.no_devices_label.grid(row=0, column=0, padx=20, pady=20)
        
        # Disable export button
        self.export_button.configure(state="disabled")
        
        self.show_info("Reset Complete", "All data has been reset.")
    
    def export_devices_csv(self):
        """Export the detected devices to a CSV file"""
        if not self.detected_devices:
            self.show_info("No Data", "No device data to export.")
            return
        
        try:
            # Create a DataFrame for export
            device_data = []
            for device in self.detected_devices:
                device_data.append({
                    "MAC Address": device['mac'],
                    "IP Address": device['ip'] if device['ip'] else "Unknown",
                    "Hostname": device['hostname'] if device['hostname'] else "Unknown",
                    "Vendor": device['vendor'] if device['vendor'] else "Unknown",
                    "First Seen": device['first_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                    "Last Seen": device['last_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                    "Packets": device['packets'],
                    "Data (KB)": f"{device['bytes']/1024:.2f}"
                })
            
            devices_df = pd.DataFrame(device_data)
            
            # Save to file
            filename = f"network_devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            devices_df.to_csv(filename, index=False)
            
            self.show_info("Export Successful", f"Device data exported to {filename}")
        except Exception as e:
            self.show_error("Export Error", f"Error exporting devices: {str(e)}")
    
    def open_streamlit_dashboard(self):
        """Open the full Streamlit dashboard in a browser"""
        # Start the Streamlit app if not already running
        try:
            # Check if Streamlit is already running
            streamlit_running = False
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                if proc.info['cmdline'] and 'streamlit' in str(proc.info['cmdline']):
                    streamlit_running = True
                    break
            
            # Start Streamlit if not running
            if not streamlit_running:
                # Start in a detached process
                cmd = ["streamlit", "run", "app.py", "--server.port", "5000"]
                if sys.platform == 'win32':
                    subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
                else:
                    subprocess.Popen(cmd, start_new_session=True)
                
                # Give it a moment to start
                time.sleep(3)
            
            # Open the dashboard in the default browser
            webbrowser.open("http://localhost:5000")
            
        except Exception as e:
            self.show_error("Dashboard Error", f"Error opening dashboard: {str(e)}")
    
    def show_info(self, title, message):
        """Show an information dialog"""
        info_window = ctk.CTkToplevel(self)
        info_window.title(title)
        info_window.geometry("400x200")
        info_window.transient(self)
        info_window.grab_set()
        
        # Center the window
        info_window.update_idletasks()
        width = info_window.winfo_width()
        height = info_window.winfo_height()
        x = (info_window.winfo_screenwidth() // 2) - (width // 2)
        y = (info_window.winfo_screenheight() // 2) - (height // 2)
        info_window.geometry(f"{width}x{height}+{x}+{y}")
        
        # Add message
        label = ctk.CTkLabel(
            info_window, 
            text=message,
            wraplength=350
        )
        label.pack(padx=20, pady=20, expand=True)
        
        # Add OK button
        button = ctk.CTkButton(
            info_window, 
            text="OK", 
            command=info_window.destroy,
            width=100
        )
        button.pack(padx=20, pady=20)
    
    def show_error(self, title, message):
        """Show an error dialog"""
        error_window = ctk.CTkToplevel(self)
        error_window.title(title)
        error_window.geometry("400x200")
        error_window.transient(self)
        error_window.grab_set()
        
        # Center the window
        error_window.update_idletasks()
        width = error_window.winfo_width()
        height = error_window.winfo_height()
        x = (error_window.winfo_screenwidth() // 2) - (width // 2)
        y = (error_window.winfo_screenheight() // 2) - (height // 2)
        error_window.geometry(f"{width}x{height}+{x}+{y}")
        
        # Add message
        label = ctk.CTkLabel(
            error_window, 
            text=message,
            wraplength=350,
            text_color="red"
        )
        label.pack(padx=20, pady=20, expand=True)
        
        # Add OK button
        button = ctk.CTkButton(
            error_window, 
            text="OK", 
            command=error_window.destroy,
            width=100
        )
        button.pack(padx=20, pady=20)

if __name__ == "__main__":
    # Check for admin privileges
    if os.geteuid() != 0:  # Not root on Unix-like systems
        print("Warning: Network packet capture typically requires administrator/root privileges.")
        print("If no packets are being captured, try running this application with elevated privileges.")
    
    app = NetworkAnalyzerApp()
    app.mainloop()