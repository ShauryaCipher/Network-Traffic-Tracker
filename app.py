import streamlit as st
import time
import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from threading import Thread, Event
import queue
import os

# Import local modules
from network_capture import start_packet_capture, process_packets, get_interface_list
from visualization import (
    plot_traffic_over_time,
    plot_protocol_distribution,
    plot_top_connections,
    create_network_graph
)
from anomaly_detection import detect_anomalies, TrafficStatistics
from device_identification import identify_devices
from utils import check_root_privileges

# Set page configuration
st.set_page_config(
    page_title="Network Traffic Visualizer",
    page_icon="🔍",
    layout="wide"
)

# Initialize session state variables
if 'capture_running' not in st.session_state:
    st.session_state.capture_running = False
if 'packet_data' not in st.session_state:
    st.session_state.packet_data = pd.DataFrame()
if 'traffic_stats' not in st.session_state:
    st.session_state.traffic_stats = TrafficStatistics()
if 'captured_packets_count' not in st.session_state:
    st.session_state.captured_packets_count = 0
if 'detected_anomalies' not in st.session_state:
    st.session_state.detected_anomalies = []
if 'detected_devices' not in st.session_state:
    st.session_state.detected_devices = []
if 'packet_queue' not in st.session_state:
    st.session_state.packet_queue = queue.Queue()
if 'stop_event' not in st.session_state:
    st.session_state.stop_event = Event()

def update_data():
    """Function to continuously update data from the packet capture queue"""
    while not st.session_state.stop_event.is_set():
        try:
            # Get new packet data from the queue
            packet_batch = []
            while not st.session_state.packet_queue.empty() and len(packet_batch) < 100:
                packet_batch.append(st.session_state.packet_queue.get(block=False))
                
            if packet_batch:
                # Process packet batch into DataFrame format
                new_data = process_packets(packet_batch)
                
                # Update the packet data
                if st.session_state.packet_data.empty:
                    st.session_state.packet_data = new_data
                else:
                    st.session_state.packet_data = pd.concat([st.session_state.packet_data, new_data])
                    
                # Keep only the last 10,000 packets to limit memory usage
                if len(st.session_state.packet_data) > 10000:
                    st.session_state.packet_data = st.session_state.packet_data.iloc[-10000:]
                
                # Update traffic statistics
                st.session_state.traffic_stats.update(new_data)
                
                # Update captured packets count
                st.session_state.captured_packets_count += len(new_data)
                
                # Run anomaly detection
                anomalies = detect_anomalies(new_data, st.session_state.traffic_stats)
                if anomalies:
                    st.session_state.detected_anomalies.extend(anomalies)
                    # Keep only the most recent 50 anomalies
                    st.session_state.detected_anomalies = st.session_state.detected_anomalies[-50:]
                
                # Update device information
                devices = identify_devices(new_data)
                if devices:
                    current_macs = {d['mac'] for d in st.session_state.detected_devices}
                    for device in devices:
                        if device['mac'] not in current_macs:
                            st.session_state.detected_devices.append(device)
                            current_macs.add(device['mac'])
                
            time.sleep(1)  # Short sleep to prevent high CPU usage
                
        except Exception as e:
            print(f"Error in update_data: {e}")
            time.sleep(1)  # Sleep and retry on error

# Main app title
st.title("🔍 Network Traffic Visualizer")

# Sidebar configuration
with st.sidebar:
    st.header("Capture Settings")
    
    # Get available network interfaces
    interfaces = get_interface_list()
    selected_interface = st.selectbox("Select Network Interface", interfaces)
    
    # Set packet count limit
    packet_limit = st.number_input("Packet Limit (0 for unlimited)", min_value=0, value=1000)
    
    # Set capture filter
    capture_filter = st.text_input("Capture Filter (BPF syntax)", value="")
    st.caption("Example filters: 'tcp', 'port 80', 'host 192.168.1.1'")
    
    # Advanced options expander
    with st.expander("Advanced Options"):
        timeout = st.number_input("Capture Timeout (seconds, 0 for none)", min_value=0, value=0)
        
        # Protocol filters
        st.subheader("Protocols to Capture")
        capture_tcp = st.checkbox("TCP", value=True)
        capture_udp = st.checkbox("UDP", value=True)
        capture_icmp = st.checkbox("ICMP", value=True)
        capture_dns = st.checkbox("DNS", value=True)
        capture_http = st.checkbox("HTTP/HTTPS", value=True)
    
    # Build filter string based on selections
    filter_parts = []
    if capture_filter:
        filter_parts.append(f"({capture_filter})")
    
    protocol_filters = []
    if capture_tcp:
        protocol_filters.append("tcp")
    if capture_udp:
        protocol_filters.append("udp")
    if capture_icmp:
        protocol_filters.append("icmp")
    if capture_dns:
        protocol_filters.append("port 53")
    if capture_http:
        protocol_filters.append("port 80 or port 443")
    
    if protocol_filters:
        filter_parts.append("(" + " or ".join(protocol_filters) + ")")
    
    final_filter = " and ".join(filter_parts) if filter_parts else ""
    
    # Start/Stop buttons
    col1, col2 = st.columns(2)
    
    with col1:
        start_button = st.button("▶️ Start Capture", disabled=st.session_state.capture_running)
    
    with col2:
        stop_button = st.button("⏹️ Stop Capture", disabled=not st.session_state.capture_running)

    # Current status
    st.subheader("Capture Status")
    status = "Running" if st.session_state.capture_running else "Stopped"
    st.info(f"Status: {status}")
    
    if st.session_state.capture_running:
        st.write(f"Packets captured: {st.session_state.captured_packets_count}")
    
    # Reset button
    if st.button("🔄 Reset All Data"):
        st.session_state.packet_data = pd.DataFrame()
        st.session_state.traffic_stats = TrafficStatistics()
        st.session_state.captured_packets_count = 0
        st.session_state.detected_anomalies = []
        st.session_state.detected_devices = []
        st.rerun()

# Handle start button click
if start_button and not st.session_state.capture_running:
    # Initialize stop event
    st.session_state.stop_event.clear()
    st.session_state.capture_running = True
    
    # Start packet capture in a separate thread
    capture_thread = Thread(
        target=start_packet_capture,
        args=(
            selected_interface,
            st.session_state.packet_queue,
            st.session_state.stop_event,
            final_filter,
            packet_limit,
            timeout
        )
    )
    capture_thread.daemon = True
    capture_thread.start()
    
    # Start data processing thread
    update_thread = Thread(
        target=update_data
    )
    update_thread.daemon = True
    update_thread.start()
    
    st.rerun()

# Handle stop button click
if stop_button and st.session_state.capture_running:
    st.session_state.stop_event.set()
    st.session_state.capture_running = False
    st.rerun()

# Main content
# Create tabs for different visualizations
tab1, tab2, tab3, tab4 = st.tabs([
    "Traffic Overview", 
    "Network Graph", 
    "Anomaly Detection", 
    "Connected Devices"
])

# Tab 1: Traffic Overview
with tab1:
    st.header("Network Traffic Overview")
    
    # Display basic stats in metrics
    if not st.session_state.packet_data.empty:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            total_bytes = st.session_state.packet_data['length'].sum()
            st.metric("Total Data Transferred", f"{total_bytes/1024:.2f} KB")
        
        with col2:
            if len(st.session_state.packet_data) > 0:
                avg_packet_size = st.session_state.packet_data['length'].mean()
                st.metric("Average Packet Size", f"{avg_packet_size:.2f} bytes")
            else:
                st.metric("Average Packet Size", "0 bytes")
        
        with col3:
            unique_ips = len(
                set(st.session_state.packet_data['src_ip'].tolist() + 
                    st.session_state.packet_data['dst_ip'].tolist())
            )
            st.metric("Unique IP Addresses", unique_ips)
    
        # Traffic over time chart
        st.subheader("Traffic Volume Over Time")
        if len(st.session_state.packet_data) > 0:
            fig1 = plot_traffic_over_time(st.session_state.packet_data)
            st.pyplot(fig1)
        else:
            st.info("Not enough data to visualize traffic over time.")
        
        # Protocol distribution
        st.subheader("Protocol Distribution")
        fig2 = plot_protocol_distribution(st.session_state.packet_data)
        st.pyplot(fig2)
        
        # Top connections
        st.subheader("Top Connections")
        fig3 = plot_top_connections(st.session_state.packet_data)
        st.pyplot(fig3)
    
    else:
        st.info("No packet data available. Start a capture to visualize traffic.")

# Tab 2: Network Graph
with tab2:
    st.header("Network Communication Graph")
    
    if not st.session_state.packet_data.empty and len(st.session_state.packet_data) > 1:
        # Create network graph
        st.subheader("Network Communication Patterns")
        
        # Add slider to limit number of connections
        max_connections = st.slider(
            "Maximum connections to display", 
            min_value=5, 
            max_value=100, 
            value=20
        )
        
        # Create and display the network graph
        fig = create_network_graph(st.session_state.packet_data, max_connections)
        st.pyplot(fig)
    else:
        st.info("Not enough data to generate a network graph. Capture more packets.")

# Tab 3: Anomaly Detection
with tab3:
    st.header("Anomaly Detection")
    
    # Configure anomaly detection parameters
    with st.expander("Anomaly Detection Configuration"):
        traffic_threshold = st.slider(
            "Traffic Spike Threshold (standard deviations)", 
            min_value=1.0, 
            max_value=10.0, 
            value=3.0, 
            step=0.5
        )
        
        port_scan_threshold = st.slider(
            "Port Scan Detection (unique ports per minute)", 
            min_value=5, 
            max_value=100, 
            value=20
        )
    
    # Display detected anomalies
    if st.session_state.detected_anomalies:
        st.subheader("Detected Anomalies")
        
        for i, anomaly in enumerate(reversed(st.session_state.detected_anomalies)):
            with st.container():
                severity_color = {
                    "High": "🔴", 
                    "Medium": "🟠", 
                    "Low": "🟡"
                }.get(anomaly['severity'], "⚪")
                
                st.write(f"{severity_color} **{anomaly['type']}** - {anomaly['timestamp']}")
                st.write(f"Description: {anomaly['description']}")
                st.write(f"Involved IPs: {', '.join(anomaly['ips'])}")
                st.divider()
                
                # Only show the 10 most recent anomalies to avoid cluttering
                if i >= 9:
                    st.info(f"{len(st.session_state.detected_anomalies) - 10} more anomalies detected...")
                    break
    else:
        st.info("No anomalies detected.")
    
    # Plot traffic with anomaly thresholds
    if not st.session_state.packet_data.empty and len(st.session_state.packet_data) > 10:
        st.subheader("Traffic with Anomaly Thresholds")
        
        # Use traffic_stats to create a plot showing normal vs. anomalous traffic
        traffic_data = st.session_state.traffic_stats.get_traffic_time_series()
        if len(traffic_data) > 1:
            fig, ax = plt.subplots(figsize=(10, 4))
            
            # Plot traffic volume
            times = [t.strftime('%H:%M:%S') for t in traffic_data['timestamp']]
            ax.plot(times, traffic_data['bytes_per_sec'], label='Traffic Volume (bytes/sec)')
            
            # Plot the threshold line
            mean = traffic_data['bytes_per_sec'].mean()
            std = traffic_data['bytes_per_sec'].std() if len(traffic_data) > 1 else 0
            threshold = mean + (traffic_threshold * std)
            ax.axhline(y=threshold, color='r', linestyle='--', label=f'Anomaly Threshold ({traffic_threshold} σ)')
            
            # Format the plot
            ax.set_xlabel('Time')
            ax.set_ylabel('Bytes per Second')
            ax.set_title('Network Traffic with Anomaly Threshold')
            ax.legend()
            
            # Rotate x-axis labels for better readability
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            st.pyplot(fig)
        else:
            st.info("Not enough time-series data for anomaly visualization.")
    else:
        st.info("Not enough packet data for anomaly detection visualization.")

# Tab 4: Connected Devices
with tab4:
    st.header("Connected Devices")
    
    if st.session_state.detected_devices:
        # Create a DataFrame for better display
        device_data = []
        for device in st.session_state.detected_devices:
            device_data.append({
                "MAC Address": device['mac'],
                "IP Address": device['ip'],
                "Hostname": device['hostname'] if device['hostname'] else "Unknown",
                "Vendor": device['vendor'] if device['vendor'] else "Unknown",
                "First Seen": device['first_seen'],
                "Last Seen": device['last_seen'],
                "Packets": device['packets'],
                "Data Transferred": f"{device['bytes']/1024:.2f} KB"
            })
        
        devices_df = pd.DataFrame(device_data)
        st.dataframe(devices_df, use_container_width=True)
        
        # Allow downloading device data as CSV
        csv = devices_df.to_csv(index=False)
        st.download_button(
            label="Download Device Data (CSV)",
            data=csv,
            file_name="network_devices.csv",
            mime="text/csv",
        )
    else:
        st.info("No devices detected yet. Start capturing packets to identify devices on the network.")
    
    # Display a note about device identification accuracy
    st.warning(
        "Note: Device identification relies on observed network traffic. "
        "Some devices may not be detected if they haven't generated traffic during the capture period."
    )

# Display warning about privileges if needed
if not check_root_privileges():  # Check if running with admin/root privileges
    st.warning(
        "⚠️ Network packet capture typically requires administrator/root privileges. "
        "If no packets are being captured, try running this application with elevated privileges."
    )

# Footer
st.markdown("---")
st.caption(
    "Network Traffic Visualizer - A tool for monitoring network traffic, "
    "detecting anomalies, and identifying connected devices."
)
