import threading
import time
import pandas as pd
import socket
from datetime import datetime
import re
# Use kamene package (previously called scapy3k) for Python 3 compatibility
from kamene.all import sniff, conf, IP, TCP, UDP, ICMP, Ether, ARP, DNS, Raw

def get_interface_list():
    """Get a list of available network interfaces."""
    # In kamene, network interfaces are accessed differently than in scapy
    try:
        # Get all interfaces
        interfaces = conf.route.routes.keys()
        return list(set([i[0] for i in interfaces if i[0] != 'lo' and i[0] != 'lo0']))
    except (AttributeError, KeyError):
        # Fallback method if the above doesn't work
        try:
            from kamene.arch import get_if_list
            interfaces = get_if_list()
            return [iface for iface in interfaces if not iface.startswith('lo')]
        except:
            # Return a default interface if all else fails
            return ['eth0']

def start_packet_capture(interface, packet_queue, stop_event, bpf_filter="", packet_limit=0, timeout=0):
    """
    Start capturing packets on the specified interface.
    
    Args:
        interface: Network interface to capture on
        packet_queue: Queue to store captured packets
        stop_event: Event to signal when to stop capturing
        bpf_filter: Berkeley Packet Filter string
        packet_limit: Maximum number of packets to capture (0 = unlimited)
        timeout: Timeout in seconds (0 = no timeout)
    """
    def packet_callback(packet):
        # Add the packet to the queue
        packet_queue.put(packet)
        
        # Check if we've reached the packet limit
        if packet_limit > 0 and packet_count[0] >= packet_limit:
            stop_event.set()
            return
        
        packet_count[0] += 1
    
    # Use a list for the counter to make it mutable within the callback
    packet_count = [0]
    
    try:
        # Start the packet capture
        sniff(
            iface=interface,
            prn=packet_callback,
            filter=bpf_filter if bpf_filter else None,
            store=0,  # Don't store packets in memory
            stop_filter=lambda x: stop_event.is_set(),
            timeout=timeout if timeout > 0 else None
        )
    except Exception as e:
        print(f"Error in packet capture: {e}")
    finally:
        # Make sure to set the stop event when finished
        stop_event.set()

def extract_hostname(packet):
    """Extract hostname information from packet if available."""
    hostname = None
    
    # Check for DNS queries
    if packet.haslayer(DNS):
        dns = packet[DNS]
        if dns.qr == 0:  # 0 for query, 1 for response
            hostname = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
    
    # Try to get hostname from HTTP Host header (if available)
    if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
        if Raw in packet and b'Host:' in packet[Raw].load:
            raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
            match = re.search(r'Host:\s*([^\r\n]+)', raw_data)
            if match:
                hostname = match.group(1).strip()
    
    return hostname

def process_packets(packet_batch):
    """
    Process a batch of captured packets into a DataFrame.
    
    Args:
        packet_batch: List of captured packets
        
    Returns:
        DataFrame with processed packet information
    """
    processed_data = []
    
    for packet in packet_batch:
        packet_data = {}
        
        # Get timestamp
        packet_data['timestamp'] = datetime.fromtimestamp(float(packet.time))
        
        # Extract Ethernet information if available
        if Ether in packet:
            packet_data['src_mac'] = packet[Ether].src
            packet_data['dst_mac'] = packet[Ether].dst
        else:
            packet_data['src_mac'] = None
            packet_data['dst_mac'] = None
        
        # Get packet size
        packet_data['length'] = len(packet)
        
        # Extract IP information if available
        if IP in packet:
            packet_data['src_ip'] = packet[IP].src
            packet_data['dst_ip'] = packet[IP].dst
            packet_data['protocol'] = packet[IP].proto
            packet_data['ttl'] = packet[IP].ttl
        else:
            packet_data['src_ip'] = None
            packet_data['dst_ip'] = None
            packet_data['protocol'] = None
            packet_data['ttl'] = None
        
        # Protocol specific information
        if TCP in packet:
            packet_data['protocol_name'] = 'TCP'
            packet_data['src_port'] = packet[TCP].sport
            packet_data['dst_port'] = packet[TCP].dport
            packet_data['flags'] = packet[TCP].flags
        elif UDP in packet:
            packet_data['protocol_name'] = 'UDP'
            packet_data['src_port'] = packet[UDP].sport
            packet_data['dst_port'] = packet[UDP].dport
            packet_data['flags'] = None
        elif ICMP in packet:
            packet_data['protocol_name'] = 'ICMP'
            packet_data['src_port'] = None
            packet_data['dst_port'] = None
            packet_data['flags'] = None
        elif ARP in packet:
            packet_data['protocol_name'] = 'ARP'
            packet_data['src_port'] = None
            packet_data['dst_port'] = None
            packet_data['flags'] = None
            packet_data['src_ip'] = packet[ARP].psrc
            packet_data['dst_ip'] = packet[ARP].pdst
        else:
            packet_data['protocol_name'] = 'Other'
            packet_data['src_port'] = None
            packet_data['dst_port'] = None
            packet_data['flags'] = None
        
        # Try to extract hostname information
        packet_data['hostname'] = extract_hostname(packet)
        
        processed_data.append(packet_data)
    
    # Create DataFrame from processed data
    if processed_data:
        return pd.DataFrame(processed_data)
    else:
        # Return empty DataFrame with the expected columns
        return pd.DataFrame(columns=[
            'timestamp', 'src_mac', 'dst_mac', 'length', 'src_ip', 'dst_ip',
            'protocol', 'ttl', 'protocol_name', 'src_port', 'dst_port', 
            'flags', 'hostname'
        ])

def get_host_name(ip):
    """Try to resolve an IP address to a hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None
