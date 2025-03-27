from scapy.all import IP, TCP, UDP, ICMP, Ether, DNS, ARP, HTTPRequest
from scapy.layers.http import HTTP
import pandas as pd
from datetime import datetime
import socket

class DataProcessor:
    """
    Process and extract data from captured packets
    """
    
    def __init__(self):
        """
        Initialize the data processor
        """
        pass
    
    def extract_packet_info(self, packet):
        """
        Extract relevant information from a packet
        
        Args:
            packet: A Scapy packet object
            
        Returns:
            dict: Dictionary containing extracted packet information
        """
        # Initialize with default values
        packet_info = {
            'timestamp': datetime.now(),
            'src': None,
            'dst': None,
            'protocol': None,
            'size': len(packet),
            'sport': None,
            'dport': None,
        }
        
        # Check for Ethernet
        if Ether in packet:
            packet_info['src_mac'] = packet[Ether].src
            packet_info['dst_mac'] = packet[Ether].dst
        
        # Check for IP
        if IP in packet:
            packet_info['src'] = packet[IP].src
            packet_info['dst'] = packet[IP].dst
            packet_info['ttl'] = packet[IP].ttl
            
            try:
                # Try to resolve hostnames
                packet_info['src_host'] = socket.getfqdn(packet[IP].src)
                packet_info['dst_host'] = socket.getfqdn(packet[IP].dst)
            except:
                packet_info['src_host'] = packet_info['src']
                packet_info['dst_host'] = packet_info['dst']
        
        # Check for ARP
        elif ARP in packet:
            packet_info['protocol'] = 'ARP'
            packet_info['src'] = packet[ARP].psrc
            packet_info['dst'] = packet[ARP].pdst
        
        # Determine protocol and ports
        if TCP in packet:
            packet_info['protocol'] = 'TCP'
            packet_info['sport'] = packet[TCP].sport
            packet_info['dport'] = packet[TCP].dport
            packet_info['flags'] = packet[TCP].flags
            
            # Check for HTTP
            if packet_info['dport'] == 80 or packet_info['sport'] == 80:
                packet_info['protocol'] = 'HTTP'
            
            # Check for HTTPS
            elif packet_info['dport'] == 443 or packet_info['sport'] == 443:
                packet_info['protocol'] = 'HTTPS'
            
        elif UDP in packet:
            packet_info['protocol'] = 'UDP'
            packet_info['sport'] = packet[UDP].sport
            packet_info['dport'] = packet[UDP].dport
            
            # Check for DNS
            if DNS in packet:
                packet_info['protocol'] = 'DNS'
                if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
                    try:
                        packet_info['query'] = packet[DNS].qd.qname.decode()
                    except:
                        packet_info['query'] = "unknown"
            
        elif ICMP in packet:
            packet_info['protocol'] = 'ICMP'
            packet_info['type'] = packet[ICMP].type
            packet_info['code'] = packet[ICMP].code
        
        return packet_info
    
    def process_packets(self, packets):
        """
        Process a batch of packets and extract their information
        
        Args:
            packets (list): List of Scapy packet objects
            
        Returns:
            list: List of dictionaries containing packet information
        """
        processed_packets = []
        for packet in packets:
            try:
                packet_info = self.extract_packet_info(packet)
                processed_packets.append(packet_info)
            except Exception as e:
                # Skip packets that cause errors during processing
                print(f"Error processing packet: {e}")
                continue
                
        return processed_packets
