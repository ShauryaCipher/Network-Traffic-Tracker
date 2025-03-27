import pandas as pd
import socket
import os
from scapy.all import ARP, Ether, srp
import time
from datetime import datetime

class DeviceTracker:
    """
    Class to track and identify devices on the network
    """
    
    def __init__(self):
        """
        Initialize the device tracker
        """
        self.known_devices = {}
        self.last_scan_time = None
        self.scan_interval = 300  # seconds (5 minutes)
    
    def get_devices(self, df):
        """
        Get current devices based on packet data and optionally perform active scanning
        
        Args:
            df (pandas.DataFrame): Dataframe containing packet data
            
        Returns:
            pandas.DataFrame: Dataframe of devices
        """
        # Extract devices from packet data
        self.extract_devices_from_packets(df)
        
        # Perform active scanning if needed
        current_time = datetime.now()
        if (self.last_scan_time is None or 
            (current_time - self.last_scan_time).total_seconds() > self.scan_interval):
            try:
                self.scan_network()
                self.last_scan_time = current_time
            except Exception as e:
                print(f"Error during network scan: {e}")
        
        # Convert to DataFrame for display
        devices_list = []
        for mac, device in self.known_devices.items():
            devices_list.append({
                'mac_address': mac,
                'ip_address': device.get('ip', 'Unknown'),
                'hostname': device.get('hostname', 'Unknown'),
                'last_seen': device.get('last_seen', 'Unknown'),
                'packet_count': device.get('packet_count', 0),
                'first_seen': device.get('first_seen', 'Unknown'),
            })
        
        return pd.DataFrame(devices_list)
    
    def extract_devices_from_packets(self, df):
        """
        Extract device information from packet data
        
        Args:
            df (pandas.DataFrame): Dataframe containing packet data
        """
        if df.empty:
            return
            
        current_time = datetime.now()
        
        # Process source addresses
        if 'src_mac' in df.columns and 'src' in df.columns:
            for _, row in df.iterrows():
                if pd.notna(row['src_mac']) and pd.notna(row['src']):
                    mac = row['src_mac']
                    ip = row['src']
                    
                    if mac not in self.known_devices:
                        self.known_devices[mac] = {
                            'ip': ip,
                            'hostname': self.get_hostname(ip),
                            'first_seen': current_time,
                            'last_seen': current_time,
                            'packet_count': 1
                        }
                    else:
                        self.known_devices[mac]['last_seen'] = current_time
                        self.known_devices[mac]['packet_count'] += 1
                        
                        # Update IP if changed
                        if self.known_devices[mac]['ip'] != ip:
                            self.known_devices[mac]['ip'] = ip
                            self.known_devices[mac]['hostname'] = self.get_hostname(ip)
        
        # Process destination addresses
        if 'dst_mac' in df.columns and 'dst' in df.columns:
            for _, row in df.iterrows():
                if pd.notna(row['dst_mac']) and pd.notna(row['dst']):
                    mac = row['dst_mac']
                    ip = row['dst']
                    
                    if mac not in self.known_devices:
                        self.known_devices[mac] = {
                            'ip': ip,
                            'hostname': self.get_hostname(ip),
                            'first_seen': current_time,
                            'last_seen': current_time,
                            'packet_count': 1
                        }
                    else:
                        self.known_devices[mac]['last_seen'] = current_time
                        
                        # Update IP if changed
                        if self.known_devices[mac]['ip'] != ip:
                            self.known_devices[mac]['ip'] = ip
                            self.known_devices[mac]['hostname'] = self.get_hostname(ip)
    
    def get_hostname(self, ip):
        """
        Attempt to resolve hostname from IP address
        
        Args:
            ip (str): IP address to resolve
            
        Returns:
            str: Resolved hostname or original IP if resolution fails
        """
        try:
            hostname = socket.getfqdn(ip)
            if hostname != ip:  # getfqdn returns the IP if resolution fails
                return hostname
            return ip
        except:
            return ip
    
    def scan_network(self):
        """
        Actively scan the network for devices using ARP
        """
        try:
            # This may fail if not running as root
            if os.geteuid() != 0:
                return
                
            # Create an ARP scan for common home/office subnet
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24")
            
            # Send the packet and get a response
            result = srp(arp_request, timeout=3, verbose=0)[0]
            
            # Process the response
            current_time = datetime.now()
            for sent, received in result:
                mac = received.hwsrc
                ip = received.psrc
                
                if mac not in self.known_devices:
                    self.known_devices[mac] = {
                        'ip': ip,
                        'hostname': self.get_hostname(ip),
                        'first_seen': current_time,
                        'last_seen': current_time,
                        'packet_count': 0
                    }
                else:
                    self.known_devices[mac]['last_seen'] = current_time
                    if self.known_devices[mac]['ip'] != ip:
                        self.known_devices[mac]['ip'] = ip
                        self.known_devices[mac]['hostname'] = self.get_hostname(ip)
                        
        except Exception as e:
            print(f"Error during ARP scan: {e}")
