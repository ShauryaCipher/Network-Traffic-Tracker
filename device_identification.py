import pandas as pd
from datetime import datetime
import re

# Dictionary to cache MAC prefix to vendor mappings
MAC_VENDORS = {
    # Some common vendors - in a real application, this would be loaded from a database
    "00:00:0C": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:03:6B": "Cisco Systems",
    "00:04:9A": "Cisco Systems",
    "00:0A:41": "Cisco Systems",
    "00:0A:8A": "Cisco Systems",
    "00:0C:85": "Cisco Systems",
    "00:0D:65": "Cisco Systems",
    "00:0E:38": "Cisco Systems",
    "00:0E:D7": "Cisco Systems",
    "00:0F:23": "Cisco Systems",
    "00:0F:34": "Cisco Systems",
    "00:11:20": "Cisco Systems",
    "00:11:5C": "Cisco Systems",
    "00:12:00": "Cisco Systems",
    "00:12:7F": "Cisco Systems",
    "00:12:D9": "Cisco Systems",
    "00:13:19": "Cisco Systems",
    "00:13:60": "Cisco Systems",
    "00:13:C3": "Cisco Systems",
    "00:14:69": "Cisco Systems",
    "00:14:A8": "Cisco Systems",
    "00:14:F1": "Cisco Systems",
    "00:15:2B": "Cisco Systems",
    "00:15:62": "Cisco Systems",
    "00:15:F9": "Cisco Systems",
    "00:16:C7": "Cisco Systems",
    "00:17:0E": "Cisco Systems",
    "00:17:3B": "Cisco Systems",
    "00:17:5A": "Cisco Systems",
    "00:17:94": "Cisco Systems",
    "00:17:DF": "Cisco Systems",
    "00:18:18": "Cisco Systems",
    "00:18:73": "Cisco Systems",
    "00:18:B9": "Cisco Systems",
    "00:19:2F": "Cisco Systems",
    "00:19:55": "Cisco Systems",
    "00:19:A9": "Cisco Systems",
    "00:19:E7": "Cisco Systems",
    "00:1A:2F": "Cisco Systems",
    "00:1A:6C": "Cisco Systems",
    "00:1A:A1": "Cisco Systems",
    "00:1A:E2": "Cisco Systems",
    "00:1B:0C": "Cisco Systems",
    "00:1B:53": "Cisco Systems",
    "00:1B:8F": "Cisco Systems",
    "00:1B:D4": "Cisco Systems",
    "00:1C:0E": "Cisco Systems",
    "00:1C:57": "Cisco Systems",
    "00:1C:9C": "Cisco Systems",
    "00:1C:F6": "Cisco Systems",
    "00:1D:45": "Cisco Systems",
    "00:1D:70": "Cisco Systems",
    "00:1D:A1": "Cisco Systems",
    "00:1D:E5": "Cisco Systems",
    "00:1E:13": "Cisco Systems",
    "00:1E:49": "Cisco Systems",
    "00:1E:79": "Cisco Systems",
    "00:1E:BD": "Cisco Systems",
    "00:1E:F6": "Cisco Systems",
    "00:1F:27": "Cisco Systems",
    "00:1F:6C": "Cisco Systems",
    "00:1F:9D": "Cisco Systems",
    "00:1F:C9": "Cisco Systems",
    
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    
    "00:16:3E": "Xensource",
    
    "00:05:69": "VMware, Inc.",
    "00:0C:29": "VMware, Inc.",
    "00:1C:14": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0A:27": "Apple",
    "00:0A:95": "Apple",
    "00:0D:93": "Apple",
    "00:0E:E6": "Apple",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:CB": "Apple",
    "00:17:F2": "Apple",
    "00:19:E3": "Apple",
    "00:1B:63": "Apple",
    "00:1D:4F": "Apple",
    "00:1E:52": "Apple",
    "00:1E:C2": "Apple",
    "00:1F:5B": "Apple",
    "00:1F:F3": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4B": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    "00:30:65": "Apple",
    "00:3E:E1": "Apple",
    "00:50:E4": "Apple",
    "00:56:CD": "Apple",
    "00:61:71": "Apple",
    "00:6D:52": "Apple",
    "00:88:65": "Apple",
    "00:B3:62": "Apple",
    "00:C6:10": "Apple",
    "04:0C:CE": "Apple",
    "04:15:52": "Apple",
    "04:1E:64": "Apple",
    "04:26:65": "Apple",
    "04:4B:ED": "Apple",
    "04:52:F3": "Apple",
    "04:54:53": "Apple",
    "04:69:F8": "Apple",
    "04:D3:CF": "Apple",
    "04:DB:56": "Apple",
    "04:E5:36": "Apple",
    "04:F1:3E": "Apple",
    "04:F7:E4": "Apple",
    "08:00:07": "Apple",
    "08:66:98": "Apple",
    "08:6D:41": "Apple",
    "08:70:45": "Apple",
    "08:74:02": "Apple",
    "08:F4:AB": "Apple",
    
    "00:25:86": "TP-Link Technologies Co., Ltd.",
    "00:1D:0F": "TP-Link Technologies Co., Ltd.",
    "14:CC:20": "TP-Link Technologies Co., Ltd.",
    "14:E6:E4": "TP-Link Technologies Co., Ltd.",
    "14:CF:E2": "TP-Link Technologies Co., Ltd.",
    "10:FE:ED": "TP-Link Technologies Co., Ltd.",

    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading Ltd",
    "E4:5F:01": "Raspberry Pi Trading Ltd",
    
    "00:50:56": "VMware, Inc.",
    "00:0C:29": "VMware, Inc.",
    "00:1C:14": "VMware, Inc.",
    
    "FC:FB:FB": "Ubiquiti Networks Inc.",
    "24:A4:3C": "Ubiquiti Networks",
    "00:15:6D": "Ubiquiti Networks Inc.",
    
    "18:FE:34": "Espressif Inc.",
    "24:0A:C4": "Espressif Inc.",
    "24:62:AB": "Espressif Inc.",
    "24:B2:DE": "Espressif Inc.",
    "30:AE:A4": "Espressif Inc.",
    "3C:61:05": "Espressif Inc.",
    "3C:71:BF": "Espressif Inc.",
    "40:91:51": "Espressif Inc.",
    "40:F5:20": "Espressif Inc.",
    "48:3F:DA": "Espressif Inc.",
    "4C:11:AE": "Espressif Inc.",
    "4C:EB:BD": "Espressif Inc.",
    "54:27:8D": "Espressif Inc.",
    "5C:CF:7F": "Espressif Inc.",
    "60:01:94": "Espressif Inc.",
    "68:C6:3A": "Espressif Inc.",
    "70:03:9F": "Espressif Inc.",
    "80:7D:3A": "Espressif Inc.",
    "84:0D:8E": "Espressif Inc.",
    "84:CC:A8": "Espressif Inc.",
    "84:F3:EB": "Espressif Inc.",
    "8C:CE:4E": "Espressif Inc.",
    "90:97:D5": "Espressif Inc.",
    "94:B5:55": "Espressif Inc.",
    "94:B9:7E": "Espressif Inc.",
    "98:F4:AB": "Espressif Inc.",
    "A0:20:A6": "Espressif Inc.",
    "A4:7B:9D": "Espressif Inc.",
    "A4:CF:12": "Espressif Inc.",
    "AC:D0:74": "Espressif Inc.",
    "B4:E6:2D": "Espressif Inc.",
    "BC:DD:C2": "Espressif Inc.",
    "C4:4F:33": "Espressif Inc.",
    "C8:2B:96": "Espressif Inc.",
    "CC:50:E3": "Espressif Inc.",
    "D8:A0:1D": "Espressif Inc.",
    "D8:BF:C0": "Espressif Inc.",
    "DC:4F:22": "Espressif Inc.",
    "EC:94:CB": "Espressif Inc.",
    "F0:08:D1": "Espressif Inc.",
}

def get_vendor_from_mac(mac_address):
    """
    Get vendor information from MAC address.
    
    Args:
        mac_address: MAC address string
    
    Returns:
        Vendor name or None if unknown
    """
    if not mac_address:
        return None
    
    # Normalize MAC address
    mac = mac_address.upper().replace(':', '').replace('-', '').replace('.', '')
    
    # Check the first 6 characters (OUI)
    oui = ':'.join([mac[i:i+2] for i in range(0, 6, 2)])
    
    return MAC_VENDORS.get(oui)

def identify_devices(packet_data):
    """
    Identify devices from network traffic.
    
    Args:
        packet_data: DataFrame with packet information
    
    Returns:
        List of identified devices
    """
    # Check if we have data
    if packet_data.empty:
        return []
    
    current_time = datetime.now()
    devices = []
    
    # Prepare device data by combining src_mac and dst_mac
    device_data = {}
    
    # Process source MAC addresses
    if 'src_mac' in packet_data.columns:
        src_data = packet_data[['src_mac', 'src_ip', 'length', 'hostname']].dropna(subset=['src_mac'])
        
        for _, row in src_data.iterrows():
            mac = row['src_mac']
            
            if mac not in device_data:
                device_data[mac] = {
                    'mac': mac,
                    'ip': set(),
                    'hostname': set(),
                    'first_seen': current_time,
                    'last_seen': current_time,
                    'packets': 0,
                    'bytes': 0,
                    'vendor': get_vendor_from_mac(mac)
                }
            
            # Update device data
            device_data[mac]['last_seen'] = current_time
            device_data[mac]['packets'] += 1
            device_data[mac]['bytes'] += row['length']
            
            if pd.notna(row['src_ip']):
                device_data[mac]['ip'].add(row['src_ip'])
            
            if pd.notna(row['hostname']) and row['hostname']:
                device_data[mac]['hostname'].add(row['hostname'])
    
    # Process destination MAC addresses
    if 'dst_mac' in packet_data.columns:
        dst_data = packet_data[['dst_mac', 'dst_ip', 'length', 'hostname']].dropna(subset=['dst_mac'])
        
        for _, row in dst_data.iterrows():
            mac = row['dst_mac']
            
            if mac not in device_data:
                device_data[mac] = {
                    'mac': mac,
                    'ip': set(),
                    'hostname': set(),
                    'first_seen': current_time,
                    'last_seen': current_time,
                    'packets': 0,
                    'bytes': 0,
                    'vendor': get_vendor_from_mac(mac)
                }
            
            # Update device data
            device_data[mac]['last_seen'] = current_time
            device_data[mac]['packets'] += 1
            device_data[mac]['bytes'] += row['length']
            
            if pd.notna(row['dst_ip']):
                device_data[mac]['ip'].add(row['dst_ip'])
            
            if pd.notna(row['hostname']) and row['hostname']:
                device_data[mac]['hostname'].add(row['hostname'])
    
    # Convert device data to list of dicts for return
    for mac, data in device_data.items():
        # Skip broadcast or multicast MAC addresses
        if mac.lower().startswith(('ff:ff:ff:ff:ff:ff', '01:00:5e')):
            continue
        
        # Convert sets to strings
        ip_list = list(data['ip'])
        hostname_list = list(data['hostname'])
        
        device = {
            'mac': mac,
            'ip': ', '.join(ip_list) if ip_list else None,
            'hostname': next(iter(hostname_list), None) if hostname_list else None,
            'vendor': data['vendor'],
            'first_seen': data['first_seen'],
            'last_seen': data['last_seen'],
            'packets': data['packets'],
            'bytes': data['bytes']
        }
        
        devices.append(device)
    
    return devices
