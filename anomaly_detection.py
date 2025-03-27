import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, deque

class TrafficStatistics:
    """
    Class to maintain statistics about network traffic for anomaly detection.
    """
    def __init__(self, window_size=60):
        # Window size in seconds
        self.window_size = window_size
        
        # Traffic volume time series
        self.traffic_time_series = deque(maxlen=1000)  # Store up to 1000 data points
        
        # Traffic by protocol
        self.protocol_stats = {}
        
        # Traffic by IP
        self.ip_stats = defaultdict(lambda: {'bytes_sent': 0, 'bytes_received': 0, 'packets_sent': 0, 'packets_received': 0})
        
        # Port scan detection
        self.port_scan_tracking = defaultdict(lambda: {'ports': set(), 'last_reset': datetime.now()})
        
        # Statistics for baselines
        self.total_bytes = 0
        self.total_packets = 0
        self.start_time = datetime.now()
        
        # Traffic rate statistics
        self.traffic_rates = []
        
        # Last update time
        self.last_update = datetime.now()
    
    def update(self, new_data):
        """
        Update statistics with new packet data.
        
        Args:
            new_data: DataFrame with new packet information
        """
        # Skip if no data
        if new_data.empty:
            return
        
        # Get current time
        current_time = datetime.now()
        
        # Calculate time difference since last update
        time_diff = (current_time - self.last_update).total_seconds()
        self.last_update = current_time
        
        # Update traffic time series
        bytes_per_sec = new_data['length'].sum() / max(time_diff, 1)
        self.traffic_time_series.append({
            'timestamp': current_time,
            'bytes_per_sec': bytes_per_sec
        })
        
        # Update traffic rates for anomaly detection
        self.traffic_rates.append(bytes_per_sec)
        if len(self.traffic_rates) > 100:  # Keep only last 100 rates
            self.traffic_rates = self.traffic_rates[-100:]
        
        # Update protocol statistics
        for protocol, group in new_data.groupby('protocol_name'):
            if protocol not in self.protocol_stats:
                self.protocol_stats[protocol] = {'bytes': 0, 'packets': 0}
            
            self.protocol_stats[protocol]['bytes'] += group['length'].sum()
            self.protocol_stats[protocol]['packets'] += len(group)
        
        # Update IP statistics and check for port scans
        for _, row in new_data.iterrows():
            src_ip = row.get('src_ip')
            dst_ip = row.get('dst_ip')
            src_port = row.get('src_port')
            dst_port = row.get('dst_port')
            length = row.get('length', 0)
            
            # Update source IP stats
            if src_ip:
                self.ip_stats[src_ip]['bytes_sent'] += length
                self.ip_stats[src_ip]['packets_sent'] += 1
            
            # Update destination IP stats
            if dst_ip:
                self.ip_stats[dst_ip]['bytes_received'] += length
                self.ip_stats[dst_ip]['packets_received'] += 1
            
            # Track potential port scans
            if src_ip and dst_ip and dst_port:
                # Reset port tracking if more than window_size seconds have passed
                if (current_time - self.port_scan_tracking[src_ip]['last_reset']).total_seconds() > self.window_size:
                    self.port_scan_tracking[src_ip]['ports'] = set()
                    self.port_scan_tracking[src_ip]['last_reset'] = current_time
                
                # Add the destination port to the set of ports this IP has tried
                self.port_scan_tracking[src_ip]['ports'].add((dst_ip, dst_port))
        
        # Update overall statistics
        self.total_bytes += new_data['length'].sum()
        self.total_packets += len(new_data)
    
    def get_traffic_time_series(self):
        """
        Get the traffic time series as a DataFrame.
        
        Returns:
            DataFrame with timestamp and bytes_per_sec columns
        """
        return pd.DataFrame(list(self.traffic_time_series))
    
    def get_average_traffic_rate(self):
        """
        Get the average traffic rate in bytes per second.
        
        Returns:
            Average traffic rate
        """
        if not self.traffic_rates:
            return 0
        return sum(self.traffic_rates) / len(self.traffic_rates)
    
    def get_traffic_rate_stddev(self):
        """
        Get the standard deviation of traffic rates.
        
        Returns:
            Standard deviation of traffic rates
        """
        if len(self.traffic_rates) < 2:
            return 0
        return np.std(self.traffic_rates)
    
    def get_potential_port_scanners(self, threshold=20):
        """
        Get IPs that might be conducting port scans.
        
        Args:
            threshold: Minimum number of unique ports tried in the window
            
        Returns:
            Dictionary mapping source IPs to number of unique ports tried
        """
        scanners = {}
        for ip, data in self.port_scan_tracking.items():
            if len(data['ports']) >= threshold:
                scanners[ip] = len(data['ports'])
        return scanners

def detect_anomalies(new_data, traffic_stats, traffic_threshold=3.0, port_scan_threshold=20):
    """
    Detect anomalies in network traffic.
    
    Args:
        new_data: DataFrame with new packet information
        traffic_stats: TrafficStatistics object
        traffic_threshold: Traffic spike threshold in standard deviations
        port_scan_threshold: Port scan detection threshold
        
    Returns:
        List of detected anomalies
    """
    anomalies = []
    current_time = datetime.now()
    
    # Skip if no data
    if new_data.empty:
        return anomalies
    
    # 1. Check for traffic volume spikes
    avg_rate = traffic_stats.get_average_traffic_rate()
    stddev = traffic_stats.get_traffic_rate_stddev()
    
    # Get the most recent traffic rate
    if traffic_stats.traffic_rates:
        latest_rate = traffic_stats.traffic_rates[-1]
        
        # If the latest rate exceeds the average by more than threshold * stddev
        if stddev > 0 and latest_rate > avg_rate + (traffic_threshold * stddev):
            # Check which IPs contributed most to this spike
            top_ips = new_data['src_ip'].value_counts().head(3).index.tolist()
            
            anomalies.append({
                'type': 'Traffic Volume Spike',
                'timestamp': current_time,
                'description': f'Traffic rate ({latest_rate:.2f} bytes/sec) exceeds normal levels by {traffic_threshold} standard deviations',
                'severity': 'Medium' if latest_rate > avg_rate + (2 * traffic_threshold * stddev) else 'Low',
                'ips': top_ips
            })
    
    # 2. Check for potential port scans
    port_scanners = traffic_stats.get_potential_port_scanners(threshold=port_scan_threshold)
    for ip, port_count in port_scanners.items():
        target_ips = set()
        for dst_ip, _ in traffic_stats.port_scan_tracking[ip]['ports']:
            target_ips.add(dst_ip)
        
        anomalies.append({
            'type': 'Potential Port Scan',
            'timestamp': current_time,
            'description': f'Host attempted to connect to {port_count} different ports across {len(target_ips)} hosts in the last {traffic_stats.window_size} seconds',
            'severity': 'High' if port_count > port_scan_threshold * 2 else 'Medium',
            'ips': [ip] + list(target_ips)[:3]  # Source IP + up to 3 target IPs
        })
    
    # 3. Check for unusual protocols
    unusual_protocols = set()
    for protocol, stats in traffic_stats.protocol_stats.items():
        # If this protocol hasn't been seen much but suddenly appears
        protocol_data = new_data[new_data['protocol_name'] == protocol]
        if not protocol_data.empty:
            protocol_bytes = protocol_data['length'].sum()
            total_bytes = new_data['length'].sum()
            protocol_ratio = protocol_bytes / total_bytes if total_bytes > 0 else 0
            
            # If this protocol makes up more than 20% of traffic and it's unusual
            if protocol_ratio > 0.2 and protocol not in ('TCP', 'UDP', 'ICMP', 'DNS', 'HTTP'):
                unusual_protocols.add(protocol)
    
    if unusual_protocols:
        anomalies.append({
            'type': 'Unusual Protocol Activity',
            'timestamp': current_time,
            'description': f'Detected unusual protocol activity: {", ".join(unusual_protocols)}',
            'severity': 'Low',
            'ips': new_data['src_ip'].value_counts().head(3).index.tolist()
        })
    
    # 4. Check for new hosts on the network
    # This would require historical data about known hosts, which we don't maintain yet
    
    return anomalies
