import pandas as pd
import numpy as np
from datetime import datetime, timedelta

class AnomalyDetector:
    """
    Class to detect anomalies in network traffic data
    """
    
    def __init__(self):
        """
        Initialize the anomaly detector
        """
        self.baseline = None
        self.last_update = None
        self.window_size = 30  # seconds for moving window
        self.history = []
    
    def update_baseline(self, df):
        """
        Update the baseline statistics from the dataframe
        
        Args:
            df (pandas.DataFrame): Dataframe containing packet data
        """
        if 'timestamp' not in df.columns or df.empty:
            return
            
        # Update the history with new data
        for _, row in df.iterrows():
            self.history.append({
                'timestamp': row['timestamp'],
                'size': row['size'] if 'size' in row else 0,
                'protocol': row['protocol'] if 'protocol' in row else 'Unknown'
            })
        
        # Remove old entries beyond window size
        current_time = datetime.now()
        self.history = [entry for entry in self.history 
                       if current_time - entry['timestamp'] < timedelta(seconds=self.window_size)]
        
        # Calculate baseline statistics
        if self.history:
            df_history = pd.DataFrame(self.history)
            
            # Calculate per-second traffic metrics
            df_history['timestamp_round'] = df_history['timestamp'].dt.floor('S')
            traffic_by_second = df_history.groupby('timestamp_round').agg({
                'size': ['count', 'sum', 'mean', 'std']
            })
            
            # Flatten the multi-index
            traffic_by_second.columns = ['count', 'total_bytes', 'mean_size', 'std_size']
            
            # Calculate protocol distribution
            protocol_counts = df_history['protocol'].value_counts(normalize=True)
            
            self.baseline = {
                'packets_per_second': {
                    'mean': traffic_by_second['count'].mean(),
                    'std': traffic_by_second['count'].std() if len(traffic_by_second) > 1 else 0,
                    'max': traffic_by_second['count'].max()
                },
                'bytes_per_second': {
                    'mean': traffic_by_second['total_bytes'].mean(),
                    'std': traffic_by_second['total_bytes'].std() if len(traffic_by_second) > 1 else 0,
                    'max': traffic_by_second['total_bytes'].max()
                },
                'packet_size': {
                    'mean': df_history['size'].mean(),
                    'std': df_history['size'].std() if len(df_history) > 1 else 0
                },
                'protocol_distribution': protocol_counts.to_dict()
            }
            
            self.last_update = current_time
    
    def detect_anomalies(self, df, threshold_multiplier=2.0):
        """
        Detect anomalies in the provided dataframe
        
        Args:
            df (pandas.DataFrame): Dataframe containing packet data
            threshold_multiplier (float): Multiplier for the standard deviation threshold
            
        Returns:
            list: List of detected anomalies
        """
        # First update the baseline
        self.update_baseline(df)
        
        if not self.baseline or df.empty:
            return []
        
        anomalies = []
        
        # Check for volume-based anomalies (packets per second)
        if 'timestamp' in df.columns:
            df['timestamp_round'] = df['timestamp'].dt.floor('S')
            current_traffic = df.groupby('timestamp_round').size()
            
            # Calculate thresholds
            pps_threshold = self.baseline['packets_per_second']['mean'] + \
                           (threshold_multiplier * self.baseline['packets_per_second']['std'])
            
            # Find seconds with traffic above threshold
            for timestamp, count in current_traffic.items():
                if count > max(pps_threshold, 3 * self.baseline['packets_per_second']['mean']):
                    anomalies.append({
                        'timestamp': timestamp,
                        'type': 'high_traffic_volume',
                        'value': count,
                        'threshold': pps_threshold,
                        'description': f'Traffic spike: {count} packets/sec (threshold: {pps_threshold:.2f})'
                    })
        
        # Check for unusual protocols
        if 'protocol' in df.columns and self.baseline['protocol_distribution']:
            protocol_counts = df['protocol'].value_counts(normalize=True)
            
            for protocol, ratio in protocol_counts.items():
                baseline_ratio = self.baseline['protocol_distribution'].get(protocol, 0.01)
                
                # Check if the protocol ratio is significantly higher than baseline
                if ratio > 3 * baseline_ratio and ratio > 0.1:  # At least 10% of traffic
                    anomalies.append({
                        'timestamp': df['timestamp'].max() if 'timestamp' in df.columns else datetime.now(),
                        'type': 'unusual_protocol_ratio',
                        'protocol': protocol,
                        'value': ratio,
                        'baseline': baseline_ratio,
                        'description': f'Unusual {protocol} traffic: {ratio*100:.1f}% (baseline: {baseline_ratio*100:.1f}%)'
                    })
        
        # Check for connections to unusual destinations
        if 'dst' in df.columns and len(df) > 10:
            # Get destination frequency
            dst_counts = df['dst'].value_counts(normalize=True)
            
            # Look for destinations that are very common in the current sample
            for dst, ratio in dst_counts.items():
                if ratio > 0.5:  # More than 50% of traffic goes to one destination
                    anomalies.append({
                        'timestamp': df['timestamp'].max() if 'timestamp' in df.columns else datetime.now(),
                        'type': 'unusual_destination',
                        'destination': dst,
                        'value': ratio,
                        'description': f'High traffic to single destination {dst}: {ratio*100:.1f}% of packets'
                    })
        
        # Deduplicate anomalies of the same type
        unique_anomalies = []
        seen_types = set()
        
        for anomaly in anomalies:
            key = (anomaly['type'], 
                  anomaly.get('protocol', ''), 
                  anomaly.get('destination', ''))
            if key not in seen_types:
                seen_types.add(key)
                unique_anomalies.append(anomaly)
        
        return unique_anomalies
