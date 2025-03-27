import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import networkx as nx
from datetime import datetime, timedelta
import matplotlib.dates as mdates
from matplotlib.colors import to_rgba

class Visualizer:
    """
    Class for visualizing network traffic data
    """
    
    def __init__(self):
        """
        Initialize the visualizer
        """
        # Set style parameters
        plt.style.use('ggplot')
        
    def generate_visualization(self, df, viz_type):
        """
        Generate a visualization based on the given dataframe and type
        
        Args:
            df (pandas.DataFrame): Dataframe containing packet data
            viz_type (str): Type of visualization to generate
            
        Returns:
            matplotlib.figure.Figure: The generated visualization figure
        """
        if viz_type == "Traffic Volume":
            return self.visualize_traffic_volume(df)
        elif viz_type == "Protocol Distribution":
            return self.visualize_protocol_distribution(df)
        elif viz_type == "Source/Destination":
            return self.visualize_source_destination(df)
        elif viz_type == "Network Graph":
            return self.generate_network_graph(df)
        elif viz_type == "Packet Size Distribution":
            return self.visualize_packet_size_distribution(df)
        else:
            # Default visualization
            return self.visualize_traffic_volume(df)
    
    def visualize_traffic_volume(self, df):
        """
        Visualize network traffic volume over time
        
        Args:
            df (pandas.DataFrame): Dataframe containing packet data
            
        Returns:
            matplotlib.figure.Figure: The generated visualization figure
        """
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Create a time series with packet counts
        if 'timestamp' in df.columns:
            # Group by timestamp (rounded to seconds)
            df['timestamp_round'] = df['timestamp'].dt.floor('S')
            traffic_by_time = df.groupby('timestamp_round').size()
            
            # Create a continuous time series with all seconds
            if len(traffic_by_time) > 1:
                min_time = traffic_by_time.index.min()
                max_time = traffic_by_time.index.max()
                all_seconds = pd.date_range(start=min_time, end=max_time, freq='S')
                traffic_by_time = traffic_by_time.reindex(all_seconds, fill_value=0)
            
            # Plot time series
            ax.plot(traffic_by_time.index, traffic_by_time.values, linewidth=2)
            ax.set_title('Network Traffic Volume Over Time')
            ax.set_xlabel('Time')
            ax.set_ylabel('Packets per Second')
            ax.grid(True)
            
            # Format x-axis to show time
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            plt.xticks(rotation=45)
            
            # Add moving average if we have enough data points
            if len(traffic_by_time) > 5:
                window_size = min(5, len(traffic_by_time) // 2)
                moving_avg = traffic_by_time.rolling(window=window_size).mean()
                ax.plot(moving_avg.index, moving_avg.values, 'r--', linewidth=1.5, 
                        label=f'{window_size}-second Moving Average')
                ax.legend()
        else:
            ax.text(0.5, 0.5, 'No timestamp data available', 
                   horizontalalignment='center', verticalalignment='center', transform=ax.transAxes)
        
        plt.tight_layout()
        return fig
    
    def visualize_protocol_distribution(self, df):
        """
        Visualize distribution of protocols in the network traffic
        
        Args:
            df (pandas.DataFrame): Dataframe containing packet data
            
        Returns:
            matplotlib.figure.Figure: The generated visualization figure
        """
        fig, ax = plt.subplots(figsize=(10, 6))
        
        if 'protocol' in df.columns:
            # Count packets by protocol
            protocol_counts = df['protocol'].value_counts()
            
            # Create pie chart
            ax.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%',
                   shadow=False, startangle=90)
            ax.set_title('Protocol Distribution')
            ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
        else:
            ax.text(0.5, 0.5, 'No protocol data available', 
                   horizontalalignment='center', verticalalignment='center', transform=ax.transAxes)
        
        plt.tight_layout()
        return fig
    
    def visualize_source_destination(self, df):
        """
        Visualize top sources and destinations
        
        Args:
            df (pandas.DataFrame): Dataframe containing packet data
            
        Returns:
            matplotlib.figure.Figure: The generated visualization figure
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))
        
        if 'src' in df.columns and 'dst' in df.columns:
            # Top sources
            src_counts = df['src'].value_counts().head(5)
            ax1.barh(src_counts.index, src_counts.values)
            ax1.set_title('Top 5 Source IP Addresses')
            ax1.set_xlabel('Packet Count')
            
            # Top destinations
            dst_counts = df['dst'].value_counts().head(5)
            ax2.barh(dst_counts.index, dst_counts.values)
            ax2.set_title('Top 5 Destination IP Addresses')
            ax2.set_xlabel('Packet Count')
        else:
            ax1.text(0.5, 0.5, 'No source/destination data available', 
                    horizontalalignment='center', verticalalignment='center', transform=ax1.transAxes)
            ax2.text(0.5, 0.5, 'No source/destination data available', 
                    horizontalalignment='center', verticalalignment='center', transform=ax2.transAxes)
        
        plt.tight_layout()
        return fig
    
    def generate_network_graph(self, df):
        """
        Generate a network graph visualization
        
        Args:
            df (pandas.DataFrame): Dataframe containing packet data
            
        Returns:
            matplotlib.figure.Figure: The generated visualization figure
        """
        fig, ax = plt.subplots(figsize=(10, 8))
        
        if 'src' in df.columns and 'dst' in df.columns:
            # Create a network graph
            G = nx.DiGraph()
            
            # Add edges for each packet (source -> destination)
            for _, row in df.iterrows():
                if pd.notna(row['src']) and pd.notna(row['dst']):
                    src = row['src']
                    dst = row['dst']
                    
                    # Add the edge or increment the weight if it exists
                    if G.has_edge(src, dst):
                        G[src][dst]['weight'] += 1
                    else:
                        G.add_edge(src, dst, weight=1)
            
            # Limit to top connections for readability
            if len(G.edges) > 30:
                # Keep only the edges with highest weight
                edges_with_weights = [(u, v, d['weight']) for u, v, d in G.edges(data=True)]
                edges_with_weights.sort(key=lambda x: x[2], reverse=True)
                
                # Create a new graph with only the top edges
                top_edges = edges_with_weights[:30]
                G_small = nx.DiGraph()
                for u, v, w in top_edges:
                    G_small.add_edge(u, v, weight=w)
                G = G_small
            
            # Scale node sizes based on degree
            node_sizes = [300 * (G.degree(node) / max(G.degree(), key=lambda x: x[1])[1]) for node in G.nodes()]
            node_sizes = [max(50, size) for size in node_sizes]  # Minimum size
            
            # Scale edge widths based on weight
            edge_weights = [d['weight'] for u, v, d in G.edges(data=True)]
            if edge_weights:
                max_weight = max(edge_weights)
                edge_widths = [1 + 5 * (d['weight'] / max_weight) for u, v, d in G.edges(data=True)]
            else:
                edge_widths = [1]
            
            # Use spring layout for node positioning
            pos = nx.spring_layout(G, seed=42)
            
            # Draw the graph
            nx.draw_networkx_nodes(G, pos, node_size=node_sizes, node_color='skyblue', alpha=0.8, ax=ax)
            nx.draw_networkx_edges(G, pos, width=edge_widths, edge_color='gray', alpha=0.6, 
                                  connectionstyle='arc3,rad=0.1', arrows=True, arrowsize=15, ax=ax)
            
            # Add labels with smaller font
            nx.draw_networkx_labels(G, pos, font_size=8, font_family='sans-serif', ax=ax)
            
            ax.set_title('Network Communication Graph')
            ax.axis('off')
        else:
            ax.text(0.5, 0.5, 'No source/destination data available for graph', 
                   horizontalalignment='center', verticalalignment='center', transform=ax.transAxes)
        
        plt.tight_layout()
        return fig
    
    def visualize_packet_size_distribution(self, df):
        """
        Visualize the distribution of packet sizes
        
        Args:
            df (pandas.DataFrame): Dataframe containing packet data
            
        Returns:
            matplotlib.figure.Figure: The generated visualization figure
        """
        fig, ax = plt.subplots(figsize=(10, 6))
        
        if 'size' in df.columns:
            # Create histogram of packet sizes
            ax.hist(df['size'], bins=30, alpha=0.7, color='skyblue', edgecolor='black')
            ax.set_title('Packet Size Distribution')
            ax.set_xlabel('Packet Size (bytes)')
            ax.set_ylabel('Frequency')
            ax.grid(True, linestyle='--', alpha=0.7)
            
            # Add mean and median lines
            mean_size = df['size'].mean()
            median_size = df['size'].median()
            
            ax.axvline(mean_size, color='red', linestyle='--', linewidth=1,
                      label=f'Mean: {mean_size:.1f} bytes')
            ax.axvline(median_size, color='green', linestyle='-.', linewidth=1,
                      label=f'Median: {median_size:.1f} bytes')
            
            ax.legend()
        else:
            ax.text(0.5, 0.5, 'No packet size data available', 
                   horizontalalignment='center', verticalalignment='center', transform=ax.transAxes)
        
        plt.tight_layout()
        return fig
    
    def visualize_anomalies(self, df, anomalies):
        """
        Visualize traffic with anomalies highlighted
        
        Args:
            df (pandas.DataFrame): Dataframe containing packet data
            anomalies (list): List of anomaly dictionaries
            
        Returns:
            matplotlib.figure.Figure: The generated visualization figure
        """
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Create a time series with packet counts
        if 'timestamp' in df.columns:
            # Group by timestamp (rounded to seconds)
            df['timestamp_round'] = df['timestamp'].dt.floor('S')
            traffic_by_time = df.groupby('timestamp_round').size()
            
            # Create a continuous time series with all seconds
            if len(traffic_by_time) > 1:
                min_time = traffic_by_time.index.min()
                max_time = traffic_by_time.index.max()
                all_seconds = pd.date_range(start=min_time, end=max_time, freq='S')
                traffic_by_time = traffic_by_time.reindex(all_seconds, fill_value=0)
            
            # Plot time series
            ax.plot(traffic_by_time.index, traffic_by_time.values, linewidth=2, label='Traffic')
            
            # Highlight anomalies
            anomaly_times = []
            anomaly_values = []
            
            for anomaly in anomalies:
                if 'timestamp' in anomaly:
                    time_point = anomaly['timestamp'].floor('S')
                    if time_point in traffic_by_time.index:
                        anomaly_times.append(time_point)
                        anomaly_values.append(traffic_by_time.loc[time_point])
            
            if anomaly_times:
                ax.scatter(anomaly_times, anomaly_values, color='red', s=100, 
                          label='Anomalies', zorder=5)
            
            ax.set_title('Network Traffic with Anomalies')
            ax.set_xlabel('Time')
            ax.set_ylabel('Packets per Second')
            ax.grid(True)
            
            # Format x-axis to show time
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            plt.xticks(rotation=45)
            
            ax.legend()
        else:
            ax.text(0.5, 0.5, 'No timestamp data available', 
                   horizontalalignment='center', verticalalignment='center', transform=ax.transAxes)
        
        plt.tight_layout()
        return fig
