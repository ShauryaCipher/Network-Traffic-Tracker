import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import networkx as nx
from collections import Counter
from datetime import timedelta

def plot_traffic_over_time(packet_data, window='1min'):
    """
    Plot network traffic volume over time.
    
    Args:
        packet_data: DataFrame with packet information
        window: Time window for aggregation
        
    Returns:
        Matplotlib figure object
    """
    # Ensure we have data
    if packet_data.empty:
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.text(0.5, 0.5, "No data available", ha='center', va='center')
        return fig
    
    # Set the timestamp as index for resampling
    df = packet_data.copy()
    df.set_index('timestamp', inplace=True)
    
    # Resample the data by the specified window
    traffic_volume = df.resample(window).sum()['length']
    
    # Create the figure
    fig, ax = plt.subplots(figsize=(10, 4))
    
    # Convert bytes to kilobytes for better readability
    ax.plot(traffic_volume.index, traffic_volume / 1024, linewidth=2)
    
    # Add labels and title
    ax.set_xlabel('Time')
    ax.set_ylabel('Traffic Volume (KB)')
    ax.set_title(f'Network Traffic Volume Over Time (Window: {window})')
    
    # Format x-axis to show time properly
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    return fig

def plot_protocol_distribution(packet_data):
    """
    Create a pie chart showing the distribution of protocols.
    
    Args:
        packet_data: DataFrame with packet information
        
    Returns:
        Matplotlib figure object
    """
    # Check if we have data
    if packet_data.empty:
        fig, ax = plt.subplots()
        ax.text(0.5, 0.5, "No data available", ha='center', va='center')
        return fig
    
    # Count protocols
    protocol_counts = packet_data['protocol_name'].value_counts()
    
    # If there are too many protocols, group the less common ones
    if len(protocol_counts) > 5:
        top_protocols = protocol_counts.nlargest(4)
        others_sum = protocol_counts[4:].sum()
        protocol_counts = pd.concat([top_protocols, pd.Series({'Others': others_sum})])
    
    # Create the pie chart
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.pie(
        protocol_counts, 
        labels=protocol_counts.index, 
        autopct='%1.1f%%',
        startangle=90, 
        shadow=False,
        explode=[0.05] * len(protocol_counts)  # Slightly explode all slices
    )
    
    ax.set_title('Protocol Distribution')
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
    
    return fig

def plot_top_connections(packet_data, top_n=10):
    """
    Create a horizontal bar chart showing the top connections by data volume.
    
    Args:
        packet_data: DataFrame with packet information
        top_n: Number of top connections to display
        
    Returns:
        Matplotlib figure object
    """
    # Check if we have data
    if packet_data.empty or 'src_ip' not in packet_data.columns or 'dst_ip' not in packet_data.columns:
        fig, ax = plt.subplots()
        ax.text(0.5, 0.5, "No connection data available", ha='center', va='center')
        return fig
    
    # Create connection pairs and sum traffic
    df = packet_data.copy()
    
    # Filter out rows with missing IP addresses
    df = df.dropna(subset=['src_ip', 'dst_ip'])
    
    # Create connection strings and group by them
    df['connection'] = df.apply(
        lambda row: f"{row['src_ip']} → {row['dst_ip']}", 
        axis=1
    )
    
    # Sum bytes by connection
    connection_volume = df.groupby('connection')['length'].sum().sort_values(ascending=False)
    
    # Get top N connections
    top_connections = connection_volume.head(top_n)
    
    # Create the horizontal bar chart
    fig, ax = plt.subplots(figsize=(10, max(4, top_n * 0.4)))
    
    # Plot bars
    bars = ax.barh(
        top_connections.index, 
        top_connections.values / 1024,  # Convert to KB
        color='skyblue',
        edgecolor='navy'
    )
    
    # Add labels and title
    ax.set_xlabel('Data Volume (KB)')
    ax.set_title(f'Top {top_n} Connections by Data Volume')
    
    # Add value labels on the bars
    for bar in bars:
        width = bar.get_width()
        label_x_pos = width + 0.5
        ax.text(label_x_pos, bar.get_y() + bar.get_height()/2, f'{width:.1f} KB',
                va='center')
    
    # Tight layout to ensure everything fits
    plt.tight_layout()
    
    return fig

def create_network_graph(packet_data, max_connections=30):
    """
    Create a network graph visualization showing connections between hosts.
    
    Args:
        packet_data: DataFrame with packet information
        max_connections: Maximum number of connections to display
        
    Returns:
        Matplotlib figure object
    """
    # Check if we have data
    if packet_data.empty or 'src_ip' not in packet_data.columns or 'dst_ip' not in packet_data.columns:
        fig, ax = plt.subplots()
        ax.text(0.5, 0.5, "No connection data available", ha='center', va='center')
        return fig
    
    # Create a DataFrame for connections
    df = packet_data.copy()
    
    # Filter out rows with missing IP addresses
    df = df.dropna(subset=['src_ip', 'dst_ip'])
    
    # Create tuples of (src_ip, dst_ip) and count occurrences
    connections = list(zip(df['src_ip'], df['dst_ip']))
    connection_counts = Counter(connections)
    
    # Get the top connections
    top_connections = connection_counts.most_common(max_connections)
    
    # Create a network graph
    G = nx.DiGraph()
    
    # Add edges (connections) to the graph with weight based on count
    max_weight = max(count for _, count in top_connections) if top_connections else 1
    
    # Get all unique IPs from the top connections
    all_ips = set()
    for (src, dst), _ in top_connections:
        all_ips.add(src)
        all_ips.add(dst)
    
    # Add nodes (IPs) to the graph
    for ip in all_ips:
        G.add_node(ip)
    
    # Add weighted edges
    for (src, dst), count in top_connections:
        # Normalize weight for visualization
        weight = (count / max_weight) * 3
        G.add_edge(src, dst, weight=weight)
    
    # Create figure
    fig, ax = plt.subplots(figsize=(12, 10))
    
    # Use spring layout for node positioning
    pos = nx.spring_layout(G, k=0.3, iterations=50)
    
    # Get edge weights for line thickness
    edge_weights = [G[u][v]['weight'] for u, v in G.edges()]
    
    # Calculate node sizes based on degree
    node_sizes = [300 * (1 + G.degree(node) / 10) for node in G.nodes()]
    
    # Draw the network elements
    nx.draw_networkx_nodes(G, pos, ax=ax, node_size=node_sizes, node_color='skyblue', alpha=0.8)
    nx.draw_networkx_edges(G, pos, ax=ax, width=edge_weights, alpha=0.5, edge_color='gray', arrows=True, arrowsize=15)
    nx.draw_networkx_labels(G, pos, ax=ax, font_size=8, font_family='sans-serif')
    
    # Set title
    ax.set_title('Network Communication Graph')
    ax.axis('off')
    
    plt.tight_layout()
    
    return fig
