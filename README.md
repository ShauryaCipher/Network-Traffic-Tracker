# Network Traffic Analyzer

A comprehensive network traffic visualization and analysis tool with both a desktop application and web interface. This tool helps security professionals and network administrators monitor network traffic, detect anomalies, and identify unauthorized access.

![Network Analyzer Screenshot](https://via.placeholder.com/800x450.png?text=Network+Traffic+Analyzer)

## 🌟 Features

- **Dual Interface**: Modern desktop app built with CustomTkinter AND web interface with Streamlit
- **Live Traffic Capture**: Monitor network traffic in real-time using kamene (formerly scapy-python3)
- **Rich Visualizations**: See traffic patterns with interactive charts and graphs
- **Network Mapping**: Interactive network graphs showing connections between hosts
- **Anomaly Detection**: Identify unusual traffic patterns and potential security threats
- **Device Identification**: Discover and monitor devices on your network
- **Protocol Analysis**: Analyze traffic distribution by protocol
- **Easy Installation**: Simple setup with both pip and executable options

## 📋 Requirements

- Python 3.8+
- Administrator/root privileges (required for packet capture)
- Supported OS: Windows, macOS, Linux
- Required packages: customtkinter, pandas, matplotlib, networkx, kamene, psutil

## 🔧 Installation

### Option 1: Download and Run the Executable (Easiest)

1. Download the NetworkTrafficAnalyzer_Executable.zip file from the `/dist` directory
2. Extract the ZIP file to a directory of your choice
3. Run the executable with administrator/root privileges:
   - **Windows**: Right-click NetworkTrafficAnalyzer.exe and select "Run as Administrator"
   - **Linux/Mac**: Use `sudo ./NetworkTrafficAnalyzer`

### Option 2: Download and Run the Package

1. Download the NetworkTrafficAnalyzer.zip file from the `/dist` directory
2. Extract the ZIP file to a directory of your choice
3. Install the required dependencies:
   ```
   pip install customtkinter pandas matplotlib networkx kamene psutil
   ```
4. Run the application with administrator/root privileges:
   - **Windows**: Run the included `run_analyzer.bat` as Administrator
   - **Linux/Mac**: Use `sudo ./run_analyzer.sh`

### Option 3: Build the Package from Source

1. Make sure all dependencies are installed
   ```
   pip install customtkinter pandas matplotlib networkx kamene psutil
   ```

2. Run the build script to create a distributable package
   ```
   python build.py
   ```

3. The package will be created in the `/dist` directory
   
4. Run the desktop application directly:
   ```
   python desktop_app.py
   ```

### Option 4: Build the Executable from Source

1. Make sure all dependencies are installed
   ```
   pip install customtkinter pandas matplotlib networkx kamene psutil pyinstaller
   ```

2. Run the executable build script
   ```
   python build_exe.py
   ```

3. The executable will be created in the `/dist` directory

### Option 5: Web Interface

1. Install dependencies
   ```
   pip install streamlit pandas matplotlib networkx kamene
   ```
2. Run the Streamlit app with administrator/root privileges
   ```
   sudo streamlit run app.py
   ```
3. Open your browser and navigate to http://localhost:5000

## ⚙️ Usage

### Desktop Application

1. Run the application with administrator/root privileges
2. Select the network interface to monitor
3. Configure capture filters if needed
4. Click "Start Capture" to begin monitoring
5. Use the different tabs to view various analyses:
   - **Overview**: General traffic statistics and protocol distribution
   - **Network Graph**: Visual representation of connections between hosts
   - **Anomalies**: Detected unusual network behavior
   - **Devices**: Connected devices and their information

### Web Interface

The web interface provides similar functionality to the desktop app with a different layout optimized for browser viewing.

## 🔐 Administrator/Root Privileges

Network packet capture requires elevated privileges on most operating systems. If no packets are being captured, make sure you're running the application with administrator (Windows) or root (macOS/Linux) privileges.

## 📊 Analyzing Traffic

- **Traffic Spikes**: Sudden increases in traffic volume may indicate data exfiltration, DDoS attacks, or malware activity
- **Port Scans**: Attempts to connect to multiple ports may indicate reconnaissance activity
- **Unusual Protocols**: Unexpected protocol usage could indicate tunneling or covert channels
- **New Devices**: Unknown devices appearing on your network may represent unauthorized access

## 🛠️ Advanced Configuration

### BPF Filters

The application supports Berkeley Packet Filter (BPF) syntax for targeted capture. Examples:

- `tcp`: Capture only TCP traffic
- `port 80 or port 443`: HTTP and HTTPS traffic only
- `host 192.168.1.1`: Traffic to/from a specific IP
- `tcp port 22`: SSH traffic

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🚀 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

