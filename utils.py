import os
import socket
import subprocess
import platform
from kamene.all import get_if_list, conf

def check_root_privileges():
    """
    Check if the application is running with root/admin privileges
    
    Returns:
        bool: True if running with root privileges, False otherwise
    """
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows does not have geteuid, try a different approach
        try:
            return os.environ.get('SUDO_USER') is not None or platform.system() == 'Windows'
        except:
            return False

def get_available_interfaces():
    """
    Get a list of available network interfaces
    
    Returns:
        list: List of available network interfaces
    """
    try:
        # Try to use Scapy's get_if_list
        interfaces = get_if_list()
        
        # Remove loopback interface on Linux/Mac
        if 'lo' in interfaces:
            interfaces.remove('lo')
            
        # If no interfaces found, try platform-specific commands
        if not interfaces:
            system = platform.system()
            if system == 'Linux':
                # Try using ip command
                try:
                    cmd_output = subprocess.check_output(['ip', 'link', 'show'], universal_newlines=True)
                    for line in cmd_output.split('\n'):
                        if ': ' in line:
                            interface = line.split(': ')[1]
                            if interface != 'lo' and interface not in interfaces:
                                interfaces.append(interface)
                except:
                    pass
            elif system == 'Darwin':  # macOS
                try:
                    cmd_output = subprocess.check_output(['ifconfig'], universal_newlines=True)
                    for line in cmd_output.split('\n'):
                        if line.startswith('\t') or line.startswith(' '):
                            continue
                        if ':' in line:
                            interface = line.split(':')[0]
                            if interface != 'lo0' and interface not in interfaces:
                                interfaces.append(interface)
                except:
                    pass
            elif system == 'Windows':
                try:
                    # On Windows, kamene uses interface names that are difficult to read
                    # Try to get more readable names
                    from kamene.arch.windows import IFACES
                    interfaces = []
                    for i in IFACES.keys():
                        # Use description if available, otherwise use the name
                        if 'description' in IFACES[i]:
                            interfaces.append(IFACES[i]['description'])
                        elif 'name' in IFACES[i]:
                            interfaces.append(IFACES[i]['name'])
                except:
                    # Fall back to kamene's interfaces
                    pass
        
        return interfaces if interfaces else ['eth0', 'wlan0']  # Fallback to common interfaces
    except Exception as e:
        print(f"Error getting network interfaces: {e}")
        return ['eth0', 'wlan0']  # Return common interface names as fallback

def format_bytes(size):
    """
    Format bytes to human-readable string
    
    Args:
        size (int): Size in bytes
        
    Returns:
        str: Formatted string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"

def is_valid_ip(ip):
    """
    Check if the given string is a valid IP address
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        socket.inet_aton(ip)
        return True
    except:
        return False

def get_local_ip():
    """
    Get the local IP address of the machine
    
    Returns:
        str: Local IP address
    """
    try:
        # Create a socket connection to a public address
        # This doesn't actually send any data
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"  # Fallback to localhost
