#!/usr/bin/env python3
"""
Build script for creating a standalone executable for Network Traffic Analyzer.
This script uses PyInstaller to create a self-contained executable file.
"""

import os
import sys
import platform
import subprocess
import shutil
import datetime

def build_executable():
    """Build the executable for Network Traffic Analyzer"""
    print("Building Network Traffic Analyzer executable...")
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print(f"Using PyInstaller version {PyInstaller.__version__}")
    except ImportError:
        print("PyInstaller is not installed. Installing...")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyinstaller'])
            print("PyInstaller installed successfully.")
        except Exception as e:
            print(f"Failed to install PyInstaller: {e}")
            print("Please install PyInstaller manually with: pip install pyinstaller")
            return
    
    # Create output directories
    dist_dir = "dist"
    if not os.path.exists(dist_dir):
        os.makedirs(dist_dir)
    
    # Build date for file naming
    build_date = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Files we need to include (they'll be auto-detected by PyInstaller)
    required_files = [
        "desktop_app.py",
        "network_capture.py",
        "visualization.py",
        "anomaly_detection.py",
        "device_identification.py",
        "device_tracker.py",
        "data_processor.py",
        "utils.py"
    ]
    
    # Check if all required files exist
    missing_files = [f for f in required_files if not os.path.exists(f)]
    if missing_files:
        print(f"Error: Missing required files: {', '.join(missing_files)}")
        print("Please make sure all required files are in the current directory.")
        return
    
    # Determine icon file based on platform
    icon_file = None
    if os.path.exists("icons/app_icon.ico"):
        icon_file = "icons/app_icon.ico"
    elif os.path.exists("icons/app_icon.icns"):
        icon_file = "icons/app_icon.icns"
    
    # Create PyInstaller command
    cmd = [
        'pyinstaller',
        '--clean',
        '--name=NetworkTrafficAnalyzer',
        '--onefile',  # Create a single executable file
        '--console',  # Show console window (needed for packet capture)
        '--hidden-import=kamene.all',
        '--hidden-import=matplotlib.backends.backend_tkagg',
    ]
    
    # Add icon if available
    if icon_file:
        cmd.append(f'--icon={icon_file}')
    
    # Add main script
    cmd.append('desktop_app.py')
    
    # Run PyInstaller
    print(f"Running PyInstaller with command: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
        
        # Check if executable was created
        if platform.system() == "Windows":
            exe_path = os.path.join("dist", "NetworkTrafficAnalyzer.exe")
        else:
            exe_path = os.path.join("dist", "NetworkTrafficAnalyzer")
            
        if os.path.exists(exe_path):
            print(f"\nExecutable created successfully: {exe_path}")
            
            # Create README file
            readme_path = os.path.join("dist", "README.txt")
            with open(readme_path, "w") as f:
                f.write("Network Traffic Analyzer\n")
                f.write("=======================\n\n")
                f.write("This is a standalone executable for the Network Traffic Analyzer application.\n\n")
                f.write("Important Notes:\n")
                f.write("- This application requires administrator/root privileges for packet capture.\n")
                f.write("- On Windows: Right-click the executable and select 'Run as Administrator'\n")
                f.write("- On Linux/Mac: Run with sudo\n\n")
                f.write("Features:\n")
                f.write("- Capture and analyze network traffic in real-time\n")
                f.write("- Visualize network connections and protocol distribution\n")
                f.write("- Detect anomalies and potential security threats\n")
                f.write("- Identify devices on your network\n\n")
            
            # Create a zip file
            zip_filename = f"NetworkTrafficAnalyzer_Executable_{build_date}.zip"
            zip_path = os.path.join(dist_dir, zip_filename)
            
            print(f"Creating zip file with executable: {zip_path}")
            
            # Create a temporary directory for zip contents
            zip_dir = os.path.join("dist", "zip_contents")
            if os.path.exists(zip_dir):
                shutil.rmtree(zip_dir)
            os.makedirs(zip_dir)
            
            # Copy files to zip directory
            shutil.copy2(exe_path, zip_dir)
            shutil.copy2(readme_path, zip_dir)
            
            # Create the zip file
            shutil.make_archive(os.path.splitext(zip_path)[0], 'zip', zip_dir)
            
            print(f"Success! Executable zip file created: {zip_path}")
            print("\nThe zip file contains:")
            print(f"- The standalone executable ({os.path.basename(exe_path)})")
            print("- README.txt with usage instructions")
            print("\nNote: The executable requires administrator/root privileges for packet capture.")
            
            # Clean up
            shutil.rmtree(zip_dir, ignore_errors=True)
        else:
            print(f"Error: Executable not found at {exe_path}")
            print("PyInstaller may have failed to create the executable.")
    except Exception as e:
        print(f"Error building executable: {e}")

if __name__ == "__main__":
    build_executable()