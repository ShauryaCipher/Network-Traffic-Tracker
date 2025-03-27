#!/usr/bin/env python3
"""
Build script for creating a distribution package for Network Traffic Analyzer.
This script creates a ZIP file with all necessary files to run the application.
"""

import os
import sys
import shutil
import datetime
import subprocess

def build_executable():
    """Build the executable for the current platform"""
    # Get the current script directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Create output directory if it doesn't exist
    dist_dir = os.path.join(current_dir, "dist")
    if not os.path.exists(dist_dir):
        os.makedirs(dist_dir)
    
    # Build date for naming
    build_date = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Required files to include in the package
    required_files = [
        "desktop_app.py",
        "network_capture.py",
        "visualization.py",
        "anomaly_detection.py",
        "device_identification.py",
        "device_tracker.py",
        "data_processor.py",
        "anomaly_detector.py",
        "utils.py",
        "visualizer.py",
        "README.md"
    ]
    
    # Check if all required files exist
    missing_files = [f for f in required_files if not os.path.exists(f)]
    if missing_files:
        print(f"Error: Missing required files: {', '.join(missing_files)}")
        print("Please make sure all required files are in the current directory.")
        return False
    
    # Create icons if they don't exist
    if not os.path.exists(os.path.join("icons", "app_icon.ico")):
        try:
            print("Generating application icons...")
            if not os.path.exists("icons"):
                os.makedirs("icons")
                
            # Generate icons using the icon generator script
            if os.path.exists("icons/generate_icons.py"):
                subprocess.run([sys.executable, "icons/generate_icons.py"], check=True)
            else:
                print("Warning: Icon generator script not found, skipping icon generation.")
        except Exception as e:
            print(f"Warning: Failed to generate icons: {e}")
    
    # Create a temporary build directory
    build_dir = os.path.join(current_dir, "build")
    if not os.path.exists(build_dir):
        os.makedirs(build_dir)
    
    # Clean build directory
    for item in os.listdir(build_dir):
        item_path = os.path.join(build_dir, item)
        if os.path.isfile(item_path):
            os.unlink(item_path)
        elif os.path.isdir(item_path) and item != "__pycache__":
            shutil.rmtree(item_path)
    
    # Copy all required files to build directory
    for file in required_files:
        if os.path.exists(file):
            shutil.copy2(file, build_dir)
    
    # Create icons directory in build
    build_icons_dir = os.path.join(build_dir, "icons")
    if not os.path.exists(build_icons_dir):
        os.makedirs(build_icons_dir)
    
    # Copy icon files to build directory
    if os.path.exists("icons"):
        for icon_file in os.listdir("icons"):
            if icon_file.endswith((".ico", ".icns", ".png")) and not icon_file.startswith("."):
                icon_path = os.path.join("icons", icon_file)
                if os.path.isfile(icon_path):
                    shutil.copy2(icon_path, build_icons_dir)
    
    # Create run scripts
    # Windows batch file
    with open(os.path.join(build_dir, "run_analyzer.bat"), "w") as f:
        f.write("@echo off\n")
        f.write("echo Starting Network Traffic Analyzer...\n")
        f.write("echo This application requires administrator privileges for packet capture.\n")
        f.write("echo If you're not seeing any traffic, please restart with administrator rights.\n")
        f.write("python desktop_app.py\n")
        f.write("pause\n")
    
    # Linux/Mac shell script
    with open(os.path.join(build_dir, "run_analyzer.sh"), "w") as f:
        f.write("#!/bin/bash\n")
        f.write("echo 'Starting Network Traffic Analyzer...'\n")
        f.write("echo 'This application requires root privileges for packet capture.'\n")
        f.write("echo 'If you are not seeing any traffic, please restart with sudo.'\n")
        f.write("python3 desktop_app.py\n")
    
    # Make shell script executable
    os.chmod(os.path.join(build_dir, "run_analyzer.sh"), 0o755)
    
    # Create installer README
    with open(os.path.join(build_dir, "README_INSTALLER.txt"), "w") as f:
        f.write("Network Traffic Analyzer\n")
        f.write("=======================\n\n")
        f.write("Installation Instructions:\n\n")
        f.write("1. Ensure you have Python 3.8 or newer installed\n")
        f.write("2. Install the required dependencies:\n")
        f.write("   pip install customtkinter pandas matplotlib networkx kamene psutil\n\n")
        f.write("3. Run the application:\n")
        f.write("   - Windows: Double-click run_analyzer.bat\n")
        f.write("   - Linux/Mac: In terminal, run: sudo ./run_analyzer.sh\n\n")
        f.write("Note: This application requires administrator/root privileges for packet capture.\n")
    
    # Create the zip file
    zip_filename = f"NetworkTrafficAnalyzer_{build_date}.zip"
    zip_path = os.path.join(dist_dir, zip_filename)
    
    print(f"Creating distribution package: {zip_path}")
    shutil.make_archive(os.path.splitext(zip_path)[0], 'zip', build_dir)
    
    print(f"Success! Distribution package created: {zip_path}")
    print("\nThe package contains:")
    print("- Python source files for the Network Traffic Analyzer")
    print("- Run scripts for Windows (.bat) and Linux/Mac (.sh)")
    print("- Application icons")
    print("- README and installation instructions")
    
    print("\nTo use the package:")
    print("1. Extract the ZIP file")
    print("2. Install the required dependencies (see README_INSTALLER.txt)")
    print("3. Run the application using the provided scripts")
    
    return True

if __name__ == "__main__":
    if build_executable():
        print("\nBuild completed successfully.")
    else:
        print("\nBuild failed.")
        sys.exit(1)