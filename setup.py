#!/usr/bin/env python3
"""
Setup script for installing Network Traffic Analyzer.
"""

from setuptools import setup, find_packages

setup(
    name="network-traffic-analyzer",
    version="1.0.0",
    description="A comprehensive network traffic visualization and analysis tool",
    author="Network Security Team",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "customtkinter",
        "pandas",
        "matplotlib",
        "networkx",
        "kamene",
        "psutil",
        "pillow",
        "streamlit"
    ],
    entry_points={
        "console_scripts": [
            "network-analyzer=desktop_app:main",
            "network-analyzer-web=app:main"
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
)