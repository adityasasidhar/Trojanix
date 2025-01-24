# Network and Malware Monitor

## Overview
The **Network and Malware Monitor** is a Python-based application that provides system performance monitoring and malware detection capabilities. It uses real-time network and CPU performance graphs along with scanning tools to identify potential malware threats in your files or directories.

---

## Features
### 1. Deep System Scan
- Scans all drives on your system for malware.
- Compares file hashes against a known malware hash database.
- Displays scan progress, total files checked, malwares detected, and any exceptions encountered.

### 2. Specific File or Folder Scan
- Allows users to select a specific file or folder for malware scanning.
- Provides detailed scan results in an output log.

### 3. Real-Time System Monitoring
- Visualizes system metrics in real-time, including:
  - **Download speed**
  - **Upload speed**
  - **CPU usage**
  - **CPU clock speed**
- Provides dynamic and user-friendly graphs for easy interpretation.

### 4. Intuitive User Interface
- Built with **Tkinter** for a clean and modern UI.
- Includes features like scrolling output logs and real-time graph rendering.
- Provides interactive buttons for starting scans and monitoring the system.

---

## Prerequisites
Ensure the following Python libraries are installed before running the application:
- `os`
- `time`
- `hashlib`
- `socket`
- `psutil`
- `pandas`
- `tkinter` (bundled with Python)
- `matplotlib`

To install missing libraries, use:
```bash
pip install psutil pandas matplotlib