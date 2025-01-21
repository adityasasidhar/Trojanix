import os
import time
import hashlib
import socket
import psutil
import pyshark
import pandas as pd
import tkinter as tk
from scapy.all import *
from threading import Thread
from tkinter import messagebox, scrolledtext

from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder

import joblib

network_model = joblib.load('../models/network_knn_model.joblib')
network_scaler = joblib.load('../app scalers/network_scaler_model.joblib')

def get_src_ip():
    """Retrieve the source IP address of the system."""
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)

def get_dest_ip(packet):
    """Extract destination IP from a given network packet."""
    return packet[IP].dst if IP in packet else None

def get_dport(packet):
    """Extract destination port from a given network packet."""
    return packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)

def get_protocol(packet):
    """Extract protocol type from a packet."""
    return packet.payload.name

def get_service(packet):
    """Identify service based on port mapping."""
    if TCP in packet or UDP in packet:
        return socket.getservbyport(packet.dport) if packet.dport else "Unknown"
    return "Unknown"

def get_sport_counts():
    """Count the number of active source ports."""
    connections = psutil.net_connections()
    return len(set(conn.laddr.port for conn in connections if conn.status == 'ESTABLISHED'))

def get_number_of_flows():
    """Count the number of active flows."""
    return len(psutil.net_connections())

def get_average_of_duration():
    """Estimate the average duration of active connections."""
    connections = psutil.net_connections()
    durations = [conn.pid for conn in connections if conn.status == 'ESTABLISHED']
    return sum(durations) / len(durations) if durations else 0

def get_total_size_of_flows_orig():
    """Estimate total sent bytes."""
    return psutil.net_io_counters().bytes_sent

def get_total_size_of_flows_resp():
    """Estimate total received bytes."""
    return psutil.net_io_counters().bytes_recv

def get_packet_count():
    """Get the number of inbound and outbound packets."""
    counters = psutil.net_io_counters()
    return counters.packets_recv, counters.packets_sent

def get_ssl_ratio():
    """Calculate SSL ratio in active connections."""
    capture = pyshark.LiveCapture(interface='Wi-Fi', display_filter="ssl")
    total_packets = 0
    ssl_packets = 0
    for packet in capture.sniff_continuously(packet_count=50):
        total_packets += 1
        if "SSL" in packet:
            ssl_packets += 1
    return ssl_packets / total_packets if total_packets else 0

def get_tls_version_ratio():
    """Calculate TLS version ratio in network traffic."""
    capture = pyshark.LiveCapture(interface='Wi-Fi', display_filter="tls")
    total_packets = 0
    tls_packets = 0
    for packet in capture.sniff_continuously(packet_count=50):
        total_packets += 1
        if "TLS" in packet:
            tls_packets += 1
    return tls_packets / total_packets if total_packets else 0

def is_valid_certificate():
    """Check if the SSL certificate is valid."""
    return True  # Needs implementation with external validation

def get_number_of_domains_in_certificate():
    """Get the number of domains present in SSL certificates."""
    return 1  # Requires external SSL certificate parsing

def get_sni_ssl_ratio():
    """Calculate the SNI presence in SSL connections."""
    capture = pyshark.LiveCapture(interface='Wi-Fi', display_filter="ssl")
    sni_count = 0
    ssl_count = 0
    for packet in capture.sniff_continuously(packet_count=50):
        if "SSL" in packet:
            ssl_count += 1
            if hasattr(packet.ssl, "handshake_extensions_server_name"):
                sni_count += 1
    return sni_count / ssl_count if ssl_count else 0

def get_dns_noerror():
    """Count the number of DNS responses without errors."""
    capture = pyshark.LiveCapture(interface='Wi-Fi', display_filter="dns and dns.flags.rcode == 0")
    return sum(1 for _ in capture.sniff_continuously(packet_count=50))

def get_dns_nxdomain():
    """Count the number of NXDOMAIN responses."""
    capture = pyshark.LiveCapture(interface='Wi-Fi', display_filter="dns and dns.flags.rcode == 3")
    return sum(1 for _ in capture.sniff_continuously(packet_count=50))

def iterate_files(start_directory):
    for dirpath, dirnames, filenames in os.walk(start_directory):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            yield file_path

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating SHA-256 for {file_path}: {e}")
        return None

def deep_scan_gui(output_text_widget, timer_label):

    sha256_hashes = pd.read_csv('../data/hashes/full_sha256.txt')
    if sha256_hashes.empty:
        messagebox.showerror("Error", "No hashes loaded. Exiting scan.")
        return

    malware_list = []
    deep_scan_start_time = time.time()
    total_files_checked = 0
    total_malwares_found = 0
    exception_count = 0

    start_directory = "C:"

    # Update the timer
    def update_timer():
        while total_files_checked == 0 or total_files_checked < len(list(iterate_files(start_directory))):
            elapsed_time = time.time() - deep_scan_start_time
            minutes, seconds = divmod(int(elapsed_time), 60)
            timer_label.config(text=f"Time Elapsed: {minutes:02}:{seconds:02}")
            timer_label.after(1000, update_timer)

    # Start updating timer in the background
    update_timer()

    output_text_widget.insert(tk.END, f"Root directory: {start_directory}\n")
    output_text_widget.yview(tk.END)

    for file_path in iterate_files(start_directory):
        total_files_checked += 1
        try:
            output_text_widget.insert(tk.END, f"Checking file: {file_path}\n")
            output_text_widget.yview(tk.END)

            file_hash = calculate_sha256(file_path)
            if file_hash and file_hash in sha256_hashes:
                output_text_widget.insert(tk.END, f"** MALWARE DETECTED ** in {file_path}\n")
                malware_list.append(file_path)
                total_malwares_found += 1
            else:
                output_text_widget.insert(tk.END, f"No malware detected in {file_path}\n")
                output_text_widget.yview(tk.END)

        except PermissionError:
            output_text_widget.insert(tk.END, f"Permission denied: {file_path}. Skipping this file.\n")
            exception_count += 1
        except Exception as e:
            output_text_widget.insert(tk.END, f"Error processing file {file_path}: {e}. Skipping this file.\n")
            exception_count += 1

    deep_scan_time = time.time() - deep_scan_start_time
    output_text_widget.insert(tk.END, f"Total scan time: {deep_scan_time:.2f} seconds\n")
    output_text_widget.insert(tk.END, f"Total files checked: {total_files_checked}\n")
    output_text_widget.insert(tk.END, f"Total malwares found: {total_malwares_found}\n")
    output_text_widget.insert(tk.END, f"Total exceptions encountered: {exception_count}\n")
    output_text_widget.yview(tk.END)

    if malware_list:
        output_text_widget.insert(tk.END, "\nMalware files found:\n")
        for malware in malware_list:
            output_text_widget.insert(tk.END, f"- {malware}\n")
    else:
        output_text_widget.insert(tk.END, "No malware files found.\n")
    output_text_widget.yview(tk.END)

# GUI setup
def start_scan():
    scan_button.config(state=tk.DISABLED)  # Disable the button to prevent multiple scans
    output_text.delete(1.0, tk.END)  # Clear previous scan results
    thread = Thread(target=deep_scan_gui, args=(output_text, timer_label))
    thread.start()
    scan_button.config(state=tk.NORMAL)  # Re-enable the button after the scan is finished


def preprocess_packet(packet, encoder, scaler):
    try:
        src_ip = packet[IP].src if IP in packet else "0.0.0.0"
        dest_ip = packet[IP].dst if IP in packet else "0.0.0.0"
        dport = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0)
        protocol = packet.payload.name if packet.payload else "Unknown"
        service = socket.getservbyport(dport) if dport else "Unknown"

        features = [
            encoder.transform([src_ip])[0],
            encoder.transform([dest_ip])[0],
            dport,
            encoder.transform([protocol])[0],
            encoder.transform([service])[0],
            len(psutil.net_connections()),
            psutil.net_io_counters().bytes_sent,
            psutil.net_io_counters().bytes_recv,
            psutil.net_io_counters().packets_recv,
            psutil.net_io_counters().packets_sent,
        ]

        features = np.array(features).reshape(1, -1)
        features = scaler.transform(features)
        return features
    except Exception as e:
        print(f"Error processing packet: {e}")
        return None


def detect_malware():
    print("Starting real-time network malware detection...")
    encoder = LabelEncoder()
    model = joblib.load("../models/network_knn_model.joblib")
    scaler = joblib.load("network_knn_scaler_model.joblib")

    capture = pyshark.LiveCapture(interface='Wi-Fi')

    for packet in capture.sniff_continuously(packet_count=100):
        features = preprocess_packet(packet, encoder, scaler)
        if features is not None:
            prediction = model.predict(features)
            if prediction[0] == 1:
                print(f"ALERT: Suspicious packet detected - {packet.summary()}")
            else:
                print("Packet is safe.")
root = tk.Tk()
root.title("Deep Malware Scan")
root.geometry("800x600")
root.config(bg="#1e1e1e")

# Define a custom color theme
bg_color = "#2e2e2e"
fg_color = "#ffffff"
button_color = "#3e8e41"
highlight_color = "#e6e6e6"

# Create and pack widgets
frame = tk.Frame(root, bg=bg_color)
frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

scan_button = tk.Button(frame, text="Start Deep Scan", command=start_scan, bg=button_color, fg=fg_color, font=("Arial", 12))
scan_button.pack(pady=10)

timer_label = tk.Label(frame, text="Time Elapsed: 00:00", bg=bg_color, fg=fg_color, font=("Arial", 12))
timer_label.pack(pady=10)

output_text = scrolledtext.ScrolledText(frame, width=90, height=25, bg="#333333", fg=fg_color, font=("Courier", 10), insertbackground='white')
output_text.pack(padx=10, pady=10)
root.mainloop()
