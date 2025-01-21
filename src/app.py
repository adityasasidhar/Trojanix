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
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

network_model = joblib.load('../models/network_knn_model.joblib')
network_scaler = joblib.load('../app scalers/network_scaler_model.joblib')

def get_src_ip():
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

def predict_network_model():
    """
    Predict network activity using the trained KNN model.
    """
    try:
        # Gather feature data
        src_ip = get_src_ip()
        dest_ip = "0.0.0.0"  # Placeholder, as getting actual destination IP requires packet inspection
        dport = 0  # Placeholder, needs packet capture to fill
        protocol = "Unknown"  # Placeholder, needs packet capture to fill
        service = "Unknown"  # Placeholder, needs port-service mapping
        sport_counts = get_sport_counts()
        number_of_flows = get_number_of_flows()
        average_of_duration = get_average_of_duration()
        std_dev_duration = 0  # Placeholder, requires capturing connection duration statistics
        total_size_flows_orig = get_total_size_of_flows_orig()
        total_size_flows_resp = get_total_size_of_flows_resp()
        inbound_pckts, outbound_pckts = get_packet_count()
        ssl_ratio = get_ssl_ratio()
        tls_version_ratio = get_tls_version_ratio()
        is_valid_cert = 1 if is_valid_certificate() else 0
        amount_diff_certificates = 0  # Placeholder
        number_of_domains_cert = get_number_of_domains_in_certificate()
        sni_ssl_ratio = get_sni_ssl_ratio()
        sni_equal_dstip = 0  # Placeholder, requires SNI-DstIP comparison logic
        url = 0  # Placeholder
        url_query_names = 0  # Placeholder
        url_query_values = 0  # Placeholder
        hostname = "Unknown"  # Placeholder
        sni = "Unknown"  # Placeholder
        downloaded_bytes = 0  # Placeholder, requires network traffic analysis
        uploaded_bytes = 0  # Placeholder
        number_of_url_flows = 0  # Placeholder
        hostname_digitratio = 0.0  # Placeholder
        hostname_alpharatio = 0.0  # Placeholder
        hostname_specialcharratio = 0.0  # Placeholder
        sni_digitratio = 0.0  # Placeholder
        sni_alpharatio = 0.0  # Placeholder
        sni_specialcharratio = 0.0  # Placeholder
        dns_noerror = get_dns_noerror()
        dns_nxdomain = get_dns_nxdomain()

        # Create feature array
        features = [
            src_ip, dest_ip, dport, protocol, service, sport_counts, number_of_flows,
            average_of_duration, std_dev_duration, total_size_flows_orig, total_size_flows_resp,
            inbound_pckts, outbound_pckts, ssl_ratio, tls_version_ratio, is_valid_cert,
            amount_diff_certificates, number_of_domains_cert, sni_ssl_ratio, sni_equal_dstip,
            url, url_query_names, url_query_values, hostname, sni, downloaded_bytes,
            uploaded_bytes, number_of_url_flows, hostname_digitratio, hostname_alpharatio,
            hostname_specialcharratio, sni_digitratio, sni_alpharatio, sni_specialcharratio,
            dns_noerror, dns_nxdomain
        ]
        label_encoder = LabelEncoder()
        for index in categorical_indices:
            features[index] = label_encoder.fit_transform([features[index]])[0]

        features = network_scaler.transform([features])

        # Predict using the model
        prediction = network_model.predict(features)

        # Return the prediction
        return prediction

    except Exception as e:
        print(f"Error in predict_network_model: {e}")
        return None



def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def iterate_files(start_directory):
    for dirpath, dirnames, filenames in os.walk(start_directory):
        for filename in filenames:
            yield os.path.join(dirpath, filename)

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

    def update_timer():
        while total_files_checked == 0 or total_files_checked < len(list(iterate_files(start_directory))):
            elapsed_time = time.time() - deep_scan_start_time
            minutes, seconds = divmod(int(elapsed_time), 60)
            timer_label.config(text=f"Time Elapsed: {minutes:02}:{seconds:02}")
            timer_label.after(1000, update_timer)

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
        except Exception:
            output_text_widget.insert(tk.END, f"Error processing file {file_path}. Skipping this file.\n")
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

def update_graphs():
    download_speed = psutil.net_io_counters().bytes_recv
    upload_speed = psutil.net_io_counters().bytes_sent
    network_processes = len(psutil.net_connections())

    x_vals.append(time.time() - start_time)
    download_speeds.append(download_speed / 1024)
    upload_speeds.append(upload_speed / 1024)
    network_process_counts.append(network_processes)

    ax1.clear()
    ax2.clear()
    ax3.clear()

    ax1.plot(x_vals, download_speeds, label="Download Speed (KB/s)", color="blue")
    ax2.plot(x_vals, upload_speeds, label="Upload Speed (KB/s)", color="green")
    ax3.plot(x_vals, network_process_counts, label="Network Processes", color="red")

    ax1.legend()
    ax2.legend()
    ax3.legend()

    canvas.draw()
    root.after(1000, update_graphs)

def start_scan():
    scan_button.config(state=tk.DISABLED)
    output_text.delete(1.0, tk.END)
    thread = Thread(target=deep_scan_gui, args=(output_text, timer_label))
    thread.start()
    scan_button.config(state=tk.NORMAL)

root = tk.Tk()
root.title("Network and Malware Monitor")
root.geometry("1000x700")
root.config(bg="#1e1e1e")

frame = tk.Frame(root, bg="#2e2e2e")
frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

scan_button = tk.Button(frame, text="Start Deep Scan", command=start_scan, bg="#3e8e41", fg="#ffffff", font=("Arial", 12))
scan_button.pack(pady=10)

timer_label = tk.Label(frame, text="Time Elapsed: 00:00", bg="#2e2e2e", fg="#ffffff", font=("Arial", 12))
timer_label.pack(pady=10)

output_text = scrolledtext.ScrolledText(frame, width=90, height=15, bg="#333333", fg="#ffffff", font=("Courier", 10), insertbackground='white')
output_text.pack(padx=10, pady=10)

fig = Figure(figsize=(10, 4), dpi=100)
ax1 = fig.add_subplot(131)
ax2 = fig.add_subplot(132)
ax3 = fig.add_subplot(133)

canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack(pady=20)

x_vals, download_speeds, upload_speeds, network_process_counts = [], [], [], []
start_time = time.time()

update_graphs()
root.mainloop()
