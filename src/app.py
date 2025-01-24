import os
import time
import hashlib
import socket
import psutil
import pandas as pd
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox, scrolledtext
from threading import Thread
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

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

    def update_timer():
        while True:
            elapsed_time = time.time() - deep_scan_start_time
            minutes, seconds = divmod(int(elapsed_time), 60)
            timer_label.config(text=f"Time Elapsed: {minutes:02}:{seconds:02}")
            time.sleep(1)

    Thread(target=update_timer, daemon=True).start()

    drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
    output_text_widget.insert(tk.END, f"Scanning system drives: {', '.join(drives)}\n")
    output_text_widget.yview(tk.END)

    for drive in drives:
        for file_path in iterate_files(drive):
            total_files_checked += 1
            try:
                output_text_widget.insert(tk.END, f"Checking file: {file_path}\n")
                output_text_widget.yview(tk.END)

                file_hash = calculate_sha256(file_path)
                if file_hash and file_hash in sha256_hashes.values:
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

def start_deep_scan():
    scan_button.config(state=tk.DISABLED)
    output_text.delete(1.0, tk.END)
    thread = Thread(target=deep_scan_gui, args=(output_text, timer_label))
    thread.start()
    scan_button.config(state=tk.NORMAL)

def specific_scan_gui(selected_path, output_text_widget):
    sha256_hashes = pd.read_csv('../data/hashes/full_sha256.txt')
    if sha256_hashes.empty:
        messagebox.showerror("Error", "No hashes loaded. Exiting scan.")
        return

    output_text_widget.delete(1.0, tk.END)
    if os.path.isfile(selected_path):
        output_text_widget.insert(tk.END, f"Scanning file: {selected_path}\n")
        file_hash = calculate_sha256(selected_path)
        if file_hash and file_hash in sha256_hashes.values:
            output_text_widget.insert(tk.END, f"** MALWARE DETECTED ** in {selected_path}\n")
        else:
            output_text_widget.insert(tk.END, "No malware detected.\n")
    elif os.path.isdir(selected_path):
        output_text_widget.insert(tk.END, f"Scanning folder: {selected_path}\n")
        for file_path in iterate_files(selected_path):
            file_hash = calculate_sha256(file_path)
            if file_hash and file_hash in sha256_hashes.values:
                output_text_widget.insert(tk.END, f"** MALWARE DETECTED ** in {file_path}\n")
            else:
                output_text_widget.insert(tk.END, f"No malware detected in {file_path}\n")
            output_text_widget.yview(tk.END)
    else:
        output_text_widget.insert(tk.END, "Invalid selection.\n")

def scan_specific_file_or_folder():
    selected_path = filedialog.askopenfilename(title="Select a file or folder to scan")
    if not selected_path:
        selected_path = filedialog.askdirectory(title="Select a folder to scan")
    if selected_path:
        thread = Thread(target=specific_scan_gui, args=(selected_path, output_text))
        thread.start()

def update_graphs():
    download_speed = psutil.net_io_counters().bytes_recv
    upload_speed = psutil.net_io_counters().bytes_sent
    cpu_clock_speed = psutil.cpu_freq().current

    x_vals.append(time.time() - start_time)
    download_speeds.append(download_speed / 1024)
    upload_speeds.append(upload_speed / 1024)
    cpu_clock_speeds.append(cpu_clock_speed)

    ax1.clear()
    ax2.clear()
    ax3.clear()
    ax4.clear()

    ax1.plot(x_vals, download_speeds, label="Download Speed (KB/s)", color="blue")
    ax2.plot(x_vals, upload_speeds, label="Upload Speed (KB/s)", color="green")
    ax3.plot(x_vals, [psutil.cpu_percent()] * len(x_vals), label="CPU Usage (%)", color="red")
    ax4.plot(x_vals, cpu_clock_speeds, label="CPU Clock Speed (MHz)", color="orange")

    for ax in [ax1, ax2, ax3, ax4]:
        ax.set_facecolor("black")
        ax.grid(color="gray", linestyle="--", linewidth=0.5)
        ax.legend()
        ax.tick_params(colors="white")
        ax.yaxis.label.set_color("white")
        ax.xaxis.label.set_color("white")

    canvas.draw()
    root.after(1000, update_graphs)

root = tk.Tk()
root.title("Network and Malware Monitor")
root.geometry("1200x800")
root.config(bg="#1e1e1e")

frame = tk.Frame(root, bg="#2e2e2e")
frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
scan_button = tk.Button(frame, text="Deep Scan (Entire System)", command=start_deep_scan, bg="#3e8e41", fg="#ffffff", font=("Arial", 12))
scan_button.pack(pady=10)
file_scan_button = tk.Button(frame, text="Scan Specific File", command=scan_specific_file_or_folder, bg="#0056a3", fg="#ffffff", font=("Arial", 12))
file_scan_button.pack(pady=10)

timer_label = tk.Label(frame, text="Time Elapsed: 00:00", bg="#2e2e2e", fg="#ffffff", font=("Arial", 12))
timer_label.pack(pady=10)

output_text = scrolledtext.ScrolledText(frame, width=100, height=15, bg="#333333", fg="#ffffff", font=("Courier", 10), insertbackground="white")
output_text.pack(padx=10, pady=10)

fig = Figure(figsize=(14, 8), dpi=100)
ax1 = fig.add_subplot(221)
ax2 = fig.add_subplot(222)
ax3 = fig.add_subplot(223)
ax4 = fig.add_subplot(224)
fig.subplots_adjust(left=0.05, right=0.95, top=0.95, bottom=0.05, wspace=0.3, hspace=0.3)

canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack(pady=20)

x_vals, download_speeds, upload_speeds, cpu_clock_speeds = [], [], [], []
start_time = time.time()

update_graphs()
root.mainloop()
