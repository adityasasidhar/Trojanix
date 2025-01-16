import os
import time
import hashlib
import pandas as pd
import tkinter as tk
from tkinter import messagebox, scrolledtext
from threading import Thread

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

    sha256_hashes = pd.read_csv('data/hashes/full_sha256.txt')
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

# Create main window
root = tk.Tk()
root.title("Deep Malware Scan")
root.geometry("800x600")  # Set initial window size
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

# Run the Tkinter event loop
root.mainloop()
