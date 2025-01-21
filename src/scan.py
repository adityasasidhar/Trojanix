import os
import time
import psutil
import hashlib
import pandas as pd

def deep_scan():

    """
    listed out some old fucntions that i think might be useful, you dont have to use it but can be used within the function
    build nesting cases for hardware status and constraints
    """

    def current_cpu_speed():
        return psutil.cpu_freq().current

    def max_cpu_speed():
        return psutil.cpu_freq().max

    def min_cpu_speed():
        return psutil.cpu_freq().min

    def current_cpu_usage():
        return psutil.cpu_percent(interval=1)

    def num_phy_cores():
        return psutil.cpu_count(logical=False)

    def num_log_cores():
        return psutil.cpu_count(logical=True)

    def get_battery_status():
        battery = psutil.sensors_battery()
        if battery:
            return battery.power_plugged
        else:
            return None

    def current_battery_capacity():
        battery = psutil.sensors_battery()
        if battery:
            return battery.percent
        else:
            return None

    def total_ram():
        memory = psutil.virtual_memory()
        return memory.total / (1024 ** 3)

    def total_available_ram():
        memory = psutil.virtual_memory()
        return memory.available / (1024 ** 3)

    def used_ram():
        memory = psutil.virtual_memory()
        return memory.used / (1024 ** 3)

    def ram_usage():
        memory = psutil.virtual_memory()
        return memory.percent

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

    def load_hash_file(csv_file):
        try:
            df = pd.read_csv(csv_file, header=None)
            return set(df[0])
        except Exception as e:
            print(f"Error loading hash file {csv_file}: {e}")
            return set()


    malware_list = []
    deep_scan_start_time = time.time()
    total_files_checked = 0
    total_malwares_found = 0
    exception_count = 0

    sha256_hashes = load_hash_file('full_sha256.txt')
    if not sha256_hashes:
        print("No hashes loaded. Exiting scan.")
        return

    start_directory = "C:"
    print(f"Starting deep scan in directory: {start_directory}")

    for file_path in iterate_files(start_directory):
        total_files_checked += 1
        try:
            print(f"Checking file: {file_path}")
            file_hash = calculate_sha256(file_path)
            if file_hash and file_hash in sha256_hashes:
                print(f"** MALWARE DETECTED ** in {file_path}")
                malware_list.append(file_path)
                total_malwares_found += 1
            else:
                print(f"No malware detected in {file_path}")
        except PermissionError:
            print(f"Permission denied: {file_path}. Skipping this file.")
            exception_count += 1
            continue
        except Exception as e:
            print(f"Error processing file {file_path}: {e}. Skipping this file.")
            exception_count += 1
            continue

    deep_scan_time = time.time() - deep_scan_start_time
    print(f"Total scan time: {deep_scan_time:.2f} seconds")
    print(f"Total files checked: {total_files_checked}")
    print(f"Total malwares found: {total_malwares_found}")
    print(f"Total exceptions encountered: {exception_count}")

    if malware_list:
        print("\nMalware files found:")
        for malware in malware_list:
            print(f"- {malware}")
    else:
        print("No malware files found.")
