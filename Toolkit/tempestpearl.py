import os
import hashlib
import logging
from multiprocessing import Pool

#TEMPESTPEARL
#Multi-threaded Malware Scanner

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def process_file(file_path, malware_hashes):
    try:
        file_hash = calculate_sha256(file_path)
    except (PermissionError, FileNotFoundError) as e:
        logging.warning(f"Error accessing {file_path}: {e}")
        return None

    if file_hash in malware_hashes:
        logging.warning(f"Threat detected: {file_path} matches a known malware hash!")
        return file_path, file_hash
    else:
        logging.info(f"No malware found in {file_path}")
        return None

def scan_directory(directory_path, malware_hashes_file, threats_found_file):
    logging.info(f"Scanning directory: {directory_path}")
    with open(malware_hashes_file, 'r') as f:
        malware_hashes = set(line.strip() for line in f)

    with Pool() as pool:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                results = pool.apply_async(process_file, (file_path, malware_hashes))
                result = results.get()  # wait for the result
                if result is not None:
                    threat_path, threat_hash = result
                    write_threat_to_file(threats_found_file, threat_path, threat_hash)

def write_threat_to_file(file_path, threat_path, threat_hash):
    with open(file_path, 'a') as f:
        f.write(f"{threat_hash} {threat_path}\n")

if __name__ == "__main__":
    print("TEMPESTPEARL | Malware Scanner")
    print("")
    directory_to_scan = input("Enter the directory to scan: ")

    malware_hashes_file = "malware_hashes.txt"
    threats_found_file = "threats_found.txt"
    error_log_file = "error_log.txt"

    if os.path.exists(directory_to_scan):
        try:
            scan_directory(directory_to_scan, malware_hashes_file, threats_found_file)
            logging.info(f"Threats found are listed in {threats_found_file}")
        except KeyboardInterrupt:
            logging.warning("Scan interrupted by user.")
        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            with open(error_log_file, 'a') as err_log:
                err_log.write(f"Error: {str(e)}\n")
            logging.info(f"Check {error_log_file} for details.")
    else:
        logging.error("Invalid directory path. Please provide a valid directory.")



