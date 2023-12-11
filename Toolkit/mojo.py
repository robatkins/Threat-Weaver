import os
import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor

#MOJO
#Multi-threaded SHA-256 File Hasher

CHUNK_SIZE = 8192
GENERATED_HASHES_FILE = "generated_sha256_file_hashes.txt"

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def generate_hash_for_file(file_path):
    try:
        file_hash = calculate_sha256(file_path)
        logging.info(f"Hash generated for {file_path}")
        with open(GENERATED_HASHES_FILE, 'a') as hash_file:
            hash_file.write(f"{file_hash}\n")
    except (PermissionError, FileNotFoundError, OSError) as e:
        logging.error(f"Error accessing {file_path}: {e}")

def generate_hashes(directory_path):
    logging.info(f"Generating hashes for files in {directory_path}")

    with ThreadPoolExecutor() as executor:
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                executor.submit(generate_hash_for_file, file_path)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("MOJO | SHA-256 File Hasher")
    print("")
    directory_to_scan = input("Enter the directory to scan: ")

    if not os.path.exists(directory_to_scan) or not os.path.isdir(directory_to_scan):
        print("Invalid directory path. Please provide a valid directory.")
    else:
        generate_hashes(directory_to_scan)
        print(f"Hashes generated and stored in {GENERATED_HASHES_FILE}")

