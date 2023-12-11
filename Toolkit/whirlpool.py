import os
import hashlib

#WHIRLPOOL
#SHA-256 Hashing without Multi-threading

def hash_file(file_path):
    """Hashes a file using SHA256."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_hashes(directory, output_file):
    """Recursively generates hashes for all files in the given directory and stores them in the output file."""
    with open(output_file, "w") as out_file:
        for foldername, subfolders, filenames in os.walk(directory):
            for filename in filenames:
                file_path = os.path.join(foldername, filename)
                file_hash = hash_file(file_path)
                out_file.write(f"{file_hash}  {file_path}\n")

if __name__ == "__main__":
    print("WHIRLPOOL | SHA-256 Malware Hasher")
    print("")
    root_directory = input("Enter the directory to scan (press Enter for current directory): ").strip()
    
    if not root_directory:
        root_directory = os.path.dirname(os.path.realpath(__file__))

    output_filename = "generated_malware_hashes.txt"
    
    generate_hashes(root_directory, output_filename)
    print(f"Hashes generated and stored in '{output_filename}'.")
