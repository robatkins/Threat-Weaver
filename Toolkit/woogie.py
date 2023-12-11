import os
import hashlib

# WOOGIE
# MD5 File Hasher without Multi-threading.

def hash_file_md5(file_path):
    """Hashes a file using MD5."""
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    return md5_hash.hexdigest()

def generate_hashes_md5(directory, output_file):
    """Recursively generates MD5 hashes for all files in the given directory and stores them in the output file."""
    with open(output_file, "w") as out_file:
        for foldername, subfolders, filenames in os.walk(directory):
            for filename in filenames:
                file_path = os.path.join(foldername, filename)
                file_hash = hash_file_md5(file_path)
                out_file.write(f"{file_hash}  {file_path}\n")

if __name__ == "__main__":
    print("WOOGIE | MD5 File Hasher")
    print("")
    root_directory = input("Enter the directory to scan (press Enter for current directory): ").strip()

    if not root_directory:
        root_directory = os.path.dirname(os.path.realpath(__file__))

    output_filename = "generated_md5_file_hashes.txt"

    generate_hashes_md5(root_directory, output_filename)
    print(f"MD5 hashes generated and stored in '{output_filename}'.")
