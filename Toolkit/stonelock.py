import os
from multiprocessing import Pool
from functools import partial
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

#STONELOCK
#Multi-threaded AES-256 Recursive File Directory Encrypter/Decrypter

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as file:
        file.write(salt + iv + ciphertext)

    # Delete the original file after encryption
    os.remove(file_path)

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as file:
        data = file.read()

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_file_path = file_path[:-len('.encrypted')]
    with open(decrypted_file_path, 'wb') as file:
        file.write(plaintext)

    # Delete the original encrypted file after decryption
    os.remove(file_path)

def process_file(operation, args):
    if operation == 'encrypt':
        encrypt_file(*args)
    elif operation == 'decrypt':
        decrypt_file(*args)

def process_directory(directory_path, password, operation):
    files = []
    for root, _, filenames in os.walk(directory_path):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            files.append((file_path, password))

    with Pool() as pool:
        pool.map(partial(process_file, operation), files)

if __name__ == "__main__":
    print("STONELOCK | AES-256 Encrypter/Decrypter")
    print("")
    directory_path = input("Enter the directory path (press Enter to use the current directory): ").strip()
    if not directory_path:
        directory_path = os.getcwd()

    operation = input("Enter 'encrypt' or 'decrypt': ").strip().lower()

    if operation not in ['encrypt', 'decrypt']:
        print("Invalid operation. Exiting.")
        exit()

    password = input("Enter the password: ").strip()

    process_directory(directory_path, password, operation)

    if operation == 'encrypt':
        print("Encryption completed.")
    elif operation == 'decrypt':
        print("Decryption completed.")


