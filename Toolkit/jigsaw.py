import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes


#JIGSAW
#AES-256 File Encrypter/Decrypter without Multi-threading

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


def encrypt_directory(directory_path, password):
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            encrypt_file(file_path, password)


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



def decrypt_directory(directory_path, password):
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            if file_name.endswith('.encrypted'):
                file_path = os.path.join(root, file_name)
                decrypt_file(file_path, password)


if __name__ == "__main__":
    print("JIGSAW | AES-256 Encrypter/Decrypter")
    print("")
    directory_path = input("Enter the directory path (press Enter to use the current directory): ").strip()
    if not directory_path:
        directory_path = os.getcwd()

    operation = input("Enter 'encrypt' or 'decrypt': ").strip().lower()

    if operation not in ['encrypt', 'decrypt']:
        print("Invalid operation. Exiting.")
        exit()

    password = input("Enter the password: ").strip()

    if operation == 'encrypt':
        encrypt_directory(directory_path, password)
        print("Encryption completed.")
    elif operation == 'decrypt':
        decrypt_directory(directory_path, password)
        print("Decryption completed.")

