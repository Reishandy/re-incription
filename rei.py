"""Author: Reishandy (isthisruxury@gmail.com"""
import argparse
from secrets import token_bytes
from zlib import compress, decompress
from getpass import getpass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants
ENCRYPTION_ROUND: int = 16
PASSWORD_ITERATION: int = 480_000
SECONDARY_LENGTH: int = 16
PRIMARY_LENGTH: int = 32
DELIMITER: bytes = b'\x00\x01\x00\x01\x00\x01\x00\x01'
DELIMITER_DATA: bytes = b'\x01\x00\x01\x00\x01\x00\x01\x00'


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
description:
    a simple cli program to encrypt and decrypt any kind of file using AES-256-CFB and password derivation using
    PBKDF2HMAC, the encrypted file will be stored on '.rei' extension.
            
    the program will encrypt the file for 16 rounds, and the password derivation will be done for 480,000
    iterations. the program will also compress the file before encrypting it and verify the integrity of the
    file before decrypting it using SHA3-512.
            
    since the compression is lossless, it will works best on text file, but it will also works on any kind of
    file but the result will not be as good as text file.
            
features:
    - encrypt any kind of file
    - integrity check using hash
    - compress the file before encrypting it
        
author:
    Muhammad Akbar Reishandy (isthisruxury@gmail.com)
        ''',
        epilog="developed for final project on cryptography class"
    )
    parser.add_argument("filename", help="file to be operated, do not use any dot ('.') on the filename input")
    parser.add_argument("-e", "--encrypt", action="store_true", help="encrypt the given file")
    parser.add_argument("-d", "--decrypt", action="store_true", help="decrypt the given file")
    args = parser.parse_args()

    check_filename = args.filename.split(".")
    if len(check_filename) > 2 or len(check_filename) < 2:
        parser.error(f"Not suitable filename: {args.filename}")

    if args.encrypt and args.decrypt:
        parser.error("Only one mode can be executed at once: -e or -d")
    elif args.encrypt:
        encryption_handler(getpass(), args.filename)  # Password is from getpass() to hide it from the terminal
    elif args.decrypt:
        decryption_handler(getpass(), args.filename)
    else:
        parser.error("No mode selected: -e or -d")


def encryption_handler(password: str, file: str):
    print("=== ENCRYPTION ===")

    # Get the key and salt
    print("Deriving key from password...", end="", flush=True)
    key, salt = derive_key(password)
    print(" Done")

    # Read the file raw
    print("Reading the file...", end="", flush=True)
    try:
        with open(file, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f" Failed\n!!! FILE '{file}' NOT FOUND !!!")
        exit(4)
    print(" Done")

    # Compress the data
    print("Compressing the data...", end="", flush=True)
    data = compress(data)
    print(" Done")

    # Encrypt the data for n-rounds
    data_round = data
    for i in range(ENCRYPTION_ROUND):
        print(f"Encrypting round {i + 1}...", end="", flush=True)

        # Encrypt the data_round
        encrypted_data, iv = encrypt(data_round, key)

        # Stitch the iv and encrypted_data and encrypt it further
        data_round = iv + DELIMITER_DATA + encrypted_data

        print(" Done")

    # Prepare the data for writing
    print("Preparing the encrypted data...", end="", flush=True)
    extension = file.split(".")[1].encode()
    data_ready = extension + DELIMITER + get_hash(data_round) + DELIMITER + salt + DELIMITER + data_round
    print(" Done")

    # Write the encrypted data into file.rei
    print("Writing the encrypted data...", end="", flush=True)
    new_file = file.split(".")[0] + "-encrypted.rei"
    with open(new_file, "wb") as f:
        f.write(data_ready)
    print(" Done")

    print("=== ENCRYPTION DONE ===")
    print(f"Result: {new_file}")


def decryption_handler(password: str, file: str):
    print("=== DECRYPTION ===")

    # Read the encrypted file
    print("Reading the file...", end="", flush=True)
    try:
        with open(file, "rb") as f:
            data_get = f.read()
    except FileNotFoundError:
        print(f" Failed\n!!! FILE '{file}' NOT FOUND !!!")
        exit(4)
    print(" Done")

    # Separate the component
    print("Preparing the data...", end="", flush=True)
    component = data_get.split(DELIMITER)

    try:
        extension = component[0].decode()
    except UnicodeDecodeError:
        print(" Failed\n!!! WRONG FILE TYPE !!!")
        exit(1)

    data_hash = component[1]
    salt = component[2]
    data = component[3]
    print(" Done")

    # Verify the hash
    print("Verifying hash...", end="", flush=True)
    if not data_hash == get_hash(data):
        print(" Failed\n!!! HASH DOES NOT MATCH !!!")
        exit(2)
    print(" Done")

    # Get the key
    print("Deriving key from password...", end="", flush=True)
    key = get_key(password, salt)
    print(" Done")

    # Decrypt the data for n-round
    data_round = data
    for i in range(ENCRYPTION_ROUND):
        print(f"Decrypting round {ENCRYPTION_ROUND - i}...", end="", flush=True)

        # Separate the iv and encrypted_data
        try:
            iv, encrypted_data = data_round.split(DELIMITER_DATA)
        except ValueError:
            print(" Failed\n!!! WRONG PASSWORD !!!")
            exit(3)

        # Decrypt the data_round
        data_round = decrypt(encrypted_data, key, iv)

        print(" Done")

    # Decompress the data
    print("Decompressing the data...", end="", flush=True)
    data_round = decompress(data_round)
    print(" Done")

    # Write the decrypted data
    print("writing the decrypted data...", end="", flush=True)
    new_file = file.split(".")[0] + "-decrypted." + extension
    with open(new_file, "wb") as f:
        f.write(data_round)
    print(" Done")

    print("=== DECRYPTION DONE ===")
    print(f"Result: {new_file}")


def derive_key(password: str) -> (bytes, bytes):
    # Generate secure 16 bytes salt
    salt = token_bytes(SECONDARY_LENGTH)

    # Derive key from password using PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_256(),
        length=PRIMARY_LENGTH,
        salt=salt,
        iterations=PASSWORD_ITERATION,
    )

    # Return the derived key
    return kdf.derive(password.encode()), salt


def get_key(password: str, salt: bytes) -> bytes:
    # Derive the key from password and salt using PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_256(),
        length=PRIMARY_LENGTH,
        salt=salt,
        iterations=PASSWORD_ITERATION,
    )

    # Return the derived key
    return kdf.derive(password.encode())


def encrypt(data: bytes, key: bytes) -> (bytes, bytes):
    # Generate iv
    iv = token_bytes(SECONDARY_LENGTH)

    # Create an encryptor using AES-256 CBC
    cipher = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.CFB(iv),
    )
    encryptor = cipher.encryptor()

    # Returns the encrypted data and the iv
    return encryptor.update(data) + encryptor.finalize(), iv


def decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    # Create a decryptor using AES-256 CBC
    cipher = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.CFB(iv),
    )
    decryptor = cipher.decryptor()

    # Returns the decrypted data
    return decryptor.update(data) + decryptor.finalize()


def get_hash(data: bytes) -> bytes:
    # Create hasher using SHA3-512
    hasher = hashes.Hash(hashes.SHA3_512())

    # Return the hash
    hasher.update(data)
    return hasher.finalize()


if __name__ == "__main__":
    main()
