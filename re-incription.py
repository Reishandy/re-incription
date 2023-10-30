"""Author: Reishandy (isthisruxury@gmail.com"""
import argparse
from os.path import getsize, join, exists, isdir
from os import getcwd, makedirs, walk, remove
from shutil import copytree
from secrets import token_bytes
from zlib import compress, decompress
from getpass import getpass

from tqdm import tqdm
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
CHUNK_SIZE: int = 1_048_576


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
description:
    A simple file encryption program using AES-256 CBC as the algorithm to encrypt the file and PBKDF2HMAC as the 
    algorithm to get key from the provided password, the output file will be in .rei format.
    
    The program will encrypt the file for 16 rounds, each round will use different key derived from the previous key 
    using SHA3-256 Hash. The original key is derived from the password using PBKDF2HMAC with 480,000 iterations and
    a salt (generated) that will be stored in the encrypted file. And hash the encrypted data using SHA3-256 and store
    it in the encrypted file, the hash will be used to verify the integrity of the data when decrypting the file.
    The program will also store the extension of the original file in the encrypted file to be used to determine the
    original file's type. Another option is to compress the file before encrypting it, the program will store the
    information that the file is compressed in the encrypted file. so the program can automatically determine if the
    file is compressed or not when decrypting the file and do the appropriate action. 
    
    The format of .rei file is as follows:
    [compressed] DELIMITER [extension] DELIMITER [hash] DELIMITER [salt] DELIMITER [encrypted_data]
    - DELIMITER: b'\\x00\\x01\\x00\\x01\\x00\\x01\\x00\\x01', used to separate the component
    - compressed: b'\\x01' if the file is compressed, b'\\x00' if not
    - extension: the extension of the original file, Unicode encoded
    - hash: the hash of the encrypted data, used to verify the integrity of the data
    - salt: the salt used to derive the key from the password
    - encrypted_data: the encrypted data, the first 16 bytes is the iv used to encrypt the data and the rest is the
                    encrypted data. seperated by DELIMITER_DATA: b'\\x01\\x00\\x01\\x00\\x01\\x00\\x01\\x00'
            
features:
    - Encrypt and decrypt file using AES-256 CBC
    - Encrypt and decrypt entire folder
    - Encryption by password using PBKDF2HMAC with 480,000 iterations to derive the key
    - 16 rounds of encryption, different key for each round
    - Integrity check using SHA3-256
    - Compression before encryption, and automatic decompression when decrypting
    - Can retain the original file extension, so the program can automatically determine the original file's type
        
author:
    Muhammad Akbar Reishandy (isthisruxury@gmail.com)
        ''',
        epilog="developed for final project on cryptography class"
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-e", "--encrypt", action="store_true", help="file encryption mode")
    group.add_argument("-d", "--decrypt", action="store_true", help="file decryption mode")
    group.add_argument("-E", "--encrypt_dir", action="store_true", help="dir encryption mode")
    group.add_argument("-D", "--decrypt_dir", action="store_true", help="dir decryption mode")

    parser.add_argument("-c", "--compress", action="store_true", help="compress the file before encryption")
    parser.add_argument("path", help="path to the file or directory to be operated")
    args = parser.parse_args()

    if args.encrypt:
        # Getting the key
        password = getpass()
        print("\033[1;34;40mDeriving key from password...", end="", flush=True)
        key, salt = derive_key(password)
        print("\033[1;32;40mDone\033[1;34;40m")

        # Encrypt the file
        encryption_handler(key, salt, args.path, args.compress)
    elif args.decrypt:
        # Decrypt the file (password needs to be generated with the salt form the file)
        decryption_handler(getpass(), args.path)
    elif args.encrypt_dir:
        # Getting the key
        password = getpass()
        print("\033[1;34;40mDeriving key from password...", end="", flush=True)
        key, salt = derive_key(password)
        print("\033[1;32;40mDone\033[1;34;40m")

        # Encrypt the dir
        dir_encryption_handler(key, salt, args.path, args.compress)
    elif args.decrypt_dir:
        # Decrypt the dir
        dir_decryption_handler(getpass(), args.path)


def encryption_handler(key: bytes, salt: bytes, file: str, compress_flag: bool):
    print("\033[1;36;40m=== ENCRYPTION ===\033[1;34;40m")

    # Checking filename
    check_filename(file)

    # Read the file raw
    data = read_file(file)

    if compress_flag:
        # Compress the data
        print("\033[1;34;40mCompressing the data...", end="", flush=True)
        data = compress(data)
        print("\033[1;32;40mDone\033[1;34;40m")

    # Encrypt the data for n-rounds
    data_round = data
    key_round = key
    for _ in tqdm(range(ENCRYPTION_ROUND), desc="Encrypting ", unit="round"):
        # Encrypt the data_round
        encrypted_data, iv = encrypt(data_round, key_round)

        # Stitch the iv and encrypted_data and encrypt it further and
        data_round = iv + DELIMITER_DATA + encrypted_data

        # Generate new key for next round with hash of the previous key
        key_round = get_hash(key_round)

    # Prepare the data for writing
    print("\033[1;34;40mPreparing the encrypted data...", end="", flush=True)
    extension = file.split(".")[1].encode()
    compress_state = b"\x01" if compress_flag else b"\x00"
    data_ready = (compress_state + DELIMITER + extension + DELIMITER + get_hash(data_round) + DELIMITER +
                  salt + DELIMITER + data_round)
    print("\033[1;32;40mDone\033[1;34;40m")

    # Write the encrypted data into file.rei
    new_file = file.split(".")[0] + "-encrypted.rei"
    write_file(new_file, data_ready)

    print("\033[1;36;40m=== ENCRYPTION DONE ===")
    print(f"\033[1;37;40mResult: {new_file}")


def decryption_handler(password: str, file: str):
    print("\033[1;36;40m=== DECRYPTION ===\033[1;34;40m")

    # Checking filename
    check_filename(file)

    # Read the encrypted file
    data_get = read_file(file)

    # Separate the component
    print("\033[1;34;40mPreparing the data...", end="", flush=True)
    component = data_get.split(DELIMITER)

    # Determining if the file is compressed
    compress_flag = True if component[0] == b"\x01" else False

    # Check if the file is of .rei type
    try:
        extension = component[1].decode()
        data_hash = component[2]
        salt = component[3]
        data = component[4]
    except IndexError or UnicodeDecodeError:
        print("\033[1;31;40mFailed\n!!! WRONG FILE TYPE !!!\033[1;37;40m")
        exit(1)

    print("\033[1;32;40mDone")
    print("\033[1;36;40m--- FILE IS COMPRESSED --- " if compress_flag
          else "\033[1;36;40m--- FILE IS NOT COMPRESSED ---")

    # Verify the hash
    print("\033[1;34;40mVerifying hash...", end="", flush=True)
    if not data_hash == get_hash(data):
        print("\033[1;31;40mFailed\n!!! HASH DOES NOT MATCH !!!\033[1;37;40m")
        exit(2)
    print("\033[1;32;40mDone")

    # Get the key
    print("\033[1;34;40mDeriving key from password...", end="", flush=True)
    key = get_key(password, salt)
    print("\033[1;32;40mDone")

    # Create a list of key used for decryption
    print("\033[1;34;40mGenerating round key...", end="", flush=True)
    key_round = []
    for _ in range(ENCRYPTION_ROUND):
        key_round.append(key)
        key = get_hash(key)
    print("\033[1;32;40mDone\033[1;34;40m")

    # Decrypt the data for n-round
    data_round = data
    for i in tqdm(range(ENCRYPTION_ROUND), desc="Decrypting ", unit="round"):
        # Separate the iv and encrypted_data
        try:
            iv, encrypted_data = data_round.split(DELIMITER_DATA)
        except ValueError:
            print("\033[1;31;40m\n!!! WRONG PASSWORD !!!\033[1;37;40m")
            exit(3)

        # Decrypt the data_round
        data_round = decrypt(encrypted_data, key_round[ENCRYPTION_ROUND - i - 1], iv)

    if compress_flag:
        # Decompress the data
        print("\033[1;34;40mDecompressing the data...", end="", flush=True)
        data_round = decompress(data_round)
        print("\033[1;32;40mDone\033[1;34;40m")

    # Write the decrypted data
    new_file = file.split(".")[0] + "-decrypted." + extension
    write_file(new_file, data_round)

    print("\033[1;36;40m=== DECRYPTION DONE ===")
    print(f"\033[1;37;40mResult: {new_file}")


def dir_encryption_handler(key: bytes, salt: bytes, directory: str, compress_flag: bool):
    print(f"\033[1;36;40m=== DIR ENCRYPTION ===\033[1;34;40m")
    # Check dirname
    check_dirname(directory)

    # Update the directory_path
    directory_path = join(getcwd(), directory)

    # Check if dir exist
    check_dir_exist(directory_path)

    # Create a new directory
    encrypted_dir = directory_path + "-encrypted"
    print(f"\033[1;34;40mCopying files to {encrypted_dir}...", end="", flush=True)
    makedirs(directory_path, exist_ok=True)
    print("\033[1;32;40mDone")

    # Copy the entire dir to the new encrypted dir
    try:
        copytree(directory_path, encrypted_dir)
    except FileExistsError:
        print("\033[1;31;40m!!! DIR ALREADY EXIST !!!\033[1;37;40m")
        exit(6)

    # The actual encryption process
    for folder_name, sub_folders, filenames in walk(encrypted_dir):
        for filename in filenames:
            print(f"\033[1;36;40m=== Encrypting {filename} ===\033[1;34;40m")
            file_path = join(folder_name, filename)
            encryption_handler(key, salt, file_path, compress_flag)
            remove(file_path)

    print(f"\033[1;36;40m=== DIR ENCRYPTION DONE ===\033[1;34;40m")
    print(f"\033[1;37;40mResult: {encrypted_dir}")


def dir_decryption_handler(password: str, directory: str):
    print(f"\033[1;36;40m=== DIR DECRYPTION ===\033[1;34;40m")
    # Check dirname
    check_dirname(directory)

    # Update the directory_path
    directory_path = join(getcwd(), directory)

    # Check if dir exist
    check_dir_exist(directory_path)

    # Create a new directory
    decrypted_dir = directory_path + "-decrypted"
    print(f"\033[1;34;40mCopying files to {decrypted_dir}...", end="", flush=True)
    makedirs(directory_path, exist_ok=True)
    print("\033[1;32;40mDone")

    # Copy the entire dir to the new encrypted dir
    try:
        copytree(directory_path, decrypted_dir)
    except FileExistsError:
        print("\033[1;31;40m!!! DIR ALREADY EXIST !!!\033[1;37;40m")
        exit(6)

    # The actual decryption process
    for folder_name, sub_folders, filenames in walk(decrypted_dir):
        for filename in filenames:
            print(f"\033[1;36;40m=== Decrypting {filename} ===\033[1;34;40m")
            file_path = join(folder_name, filename)
            decryption_handler(password, file_path)
            remove(file_path)

    print(f"\033[1;36;40m=== DIR DECRYPTION DONE ===\033[1;34;40m")
    print(f"\033[1;37;40mResult: {decrypted_dir}")


def check_dir_exist(check_dir: str):
    if exists(check_dir):
        if not isdir(check_dir):
            print(f"\033[1;31;40m!!! {check_dir} IS NOT A DIRECTORY !!!\033[1;37;40m")
            exit(7)
    else:
        print("\033[1;31;40m!!! DIR NOT FOUND !!!\033[1;37;40m")
        exit(7)


def check_dirname(path: str):
    if "\\" in path or "/" in path:
        print("\033[1;31;40m!!! PATH DIR NOT SUITABLE !!!\033[1;37;40m")
        exit(5)


def check_filename(file: str):
    filename = file.split(".")
    if len(filename) > 2 or len(filename) < 2:
        print("\033[1;31;40m!!! FILENAME NOT SUITABLE !!!\033[1;37;40m")
        exit(5)


def write_file(new_file: str, data: bytes):
    with open(new_file, "wb") as f:
        with tqdm(f, total=len(data), desc="Writing    ", unit="Bytes",
                  unit_scale=True, unit_divisor=1024) as pbar:
            for i in range(0, len(data), CHUNK_SIZE):
                chunk = data[i:i + CHUNK_SIZE]
                f.write(chunk)
                pbar.update(len(chunk))


def read_file(file: str) -> bytes:
    data = b''
    try:
        file_size = getsize(file)
        with open(file, "rb") as f:
            with tqdm(f, total=file_size, desc="Reading    ", unit="Bytes",
                      unit_scale=True, unit_divisor=1024) as pbar:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    data += chunk
                    pbar.update(len(chunk))
    except FileNotFoundError:
        print(f"\033[1;31;40m\n!!! FILE '{file}' NOT FOUND !!!\033[1;37;40m")
        exit(4)
    return data


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
    hasher = hashes.Hash(hashes.SHA3_256())

    # Return the hash
    hasher.update(data)
    return hasher.finalize()


if __name__ == "__main__":
    main()
