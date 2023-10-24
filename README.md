# Re-incription
A simple command-line program for encrypting and decrypting any type of file using AES-256-CFB encryption and password derivation using PBKDF2HMAC. The encrypted files will be stored with a '.rei' extension.

# Description
This Python program provides a user-friendly way to secure your files by encrypting them with strong encryption and password protection. The program offers the following features:

- File Encryption: Encrypt any type of file for added security.
- Integrity Check: Verify the integrity of the file using SHA3-512 to ensure it has not been tampered with.
- Data Compression: Compress files before encryption to reduce their size (note that this works best on text files).

# Author
Muhammad Akbar Reishandy (isthisruxury@gmail.com)

# Requirements
Before using this program, make sure you have the following dependencies installed:

- Python 3.7+: This program is written in Python. You can download Python from the official website.

- Cryptography Library: To install the required libraries, run the following command:
```
pip install cryptography
```

# Usage
To use this program, follow these simple instructions:

- Encrypt a File:
```
python rei.py -e <filename>
```
Replace <filename> with the name of the file you want to encrypt. The program will prompt you for a password to protect the file.

- Decrypt an Encrypted File:
```
python rei.py -d <encrypted_filename>
```
Replace <encrypted_filename> with the name of the encrypted file you want to decrypt. You will be prompted for the password used for encryption.

# Encryption Details
- The program encrypts files using AES-256-CFB for 16 rounds with unique IV for each round.
- Password derivation is performed using PBKDF2HMAC with SHA3-256 for 480,000 iterations.
- Files are compressed before encryption.
- SHA3-512 is used to verify the integrity of the file.

# Note
- The program doesn't accept filename with more than 1 dot ('.')
- Password for encryption and decryption is inputted with getpass
- The encryption mode is loseless, that means compression might not be efficient.

# Development
This program was developed as part of a final project for a cryptography class.
