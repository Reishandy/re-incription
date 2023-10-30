# Re-Incription

Re-Incription is a simple file encryption program using AES-256 CFB and PBKDF2HMAC for key derivation from a password. The program performs 16 rounds of encryption, with a different key for each round derived from the previous key using SHA3-256 Hash. It also checks for data integrity using SHA3-256.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Features](#features)
- [Notes](#notes)
- [License](#license)
- [Author](#author)

## Installation
Clone this repository to your local machine, navigate to the cloned directory, and install the required dependencies:
```
git clone https://github.com/Reishandy/re-incription.git && cd re-incription && pip install -r requirements.txt
```
or
```commandline
git clone https://github.com/Reishandy/re-incription.git
cd re-incription
pip install -r requirements.txt
```


## Usage
To encrypt a file:
```commandline
python re-incription.py -e options filename
```
- options: Use -c to compress the file before encryption if desired.
- filename: The name of the file to be encrypted (include the extension).

To decrypt a file:
```commandline
python re-incription.py -d filename
```
- filename: The name of the encrypted .rei file.

To encrypt a dir:
```commandline
python re-incription.py -E options dirname
```
- options: Use -c to compress the file before encryption if desired.
- dirname: The name of the dir to be encrypted (only the dir name).

To decrypt a dir:
```commandline
python re-incription.py -D dirname
```
- dirname: The name of the dir to be decrypted (only the dir name).



## Examples
Encrypt a file with compression:
```commandline
python re-incription.py -e -c mydocument.txt
```

Decrypt an encrypted file:
```commandline
python re-incription.py -d mydocument-encrypted.rei
```

Encrypt a dir with compression:
```commandline
python re-incription.py -E -c myDir
```

Decrypt an encrypted dir:
```commandline
python re-incription.py -D myDir-encrypted
```


## Features
- File encryption and decryption using AES-256 CFB.
- Folder encryption and decryption.
- Key derivation from password using PBKDF2HMAC with 480,000 iterations.
- 16 rounds of encryption, each with a different key.
- Data integrity check using SHA3-256.
- Option to compress file before encryption and automatic decompression during decryption.

## Notes
- Password: When prompted for a password, you can type it securely without the characters being displayed in the terminal.
- File Type: Ensure that the file to be decrypted is of the .rei type. The program will verify the file's integrity and authenticity before decryption.

## License
This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## Author
Muhammad Akbar Reishandy - isthisruxury@gmail.com
