HSM RSA Key Management and CSR Generation Script

# [HSMTool](https://github.com/krypt0k1/CryptographyProjects/blob/hsmtool/hsmtool.py) 

Description

This Python script is designed for managing cryptographic keys on a nShield HSM. It provides functionality for creating RSA key pairs, wrapping private keys with AES keys, and generating Certificate Signing Requests (CSRs) using the RSA keys stored on the HSM. The program integrates with OpenSSL via the nfkm engine for CSR generation and supports the secure export of private keys in encrypted binary format.

Purpose

This tool simplifies and automates key management operations in secure environments, ensuring compliance with cryptographic best practices. It is ideal for use cases requiring secure key storage, private key wrapping for backup or transport, and CSR generation for obtaining digital certificates.

Features
    Key Management:
        Creates or uses an existing RSA key pair.
        Wraps the RSA private key with a new or existing AES wrapping key.
        Exports the wrapped private key to an encrypted binary file.
    CSR Generation:
        Generates CSRs using the public key stored on the HSM.
        Compatible with OpenSSL via the nfkm engine.
    Flexibility:
        Supports key sizes of 2048 and 4096 bits.
        Allows the use of existing keys or generates new ones.

Supported Operating Systems

    Windows
    Linux

Prerequisites

    Hardware: nCipher nShield HSM (e.g., Edge, Connect, or Solo).
    Software:
        nCipher Security World Software (with OpenSSL engine).
        Python 3.6+.
        Required Python modules: python-pkcs11, os, re, sys, time, subprocess.
    Environment Setup:
        Configure environment variables:
            PKCS11_MODULE_PATH: Path to the PKCS#11 module.
            NFAST_HOME: Path to the nFast directory.
            OPENSSL_ENGINES: Path to the OpenSSL engines directory.
        Add the HSM tools to the system PATH:
            Windows: %NFAST_HOME%\bin.
            Linux: /opt/nfast/bin.

Installation

    Clone this repository: 
    git clone https://github.com/krypt0k1/hsmtool.git
    cd hsmtool

Install dependencies:

    pip install python-pkcs11

Usage

    Run the script:

    python3.10 hsmtool.py

    Follow the prompts:
        Enter labels for RSA and AES keys.
        Provide the token label and PIN.
        Specify key size (2048 or 4096).
        Decide whether the public key should be a wrapping key.
        Generate a new key pair or use an existing one.
        Generate a CSR and save it to a file.

    Example of saving wrapped private key material:
        Default: Current working directory.
        Custom: Provide a directory path when prompted.

    CSR output will be saved as a .req file.

Example Workflow

    Generate Keys and Wrap Private Key:
        Input RSA key label: rsa_key.
        Input AES wrapping key label: aes_key.
        Input token label: loadshared accelerator.
        Input PIN: 1234.
        Generate or use an existing RSA/AES key.
        Save the wrapped key material (e.g., rsa_key_wrapped_key_MM_DD_YYYY-HH_MM.bin).

    Generate CSR:
        Provide the key label: rsa_key.
        CSR file will be saved as rsa_key_csr.req.

Dependencies

    Hardware:
        nCipher HSM.
    Software:
        OpenSSL with the nShield Security World engine.
    Python Packages:
        python-pkcs11
        os
        sys
        time
        subprocess
        re

Example

![image](https://github.com/user-attachments/assets/8a982c4d-eee0-44ad-a294-979f282ba9e7)

License

[MIT License](https://github.com/krypt0k1/hsmtool/blob/main/LICENSE)


Contributing

Contributions are welcome! Submit pull requests or issues via GitHub.


Author

Armando Montero - nCipher Security
