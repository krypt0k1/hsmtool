# 🔒 HSM Cryptographic Operations Tool

This Python-based command-line interface (CLI) tool allows you to perform various cryptographic operations using nCipher Hardware Security Modules (HSMs) and the PKCS#11 API. It provides functionalities for key management (generation, copy, delete, modification), key wrapping/unwrapping, and cryptographic operations like signing, verification, encryption, and decryption.

The tool is designed to be user-friendly while interacting with the complexities of PKCS#11.
# ✨ Capabilities and Features

    Session Management: Initialize and manage PKCS#11 sessions with your HSM tokens.

    Key Listing: List all available secret, private, public keys, and certificates on the HSM.

    Key Generation:

        Generate symmetric keys (AES, DES2, DES3) with configurable sizes and attributes.

        Generate asymmetric key pairs (RSA, DSA, EC) with configurable parameters and attributes.

        Support for various EC curves.

    Key Management:

        Copy Key: Duplicate existing keys within the same token.

        Delete Key: Securely remove keys from the HSM.

        Modify Key Attributes: Change attributes like CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP, and CKA_EXTRACTABLE.

        Set CKA_TRUSTED Attribute: Utilize an external script (trustme.py) to set the CKA_TRUSTED attribute for specific keys (requires Security Officer (SO) PIN and preload utility).

    Cryptographic Operations:

        Wrap/Unwrap Keys: Securely wrap keys with other keys (e.g., AES with RSA public key, AES with another AES key) and unwrap them.

        Sign Data: Create digital signatures using private or secret keys.

        Verify Signature: Authenticate data using public keys and signatures.

        Encrypt Data: Encrypt data using symmetric or asymmetric keys.

        Decrypt Data: Decrypt previously encrypted data.

    Input/Output Flexibility: Supports reading data from files or direct string input for cryptographic operations.

# ⚙️ Prerequisites

Before you begin, ensure you have the following installed and configured:

    Python 3.7+:

    python3 --version

    Microsoft requires C++ Build Tools
    Download it here: https://visualstudio.microsoft.com/visual-cpp-build-tools/

    nCipher HSM and PKCS#11 Library:

        You must have an nCipher HSM connected and configured.

        The nCipher PKCS#11 library (cknfast.so on Linux, cknfast.dll on Windows) must be installed on your system.

    preload Utility (for CKA_TRUSTED operation):

        The preload utility (part of the nCipher tools) is required if you intend to use the "Set CKA_TRUSTED attribute" feature.

# 🚀 Installation

Follow these steps to set up the HSM Cryptographic Operations Tool:
1. Clone the Repository

    git clone https://github.com/krypt0k1/hsmtool.git 

2. Install Python Requirements

    Create a requirements.txt file in the root of the repository with the following content:

        python-pkcs11>=0.7.0
        prettytable>=3.0.0

Then, install the required Python packages:

        pip install --upgrade setuptools
        pip install -r requirements.txt

3. Configure PKCS#11 Library Path
    
    The tool needs to know the path to your nCipher PKCS#11 library. It attempts to auto-detect this based on your OS or by using the NFAST_MODULE environment variable.
    
    Recommended: Set NFAST_MODULE Environment Variable
    
    This is the most reliable way to point the tool to your PKCS#11 library.

        Linux/macOS:
    
        export NFAST_MODULE=/opt/nfast/toolkits/pkcs11/libcknfast.so
        # Add this line to your shell profile (~/.bashrc, ~/.zshrc) for persistence
    
        Windows (Command Prompt):
    
        set NFAST_MODULE="C:\Program Files\nCipher\nfast\toolkits\pkcs11\cknfast.dll"
        # For persistence, add to System Environment Variables (Advanced System Settings -> Environment Variables)

        
   If NFAST_MODULE is not set, the tool will default to /opt/nfast/toolkits/pkcs11/libcknfast.so on Linux and C:\Program Files\nCipher\nfast\toolkits\pkcs11\cknfast.dll on Windows.
        
# 💡 Usage

The main entry point for the tool is hsmtool.py.
1. Start the Tool
   
    python hsmtool
   
Upon successful execution, you will be prompted to select a PKCS#11 token and enter its PIN. After establishing a session, the main menu will be displayed.

![image](https://github.com/user-attachments/assets/d74a8ec4-23be-4b24-ba45-bd7564ae907c)



2. Common Operations Examples

  a) Listing Keys

Select option 1 from the main menu. 
This will display all keys and certificates found on your token.
b) Generating an AES Key

    Select option 2 ("Generate key/key-pair").

    Enter AES as the key type.

    Provide a unique label for your key (e.g., MyAesKey).

    Enter the desired key size (e.g., 256).

    Follow the prompts to configure attributes like ENCRYPT, DECRYPT, WRAP, UNWRAP, SENSITIVE, and EXTRACTABLE.

c) Generating an RSA Key Pair

    Select option 2 ("Generate key/key-pair").

    Enter RSA as the key type.

    Provide a unique label for the key pair (e.g., MyRsaPair).

    Enter the desired key size (e.g., 2048).

    Follow the prompts to configure attributes for both the public and private keys.

d) Encrypting and Decrypting Data (e.g., with AES)

Encryption:

    Generate an AES key with CKA_ENCRYPT enabled.

    Select option 10 ("Encrypt data").

    Choose input method (file or string).

    Select your AES key by label and type.

    The tool will generate an IV. Make sure to save this IV (hex string) as it's required for decryption.

    The encrypted data will be displayed or saved to a file (.enc extension).

Decryption:

    Select option 11 ("Decrypt data").

    Choose input method (file or string).

    Select your AES key (it must have CKA_DECRYPT enabled).

    Provide the exact IV (hex string) that was used during encryption.

    The decrypted data will be displayed or saved to a file (.dec extension, or original name if .enc was present).

e) Signing and Verifying Data (e.g., with RSA)

Signing:

    Generate an RSA key pair with the private key having CKA_SIGN enabled.

    Select option 8 ("Sign data").

    Choose input method (file or string).

    Select your RSA private key by label and type.

    The signature (hex string) will be displayed and can be saved to a file (.bin extension).

Verification:

    Select option 9 ("Verify signature").

    Choose input method (files or strings for original data and signature).

    Select your RSA public key by label and type.

    Provide the original data and the signature generated earlier.

    The tool will indicate if the signature is valid or invalid.

f) Setting CKA_TRUSTED Attribute

Important: This operation requires the preload utility and trustme.py script to be in the same directory. It also requires the key to be module-protected on nCipher HSMs, and you will need the Security Officer (SO) PIN.

    Select option 12 ("Set CKA_TRUSTED attribute (via external script)").

    Provide the key label, algorithm type (symmetric or asymmetric), and whether to set CKA_TRUSTED to true or false.

    Enter the Security Officer (SO) PIN when prompted.

    The trustme.py script will be executed as a subprocess, attempting to modify the attribute.

# 🤝 Contributing

Contributions are welcome! If you find a bug or have an idea for an enhancement, please open an issue or submit a pull request.

# 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/krypt0k1/hsmtool/blob/main/LICENSE) file for details.
