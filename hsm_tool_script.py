# Required functions for interacting with an HSM via PKCS#11

import pkcs11
import platform
import os
import getpass
import subprocess
from prettytable import PrettyTable
from pkcs11 import Attribute, KeyType, ObjectClass, Mechanism
from pkcs11.exceptions import *


# --- Constants ---
NFAST_MODULE_ENV_VAR = 'NFAST_MODULE'
# Default paths, can be overridden by the environment variable
NFAST_LINUX_PATH = '/opt/nfast/toolkits/pkcs11/libcknfast.so'
NFAST_WINDOWS_PATH = 'C:\\Program Files\\nCipher\\nfast\\toolkits\\pkcs11\\cknfast.dll'

# Supported EC Curves - customize this list based on your HSM's capabilities
SUPPORTED_EC_CURVES = [
    'c2pnb163v1', 'c2pnb163v2', 'c2pnb163v3', 'c2pnb176w1', 'c2tnb191v1',
    'c2tnb191v2', 'c2tnb191v3', 'c2onb191v4', 'c2onb191v5', 'c2pnb208w1',
    'c2tnb239v1', 'c2tnb239v2', 'c2tnb239v3', 'c2onb239v4', 'c2onb239v5',
    'c2pnb272w1', 'c2pnb304w1', 'c2tnb359v1', 'c2pnb368w1', 'c2tnb431r1',
    'prime192v2', 'prime192v3', 'prime239v1', 'prime239v2', 'prime239v3',
    'secp256r1', 'sect163k1', 'sect163r1', 'sect239k1', 'sect113r1',
    'sect113r2', 'secp112r1', 'secp112r2', 'secp160r1', 'secp160k1',
    'secp256k1', 'sect163r2', 'sect283k1', 'sect283r1', 'sect131r1',
    'sect131r2', 'sect193r1', 'sect193r2', 'sect233k1', 'sect233r1',
    'secp128r1', 'secp128r2', 'secp160r2', 'secp192k1', 'secp224k1',
    'secp224r1', 'secp384r1', 'secp521r1', 'sect409k1', 'sect409r1',
    'sect571k1', 'sect571r1', 'brainpoolp160r1', 'brainpoolp160t1',
    'brainpoolp192r1', 'brainpoolp192t1', 'brainpoolp224r1', 'brainpoolp224t1',
    'brainpoolp256r1', 'brainpoolp256t1', 'brainpoolp320r1', 'brainpoolp320t1',
    'brainpoolp384r1', 'brainpoolp384t1', 'brainpoolp512r1', 'brainpoolp512t1',
]
SUPPORTED_SYMMETRIC_KEY_TYPES = ['AES', 'DES2', 'DES3']
SUPPORTED_ASYMMETRIC_KEY_TYPES = ['RSA', 'DSA', 'EC']
# Combine all supported key types for easy reference
ALL_SUPPORTED_KEY_TYPES = SUPPORTED_SYMMETRIC_KEY_TYPES + SUPPORTED_ASYMMETRIC_KEY_TYPES


# --- Core Functions ---

def initialize_pkcs11_library():
    """
    Determines and sets the PKCS#11 library path, then loads the library.

    Returns:
        pkcs11.lib: The loaded PKCS#11 library object.

    Raises:
        ValueError: If the PKCS#11 library path cannot be determined or found.
        pkcs11.PKCS11Error: If there's an error loading the library.
    """
    lib_path = os.environ.get(NFAST_MODULE_ENV_VAR)
    if not lib_path:
        os_type = platform.system()
        if os_type == 'Linux':
            lib_path = NFAST_LINUX_PATH
            print(f"Environment variable {NFAST_MODULE_ENV_VAR} not set, defaulting to: {lib_path}")
            # Ensure nCipher binaries are in PATH for related tools like 'preload' if needed
            os.environ['NFAST_HOME'] = '/opt/nfast'
            os.environ['PATH'] = f"{os.environ['NFAST_HOME']}/bin:{os.environ['PATH']}"
            os.environ['PATH'] = f"{os.environ['NFAST_HOME']}/python3/:{os.environ['PATH']}"
        elif os_type == 'Windows':
            lib_path = NFAST_WINDOWS_PATH
            print(f"Environment variable {NFAST_MODULE_ENV_VAR} not set, defaulting to: {lib_path}")
            # Ensure nCipher binaries are in PATH
            os.environ['NFAST_HOME'] = 'C:\\Program Files\\nCipher\\nfast'
            os.environ['PATH'] = f"{os.environ['NFAST_HOME']}\\bin;{os.environ['PATH']}"
            os.environ['PATH'] = f"{os.environ['NFAST_HOME']}\\python3;{os.environ['PATH']}"
        else:
            raise ValueError(
                f"Unsupported OS '{os_type}'. Set the {NFAST_MODULE_ENV_VAR} "
                "environment variable to your PKCS#11 library path."
            )
        # Set it for the current process if defaulted, so it's consistent
        os.environ[NFAST_MODULE_ENV_VAR] = lib_path
    else:
        print(f"Using PKCS#11 library from environment variable {NFAST_MODULE_ENV_VAR}: {lib_path}")

    if not os.path.exists(lib_path):
        raise ValueError(
            f"PKCS#11 library not found at path: {lib_path}. "
            f"Please check the path or set the {NFAST_MODULE_ENV_VAR} environment variable.")
    return pkcs11.lib(lib_path)


def open_session():
    """
    Initializes the PKCS#11 library, lists available tokens,
    and opens a session with a user-selected token.

    Returns:
        pkcs11.Session: The opened session object, or None if opening fails.
    """
    try:
        lib = initialize_pkcs11_library()
        tokens = list(lib.get_tokens())

        if not tokens:
            print("No PKCS#11 tokens found. Please ensure your HSM is connected and configured.")
            return None

        print("\nAvailable tokens:")
        for i, token_info in enumerate(tokens):
            print(f"  {i + 1}. Label: '{token_info.label}' Manufacturer: {token_info.manufacturer_id}, "
                  f"Firmware: {token_info.firmware_version[0]}.{token_info.firmware_version[1]}")

        selected_token = None
        while not selected_token:
            choice_str = input(
                f"Select token by number (1-{len(tokens)}) or enter exact token label: ").strip()
            try:
                if choice_str.isdigit() and 1 <= int(choice_str) <= len(tokens):
                    selected_token = tokens[int(choice_str) - 1]
                else:
                    selected_token = lib.get_token(token_label=choice_str)
            except (ValueError, NoSuchToken):
                print("Invalid selection. Please enter a valid number or token label.")
            except PKCS11Error as e:
                print(f"Error selecting token: {e}")
                return None  # Cannot proceed

        pin = getpass.getpass(f"Enter PIN for token '{selected_token.label}': ")
        if not pin:
            print("PIN cannot be empty. Aborting session opening.")
            return None

        rw_input = input("Open read-write session? (yes/no) [default: no]: ").strip().lower()
        is_rw_session = rw_input == 'yes'

        session = selected_token.open(user_pin=pin, rw=is_rw_session)
        print(f"\nSuccessfully opened {'read-write' if is_rw_session else 'read-only'} session with token '{selected_token.label}'.")
        return session

    except (TokenNotPresent, TokenNotRecognized, TokenWriteProtected,
            NoSuchToken, UserNotLoggedIn, UserAlreadyLoggedIn,
            UserPinNotInitialized, UserTooManyTypes, OperationNotInitialized,
            DeviceError, DeviceRemoved, PinIncorrect, PinLocked, PinInvalid) as p11e:
        print(f"PKCS#11 Error during session opening: {p11e}")
    except ValueError as ve:
        print(f"Configuration Error: {ve}")
    except Exception as e:
        print(f"An unexpected error occurred during session opening: {e}")
    return None


# --- Menu and Operations ---

def display_menu(session):
    """
    Displays the operation menu and handles user choices.

    Args:
        session (pkcs11.Session): The active PKCS#11 session.
    """
    while True:
        print("\n" + "=" * 15 + " HSM Tool Menu " + "=" * 15)
        print(" 1. List available keys")
        print(" 2. Generate key/key-pair")
        print(" 3. Copy key")
        print(" 4. Delete key")
        print(" 5. Modify key attributes (individual attributes)")
        print(" 6. Wrap key")
        print(" 7. Unwrap key")
        print(" 8. Sign data")
        print(" 9. Verify signature")
        print(" 10. Encrypt data")
        print(" 11. Decrypt data ")
        print(" 12. Set CKA_TRUSTED attribute (via external script)")
        print(" 0. Exit")
        print("=" * 47)

        choice = input("Enter your choice: ").strip()

        try:
            if choice == '1':
                print("\n--- Listing available keys ---")
                list_all_keys(session)
            elif choice == '2':
                print("\n--- Generating key/key-pair ---")
                generate_hsm_key(session)
            elif choice == '3':
                print("\n--- Copying key ---")
                print("Note: Keys are copied within the same token.")
                copy_hsm_key(session)
            elif choice == '4':
                print("\n--- Deleting key ---")
                delete_key(session)
            elif choice == '5':
                print("\n--- Modifying key attributes ---")
                modify_key(session)
            elif choice == '6':
                print("\n--- Wrapping key ---")
                wrap_key(session)
            elif choice == '7':
                print("\n--- Unwrapping key ---")
                unwrap_key(session)
            elif choice == '8':
                print("\n--- Signing data ---")
                sign_data(session)
            elif choice == '9':
                print("\n--- Verifying signature ---")
                verify_signature(session)
            elif choice == '10':
                print("\n--- Encrypting data ---")
                encrypt_data(session)
            elif choice == '11':
                print("\n--- Decrypting data ---")
                decrypt_data(session)
            elif choice == '12':
                print("\n--- Setting CKA_TRUSTED attribute via external script ---")
                set_trusted_attribute(session)
            elif choice == '0':
                print("\nExiting HSM Tool...")
                break
            else:
                print("\nInvalid choice. Please select a valid option.")
        except PKCS11Error as e:
            print(f"\nAn error occurred during operation: {e}")
            print("Please check the details and try again if applicable.")
        except Exception as e:  # Catch any other unexpected errors during operations
            print(f"\nAn unexpected error occurred: {e}")
        finally:
            if choice != '0':  # Don't pause if exiting
                input("\nPress Enter to continue...")


# --- Function to call trustme as a subprocess ---
def set_trusted_attribute(session):
    """
    Executes trustme.py as a subprocess to modify the CKA_TRUSTED attribute.
    This function doesn not close the current PKCS#11 session
    because 'preload -s ncipher-pkcs11-so-softcard' will establish its own session.
    After the subprocess completes, it continues open the session for
    continued operation in the main HSM Tool (hsmtool.py).

    Args:
        session (pkcs11.Session): The active PKCS#11 session.
    """
    print("\nNote: This operation requires the 'preload' utility and 'trustme.py' script to be accessible in the current directory.")
    
    # List keys
    list_all_keys(session)
    print("\n--- Setting CKA_TRUSTED attribute ---")
    # Enter the key label, algorithm type, and CKA_TRUSTED value
    try:
        key_label = input("Enter the key label: ").strip()
        while not key_label:
            print("Key label cannot be empty.")
            key_label = input("Enter the key label: ").strip()

        algo_type = input("Enter the algorithm type (symmetric/asymmetric): ").strip().lower()
        while algo_type not in ['symmetric', 'asymmetric']:
            print("Invalid algorithm type. Please enter 'symmetric' or 'asymmetric'.")
            algo_type = input("Enter the algorithm type (symmetric/asymmetric): ").strip().lower()

        trusted_val_str = input("Set CKA_TRUSTED to true/false: ").strip().lower()
        while trusted_val_str not in ['true', 'false']:
            print("Invalid value. Please enter 'true' or 'false'.")
            trusted_val_str = input("Set CKA_TRUSTED to true/false: ").strip().lower()

        so_pin = getpass.getpass("Enter the Security Officer (SO) PIN for the token: ")
        if not so_pin:
            print("SO PIN is required to modify CKA_TRUSTED. Operation cancelled.")
            return

        # Construct the command to execute trustme.py with its arguments
        # Ensure 'preload' is in your system's PATH, and 'trustme.py' is in the same directory.
        command = [
            'preload',
            '-s',
            'ncipher-pkcs11-so-softcard', # This is specific to nCipher HSMs
            'python', # Use 'python' or 'python3' based on your system setup
            'trustme.py',
            '--label', key_label,
            '--algo', algo_type,
            '--trusted', trusted_val_str,
            '--pin', so_pin # Pass the SO PIN as an argument
        ]
        print(f"\nExecuting command: {' '.join(command)}")

        # Execute the subprocess and capture its output
        # Pass the SO_PIN to the subprocess's stdin
        result = subprocess.run(
            command,            
            capture_output=True, # Capture stdout and stderr
            text=True,           # Capture stdout and stderr as strings
            check=False,        # Do not raise CalledProcessError on non-zero exit
            input=so_pin + '\n', # Provide the SO PIN to stdin, followed by a newline
        )

        if result.stdout:
            print(result.stdout.strip())
        if result.stderr:
            print("--- Errors ---")
            print(result.stderr.strip())
        print("-------------------------\n")

        if result.returncode != 0:
            print(f"❌ CKA_TRUSTED modification script failed with Exit Code: {result.returncode}.")
            print("   Please review the error messages from 'trustme.py' and 'preload'.")
        else:
            print("✅ CKA_TRUSTED modification script executed successfully.")

    # -- Error Handling for subprocess execution --#
    except FileNotFoundError:
        print("❌ Error: 'preload' or 'python' command not found.")
        print("   Please ensure 'preload' is installed and in your system's PATH,")
        print("   and 'python' is correctly configured or specify the full path.")
    except Exception as e:
        print(f"❌ An unexpected error occurred while calling the script: {e}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error executing trustme.py: {e}")
        print("   Please ensure the script is accessible and the arguments are correct.")
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user.")

# --- Key Management Helper Functions ---

def _get_keys_by_class(session, key_class, class_name_str):
    """Helper function to retrieve keys of a specific class."""
    try:
        return list(session.get_objects({
            Attribute.CLASS: key_class,
            Attribute.TOKEN: True  # Only list keys residing on the token
        }))
    except PKCS11Error as e:
        print(f"Error listing {class_name_str.lower()} keys: {e}")
        return []


def _get_key_label(key_object):
    """Safely retrieves the label of a key object."""
    try:
        return key_object.label if key_object.label is not None else "N/A (No Label)"
    except PKCS11Error:  # Some attributes might not be readable on some keys/HSMs
        return "N/A (Label Unreadable)"
    except AttributeError:
        return "N/A (Label Attribute Missing)"


def _prompt_for_boolean(prompt_text, default_yes=True):
    """Helper to get a boolean (yes/no) input from the user."""
    default_str = "[Y/n]" if default_yes else "[y/N]"
    while True:
        val = input(f"{prompt_text} {default_str}: ").strip().lower()
        if not val:  # User pressed Enter, use default
            return default_yes
        if val in ['y', 'yes']:
            return True
        if val in ['n', 'no']:
            return False
        print("❌ Invalid input. Please enter 'yes' or 'no'.")


def print_key_attributes(key):
    """
    Prints the attributes of a given PKCS#11 key object in a formatted table.
    """
    # Mapping for Key Types
    key_type_map = {
        KeyType.RSA: "RSA", KeyType.DSA: "DSA", KeyType.DH: "DH", KeyType.EC: "EC",
        KeyType.DES2: "DES2", KeyType.DES3: "DES3", KeyType.AES: "AES",
        KeyType.EC_EDWARDS: "EC_EDWARDS"
    }

    # Mapping for Object Classes
    object_class_map = {
        ObjectClass.DATA: "DATA", ObjectClass.CERTIFICATE: "CERTIFICATE",
        ObjectClass.PUBLIC_KEY: "PUBLIC_KEY", ObjectClass.PRIVATE_KEY: "PRIVATE_KEY",
        ObjectClass.SECRET_KEY: "SECRET_KEY", ObjectClass.HW_FEATURE: "HW_FEATURE",
        ObjectClass.DOMAIN_PARAMETERS: "DOMAIN_PARAMETERS", ObjectClass.MECHANISM: "MECHANISM",
        ObjectClass.OTP_KEY: "OTP_KEY"
    }

    table = PrettyTable()
    table.field_names = ["Attribute", "Value"]
    table.padding_width = 1

    for attr in Attribute:
        try:
            # Skip some attributes for conciseness
            if attr in [
                    Attribute.MODULUS, Attribute.PUBLIC_EXPONENT, Attribute.ID,
                    Attribute.SUBJECT, Attribute.ISSUER, Attribute.SERIAL_NUMBER,
                    Attribute.VALUE,  # Raw value of symmetric keys or private exponent, often omitted
                    Attribute.EC_PARAMS,  # EC_PARAMS can be large, handled separately if needed
                    Attribute.EC_POINT,   # EC_POINT can be large and not useful in simple list
                    Attribute.PRIME,      # DSA Prime P. Only show bit length for DSA.
                    Attribute.SUBPRIME,   # DSA Subprime Q. Only show bit length for DSA.
                    Attribute.BASE,       # DSA Base G. Only show bit length for DSA.
            ]:
                continue

            value = key.__getitem__(attr)

            if value is not None:
                # Check if the attribute is Key Type or Object Class
                if attr == Attribute.KEY_TYPE:
                    value = key_type_map.get(value, f"Unknown Key Type ({value})")
                elif attr == Attribute.CLASS:
                    value = object_class_map.get(value, f"Unknown Object Class ({value})")
                elif isinstance(value, bytes):
                    value = value.hex()  # Convert bytes to hex string for display

                table.add_row([attr.name, value])
        except Exception:
            pass  # Ignore attributes that cannot be read for this key

    # Special handling for DSA primes and base if they are present and were skipped
    try:
        if key[Attribute.KEY_TYPE] == KeyType.DSA:
            try:
                prime_p = key[Attribute.PRIME]
                table.add_row(["PRIME (P) Bit Length", f"{len(prime_p) * 8} bits"])
            except Exception:
                pass
            try:
                subprime_q = key[Attribute.SUBPRIME]
                table.add_row(["SUBPRIME (Q) Bit Length", f"{len(subprime_q) * 8} bits"])
            except Exception:
                pass
            try:
                base_g = key[Attribute.BASE]
                table.add_row(["BASE (G) Bit Length", f"{len(base_g) * 8} bits"])
            except Exception:
                pass
    except Exception:
        pass # Ignore if key type cannot be read

    print(table)


def find_key_in_session(session, label, obj_class, key_type=None):
    """
    Searches for a key in the session based on label, object class, and optional key type.
    """
    print(
        f"Searching for key with label: '{label}' (Class: {obj_class.name}, Type: {key_type.name if key_type else 'Any'})")
    try:
        search_params = {
            Attribute.LABEL: label,
            Attribute.CLASS: obj_class,
            Attribute.TOKEN: True  # Ensure it's a token object
        }
        if key_type:
            search_params[Attribute.KEY_TYPE] = key_type

        keys = list(session.get_objects(search_params))
        if keys:
            key = keys[0]  # Assuming we want the first match
            print(f"✅ Found key: {_get_key_label(key)} ")
            return key
        else:
            print(f"❌ Key with label '{label}' not found.")
            return None
    except (NoSuchKey, MultipleObjectsFound, PKCS11Error) as e:
        print(f"❌ Error while searching for key '{label}': {e}")
        return None
    except Exception as e:
        print(f"❌ An unexpected error occurred while searching for key '{label}': {e}")
        return None


def get_key_for_crypto_op(session, required_attribute):
    """
    Prompts the user to select a key and validates its capabilities for a given crypto operation.
    Args:
        session (pkcs11.Session): The active PKCS#11 session.
        required_attribute (pkcs11.Attribute): The attribute the key must possess
                                               (e.g., Attribute.ENCRYPT, Attribute.DECRYPT,
                                               Attribute.SIGN, Attribute.VERIFY).
    Returns:
        pkcs11.ObjectClass: The key object if found and suitable, otherwise None.
    """
    list_all_keys(session)  # Show available keys

    key_label = input(f"Enter the label of the key to perform {required_attribute.name.lower()} with: ").strip()
    object_class_str = input(
        "Enter the object class of the key [SECRET_KEY, PRIVATE_KEY, PUBLIC_KEY]: ").strip().upper()
    key_type_str = input(
        f"Enter the key type of the key [{', '.join(ALL_SUPPORTED_KEY_TYPES)}]: ").strip().upper()

    obj_class_map = {
        'SECRET_KEY': ObjectClass.SECRET_KEY,
        'PRIVATE_KEY': ObjectClass.PRIVATE_KEY,
        'PUBLIC_KEY': ObjectClass.PUBLIC_KEY,
    }
    key_type_map = {
        'AES': KeyType.AES, 'DES2': KeyType.DES2, 'DES3': KeyType.DES3,
        'RSA': KeyType.RSA, 'DSA': KeyType.DSA, 'EC': KeyType.EC
    }

    obj_class_enum = obj_class_map.get(object_class_str)
    key_type_enum = key_type_map.get(key_type_str)

    if obj_class_enum is None:
        print("❌ Invalid object class provided. Aborting.")
        return None
    if key_type_enum is None:
        print("❌ Invalid key type provided. Aborting.")
        return None

    # Basic capability check based on object class and key type for clarity before finding the key
    if required_attribute == Attribute.ENCRYPT:
        if (obj_class_enum == ObjectClass.PRIVATE_KEY) or \
           (obj_class_enum == ObjectClass.PUBLIC_KEY and key_type_enum not in [KeyType.RSA, KeyType.EC]) or \
           (obj_class_enum == ObjectClass.SECRET_KEY and key_type_enum not in [KeyType.AES, KeyType.DES2, KeyType.DES3]):
            print(f"❌ Invalid key type/class for encryption. Only symmetric keys (SECRET_KEY) or "
                  f"asymmetric public keys (RSA, EC) are typically used for encryption.")
            return None
    elif required_attribute == Attribute.DECRYPT:
        if (obj_class_enum == ObjectClass.PUBLIC_KEY) or \
           (obj_class_enum == ObjectClass.PRIVATE_KEY and key_type_enum not in [KeyType.RSA, KeyType.EC]) or \
           (obj_class_enum == ObjectClass.SECRET_KEY and key_type_enum not in [KeyType.AES, KeyType.DES2, KeyType.DES3]):
            print("❌ Invalid key type/class for decryption. Only symmetric keys (SECRET_KEY) or "
                  "asymmetric private keys (RSA, EC) are typically used for decryption.")
            return None
    elif required_attribute == Attribute.SIGN:
        if obj_class_enum not in [ObjectClass.SECRET_KEY, ObjectClass.PRIVATE_KEY]:
            print("❌ Only secret or private keys can be used for signing.")
            return None
    elif required_attribute == Attribute.VERIFY:
        if obj_class_enum not in [ObjectClass.PUBLIC_KEY]:
            print("❌ Only public keys can typically be used for signature verification.")
            return None

    key = find_key_in_session(
        session,
        key_label,
        obj_class_enum,
        key_type_enum
    )

    if not key:
        return None

    # Deeper check for the specific required attribute on the found key
    try:
        if not key.__getitem__(required_attribute):
            print(f"❌ The key '{_get_key_label(key)}' is not capable of {required_attribute.name.lower()} "
                  f"(CKA_{required_attribute.name} is False).")
            return None
        print(f"✅ Key '{_get_key_label(key)}' found and is capable of {required_attribute.name.lower()}.")
        return key
    except PKCS11Error:
        print(f"❌ Could not read attribute CKA_{required_attribute.name} from key '{_get_key_label(key)}'.")
        return None


# --- Key Management Functions ---

def list_all_keys(session):
    """Lists all available secret, private, and public keys in the token."""
    print("Fetching keys, this might take a moment...")

    key_types_to_list = [
        (ObjectClass.SECRET_KEY, "Secret Keys"),
        (ObjectClass.PRIVATE_KEY, "Private Keys"),
        (ObjectClass.PUBLIC_KEY, "Public Keys"),
        (ObjectClass.CERTIFICATE, "Certificates"),
        (ObjectClass.DOMAIN_PARAMETERS, "Domain Parameters"),
    ]

    found_any_keys = False
    for key_class, description in key_types_to_list:
        print(f"\n{description}:")
        keys = _get_keys_by_class(session, key_class, description)
        if keys:
            found_any_keys = True
            for key in keys:
                label = _get_key_label(key)
                key_type_str = "Unknown"
                try:
                    key_type_attr = key[Attribute.KEY_TYPE]
                    key_type_str = KeyType(key_type_attr).name
                except (PKCS11Error, KeyError, ValueError):
                    pass # Key might not have a type attribute or it's unreadable

                print(f"  - Label: {label} Type: {key_type_str} ")
        else:
            print(f"  - No {description.lower()} found.")

    if not found_any_keys:
        print("\nNo keys found on the token in any category.")


def _get_base_key_template(key_label):
    """Returns a base template with common attributes for key generation."""
    return {
        Attribute.TOKEN: True,
        Attribute.LABEL: key_label,
        # Default to secure attributes, user can override
        Attribute.SENSITIVE: True,
        Attribute.EXTRACTABLE: False,
    }


def generate_hsm_key(session):
    """Generates a key or key-pair on the HSM token based on user input."""
    try:
        print("Supported key types: " + ", ".join(ALL_SUPPORTED_KEY_TYPES))
        key_type_input = input("Enter key type: ").strip().upper()

        if key_type_input not in ALL_SUPPORTED_KEY_TYPES:
            print(f"❌ Unsupported key type: {key_type_input}")
            return

        key_label = ""
        while not key_label:
            key_label = input("Enter key label (cannot be empty): ").strip()
            if not key_label:
                print("❌ Key label is mandatory.")

        base_template = _get_base_key_template(key_label)

        # --- Symmetric Key Generation ---
        if key_type_input in SUPPORTED_SYMMETRIC_KEY_TYPES:
            pkcs11_key_type = getattr(KeyType, key_type_input)
            default_size = 256 if key_type_input == 'AES' else 192
            key_size_bits = 0
            while key_size_bits <= 0:
                try:
                    size_input = input(
                        f"Enter key size in bits (e.g., for AES: 128, 192, 256; default: {default_size}): ").strip()
                    key_size_bits = int(size_input) if size_input else default_size
                    if key_size_bits <= 0:
                        print("❌ Key size must be a positive integer.")
                except ValueError:
                    print("❌ Invalid key size. Please enter an integer.")

            template = base_template.copy()
            template.update({
                Attribute.ENCRYPT: _prompt_for_boolean("Allow key for encryption?", default_yes=True),
                Attribute.DECRYPT: _prompt_for_boolean("Allow key for decryption?", default_yes=True),
                Attribute.SIGN: False,
                Attribute.VERIFY: False,
                Attribute.WRAP: _prompt_for_boolean("Allow key for wrapping other keys?", default_yes=False),
                Attribute.UNWRAP: _prompt_for_boolean("Allow key for unwrapping other keys?", default_yes=False),
            })
            template[Attribute.SENSITIVE] = _prompt_for_boolean(
                "Mark as SENSITIVE (cannot be revealed)?", default_yes=True)
            if template[Attribute.SENSITIVE]:
                template[Attribute.EXTRACTABLE] = _prompt_for_boolean(
                    "Allow key to be EXTRACTABLE (e.g., for wrapping)?", default_yes=False)
            else:
                template[Attribute.EXTRACTABLE] = _prompt_for_boolean(
                    "Allow key to be EXTRACTABLE?", default_yes=True)

            generated_key = session.generate_key(
                pkcs11_key_type, key_size_bits, template=template)
            print(f"\n{key_type_input} key '{_get_key_label(generated_key)}' generated successfully.")
            print_key_attributes(generated_key)

        # --- Asymmetric Key Pair Generation ---
        elif key_type_input in SUPPORTED_ASYMMETRIC_KEY_TYPES:
            pkcs11_key_type_enum = getattr(KeyType, key_type_input)
            public_key, private_key = None, None

            if key_type_input == 'RSA':
                public_template = get_rsa_public_template()
                public_template.update({Attribute.LABEL: key_label})

                private_template = get_rsa_private_template()
                private_template.update({Attribute.LABEL: key_label})
                private_template[Attribute.SENSITIVE] = _prompt_for_boolean("Mark private key as SENSITIVE?", default_yes=True)
                if private_template[Attribute.SENSITIVE]:
                    private_template[Attribute.EXTRACTABLE] = _prompt_for_boolean("Allow private key to be EXTRACTABLE?", default_yes=False)
                else:
                    private_template[Attribute.EXTRACTABLE] = _prompt_for_boolean("Allow private key to be EXTRACTABLE?", default_yes=True)

                key_size_bits = 0
                valid_rsa_sizes = [1024, 2048, 3072, 4096]
                while key_size_bits not in valid_rsa_sizes:
                    try:
                        size_input = input(
                            f"Enter RSA key size in bits ({', '.join(map(str, valid_rsa_sizes))}) [default: 2048]: ").strip()
                        key_size_bits = int(size_input) if size_input else 2048
                        if key_size_bits not in valid_rsa_sizes:
                            print("Please choose a standard RSA key size.")
                    except ValueError:
                        print("❌ Invalid key size. Please enter an integer.")

                public_key, private_key = session.generate_keypair(
                    pkcs11_key_type_enum, key_size_bits,
                    public_template=public_template,
                    private_template=private_template
                )
            elif key_type_input == 'DSA':
                # DSA key generation often involves two steps: generating domain parameters, then the key pair.               
                # Key size for DSA refers to the prime modulus length (L).
                key_size_bits = 1024 # Fixed for stability; higher sizes cause errors with nCipher HSMs.
                print(f"Note: DSA prime modulus length (L) is fixed to {key_size_bits} bits for stability.")

                public_template = get_dsa_public_template()
                public_template.update({Attribute.LABEL: key_label})

                private_template = get_dsa_private_template()
                private_template.update({Attribute.LABEL: key_label})
                private_template[Attribute.SENSITIVE] = _prompt_for_boolean("Mark private key as SENSITIVE?", default_yes=True)
                if private_template[Attribute.SENSITIVE]:
                    private_template[Attribute.EXTRACTABLE] = _prompt_for_boolean("Allow private key to be EXTRACTABLE?", default_yes=False)
                else:
                    private_template[Attribute.EXTRACTABLE] = _prompt_for_boolean("Allow private key to be EXTRACTABLE?", default_yes=True)

                public_key, private_key = session.generate_keypair(
                    pkcs11_key_type_enum,
                    key_size_bits, # This is the L-value for DSA for generate_keypair
                    public_template=public_template,
                    private_template=private_template
                )

            elif key_type_input == 'EC':
                public_template = get_ec_public_template()
                public_template.update({Attribute.LABEL: key_label})

                private_template = get_ec_private_template()
                private_template.update({Attribute.LABEL: key_label})
                private_template[Attribute.SENSITIVE] = _prompt_for_boolean("Mark private key as SENSITIVE?", default_yes=True)
                if private_template[Attribute.SENSITIVE]:
                    private_template[Attribute.EXTRACTABLE] = _prompt_for_boolean("Allow private key to be EXTRACTABLE?", default_yes=False)
                else:
                    private_template[Attribute.EXTRACTABLE] = _prompt_for_boolean("Allow private key to be EXTRACTABLE?", default_yes=True)

                print("\nAvailable EC Curves:")
                for i, curve in enumerate(SUPPORTED_EC_CURVES):
                    print(f"  {i+1}. {curve}")
                selected_curve_name = ""
                while not selected_curve_name:
                    curve_choice = input(
                        f"Select curve by number or name (e.g., secp256r1): ").strip()
                    if curve_choice.isdigit() and 1 <= int(curve_choice) <= len(SUPPORTED_EC_CURVES):
                        selected_curve_name = SUPPORTED_EC_CURVES[int(curve_choice) - 1]
                    elif curve_choice in SUPPORTED_EC_CURVES:
                        selected_curve_name = curve_choice
                    else:
                        print("❌ Invalid curve selection. Please choose from the list.")

                from pkcs11.util.ec import encode_named_curve_parameters
                ec_params_encoded = encode_named_curve_parameters(selected_curve_name)
                public_template[Attribute.EC_PARAMS] = ec_params_encoded

                public_key, private_key = session.generate_keypair(
                    pkcs11_key_type_enum,
                    # No key_size_bits parameter for EC usually, it's derived from curve
                    public_template=public_template,
                    private_template=private_template,
                )

            if public_key and private_key:
                print(f"\n{key_type_input} key pair generated successfully:")
                print(f"  Public Key:  '{public_key.label}'")
                print_key_attributes(public_key)
                print(f"  Private Key: '{private_key.label}'")
                print_key_attributes(private_key)
            else:
                print(f"\n❌ Failed to generate {key_type_input} key pair.")

    except (ExceededMaxIterations, FunctionFailed, MechanismInvalid, OperationActive,
            SessionClosed, SessionReadOnly, KeyTypeInconsistent, KeySizeRange,
            PKCS11Error) as e:
        print(f"❌ Error generating key: {e}")
    except ValueError as e:
        print(f"❌ Invalid input: {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred during key generation: {e}")


def copy_hsm_key(session):
    """Copies a key within the same token, assigning a new label."""
    original_key_label = ""
    try:
        print("\nAvailable keys for copying (secrets, private keys, public keys):")
        list_all_keys(session)

        key_type_to_copy_str = ""
        while key_type_to_copy_str not in ALL_SUPPORTED_KEY_TYPES:
            key_type_to_copy_str = input(
                f"Enter type of key to copy ({', '.join(ALL_SUPPORTED_KEY_TYPES)}): ").strip().upper()
            if key_type_to_copy_str not in ALL_SUPPORTED_KEY_TYPES:
                print(f"❌ Unsupported key type: {key_type_to_copy_str}. Please choose from the list.")

        original_key_label = ""
        while not original_key_label:
            original_key_label = input("Enter the label of the key to copy: ").strip()
            if not original_key_label:
                print("Original key label cannot be empty.")

        new_key_label = ""
        while not new_key_label or new_key_label == original_key_label:
            new_key_label = input(
                "Enter the new label for the copied key (must be different): ").strip()
            if not new_key_label:
                print("New key label cannot be empty.")
            elif new_key_label == original_key_label:
                print("New key label must be different from the original key label.")

        key_class_to_find = None
        key_type_enum = getattr(KeyType, key_type_to_copy_str)

        if key_type_to_copy_str in SUPPORTED_SYMMETRIC_KEY_TYPES:
            key_class_to_find = ObjectClass.SECRET_KEY
            key_to_copy = find_key_in_session(
                session, original_key_label, key_class_to_find, key_type_enum)
            if not key_to_copy:
                return

            new_key_attributes = {
                Attribute.TOKEN: True,
                Attribute.LABEL: new_key_label
            }
            # Copy relevant attributes, respecting security best practices
            # For a copy, generally inherit sensitive/extractable from original if allowed            
            try:
                new_key_attributes[Attribute.SENSITIVE] = key_to_copy[Attribute.SENSITIVE]
                new_key_attributes[Attribute.EXTRACTABLE] = key_to_copy[Attribute.EXTRACTABLE]
            except PKCS11Error:
                # If attributes cannot be read, default to secure values
                new_key_attributes[Attribute.SENSITIVE] = True
                new_key_attributes[Attribute.EXTRACTABLE] = False

            copied_key = key_to_copy.copy(new_key_attributes)
            print(f"\n✅ Secret key '{_get_key_label(copied_key)}' copied successfully from '{original_key_label}'.")
            print_key_attributes(copied_key)

        elif key_type_to_copy_str in SUPPORTED_ASYMMETRIC_KEY_TYPES:
            copied_private = False
            copied_public = False

            # Try to copy Private Key
            private_key_to_copy = find_key_in_session(
                session, original_key_label, ObjectClass.PRIVATE_KEY, key_type_enum)
            if private_key_to_copy:
                new_private_attrs = {
                    Attribute.TOKEN: True,
                    Attribute.LABEL: new_key_label
                }
                try:
                    new_private_attrs[Attribute.SENSITIVE] = private_key_to_copy[Attribute.SENSITIVE]
                    new_private_attrs[Attribute.EXTRACTABLE] = private_key_to_copy[Attribute.EXTRACTABLE]
                except PKCS11Error:
                    new_private_attrs[Attribute.SENSITIVE] = True
                    new_private_attrs[Attribute.EXTRACTABLE] = False

                copied_private_key = private_key_to_copy.copy(new_private_attrs)
                print(f"\n✅ Private key '{_get_key_label(copied_private_key)}' copied successfully from '{original_key_label}'.")
                print_key_attributes(copied_private_key)
                copied_private = True
            else:
                print(f"\n❌ Private key with label '{original_key_label}' not found for copying.")

            # Try to copy Public Key
            public_key_to_copy = find_key_in_session(
                session, original_key_label, ObjectClass.PUBLIC_KEY, key_type_enum)
            if public_key_to_copy:
                new_public_attrs = {
                    Attribute.TOKEN: True,
                    Attribute.LABEL: new_key_label
                }
                copied_public_key = public_key_to_copy.copy(new_public_attrs)
                print(f"✅ Public key '{_get_key_label(copied_public_key)}' copied successfully from '{original_key_label}'.")
                print_key_attributes(copied_public_key)
                copied_public = True
            else:
                print(f"❌ Public key with label '{original_key_label}' not found for copying.")

            if not copied_private and not copied_public:
                print(f"\n❌ No parts of asymmetric key '{original_key_label}' were copied.")
        else:
            print(f"❌ Internal error: Unhandled key type for copying: {key_type_to_copy_str}")

    except (NoSuchKey, MultipleObjectsFound, PKCS11Error) as e:
        print(f"❌ Error during key copy: {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred during key copy: {e}")


def delete_key(session):
    """Deletes a key from the HSM token based on user input."""
    try:
        print("\nAvailable keys for deletion (secrets, private keys, public keys):")
        list_all_keys(session)

        key_type_to_delete_str = ""
        while key_type_to_delete_str not in ALL_SUPPORTED_KEY_TYPES:
            key_type_to_delete_str = input(
                f"Enter type of key to delete ({', '.join(ALL_SUPPORTED_KEY_TYPES)}): ").strip().upper()
            if key_type_to_delete_str not in ALL_SUPPORTED_KEY_TYPES:
                print(f"❌ Unsupported key type: {key_type_to_delete_str}. Please choose from the list.")

        key_label = ""
        while not key_label:
            key_label = input("Enter the label of the key to delete: ").strip()
            if not key_label:
                print("❌ Key label cannot be empty.")

        key_class_to_find = None
        if key_type_to_delete_str in SUPPORTED_SYMMETRIC_KEY_TYPES:
            key_class_to_find = ObjectClass.SECRET_KEY
        elif key_type_to_delete_str in SUPPORTED_ASYMMETRIC_KEY_TYPES:
            key_class_to_find = ObjectClass.PRIVATE_KEY # For asymmetric, we'll try private first, then public.
        else:
            print(f"❌ Internal error: Unhandled key type for deletion: {key_type_to_delete_str}")
            return

        # Try to delete private/secret key first
        key_to_delete_private_or_secret = find_key_in_session(
            session, key_label, key_class_to_find, getattr(KeyType, key_type_to_delete_str))

        if key_to_delete_private_or_secret:
            confirm = input(
                f"Are you sure you want to delete the key '{_get_key_label(key_to_delete_private_or_secret)}'? (yes/no): ").strip().lower()
            if confirm in ['yes', 'y']:
                key_to_delete_private_or_secret.destroy()
                print(f"✅ Key '{_get_key_label(key_to_delete_private_or_secret)}' deleted successfully.")

                if key_class_to_find == ObjectClass.PRIVATE_KEY:
                    # If it was a private key, also attempt to delete the corresponding public key
                    public_key_to_delete = find_key_in_session(
                        session, key_label, ObjectClass.PUBLIC_KEY, getattr(KeyType, key_type_to_delete_str))
                    if public_key_to_delete:
                        public_key_to_delete.destroy()
                        print(f"✅ Associated public key '{_get_key_label(public_key_to_delete)}' also deleted.")
            else:
                print("❌ Deletion cancelled.")
        else:
            print(f"❌ No key found with label '{key_label}' and specified type/class for deletion.")

    except PKCS11Error as e:
        print(f"❌ Error deleting key: {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred during key deletion: {e}")


def modify_key(session):
    """
    Modify key attributes.
    """
    try:
        list_all_keys(session)
        key_label = input("Enter the label of the key to modify: ").strip()
        object_class_str = input(
            "Enter the object class (SECRET_KEY, PRIVATE_KEY, PUBLIC_KEY): ").strip().upper()

        obj_class_map = {
            'SECRET_KEY': ObjectClass.SECRET_KEY,
            'PRIVATE_KEY': ObjectClass.PRIVATE_KEY,
            'PUBLIC_KEY': ObjectClass.PUBLIC_KEY
        }

        if object_class_str not in obj_class_map:
            print(
                "❌ Invalid object class. Please enter SECRET_KEY, PRIVATE_KEY, or PUBLIC_KEY.")
            return

        object_class = obj_class_map[object_class_str]
        key = find_key_in_session(session, key_label, object_class)

        if not key:
            print(
                f"❌ No key found with label '{key_label}' and object class '{object_class_str}'.")
            return

        print(f"Modifying attributes for key: {_get_key_label(key)}")

        # Display current attributes
        print("Current attributes:")
        print_key_attributes(key)

        # Menu to modify attributes
        print("\nSelect an attribute to modify:")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Sign")
        print("4. Verify")
        print("5. Wrap")
        print("6. Unwrap")
        print("7. Extractable")
        print("0. Exit")

        choice = input("Enter your choice (0-7): ").strip()

        if choice == '0':
            print("Exiting modification. Returning to main menu...\n")
            return

        attr_to_modify = None
        if choice == '1':
            attr_to_modify = Attribute.ENCRYPT
        elif choice == '2':
            attr_to_modify = Attribute.DECRYPT
        elif choice == '3':
            attr_to_modify = Attribute.SIGN
        elif choice == '4':
            attr_to_modify = Attribute.VERIFY
        elif choice == '5':
            attr_to_modify = Attribute.WRAP
        elif choice == '6':
            attr_to_modify = Attribute.UNWRAP
        elif choice == '7':
            attr_to_modify = Attribute.EXTRACTABLE
        else:
            print("❌ Invalid choice. Please try again.")
            return

        # Prompt for boolean value
        new_value = _prompt_for_boolean(
            f"Set {attr_to_modify.name} (True/False)?")
        key.__setitem__(attr_to_modify, new_value)
        print(f"Key attribute {attr_to_modify.name} modified successfully.\n")
        print_key_attributes(key)  # Print the updated attributes

    except AttributeReadOnly:
        print("❌ This attribute is read-only and cannot be modified.")
    except PKCS11Error as e:
        print(f"❌ Error modifying key attributes: {e}")
        print("Please ensure you have sufficient permissions and the attribute is modifiable.")
    except Exception as e:
        print(f"❌ An unexpected error occurred during key modification: {e}")

# --- Key Wrapping/Unwrapping Helper Templates ---
def get_public_template(key_type):
    """
    Returns the appropriate public template based on the key type.

    :param key_type: The type of the key (e.g., "RSA", "EC").
    :return: The public template for the specified key type.
    """
    if key_type == "RSA":
        return get_rsa_public_template()
    elif key_type == "EC":
        return get_ec_public_template()
    elif key_type == "DSA":
        return get_dsa_public_template()
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

def get_symmetric_template():
    """Returns a template for symmetric keys."""
    return {
        Attribute.TOKEN: True,
        Attribute.SENSITIVE: True,
        Attribute.ENCRYPT: True,
        Attribute.DECRYPT: True,
        Attribute.WRAP: True,
        Attribute.UNWRAP: True,
        Attribute.EXTRACTABLE: False,
    }

def get_rsa_private_template():
    """Returns a template for RSA private keys."""
    return {
        Attribute.TOKEN: True,
        Attribute.SENSITIVE: True,
        Attribute.SIGN: True,
        Attribute.DECRYPT: True,
        Attribute.UNWRAP: True,
        Attribute.EXTRACTABLE: False,
        Attribute.PRIVATE: True,
    }

def get_rsa_public_template():
    """Returns a template for RSA public keys."""
    return {
        Attribute.TOKEN: True,
        Attribute.VERIFY: True,
        Attribute.ENCRYPT: True,  # RSA public keys can encrypt
        Attribute.WRAP: True,  # Can wrap symmetric keys
    }

def get_dsa_private_template():
    """Returns a template for DSA private keys."""
    return {
        Attribute.TOKEN: True,
        Attribute.PRIVATE: True,
        Attribute.SIGN: True,
        Attribute.SENSITIVE: True,
        Attribute.EXTRACTABLE: False,
    }

def get_dsa_public_template():
    """Returns a template for DSA public keys."""
    return {
        Attribute.TOKEN: True,
        Attribute.VERIFY: True,
        Attribute.ENCRYPT: False,  # DSA public keys generally don't encrypt
        Attribute.WRAP: False,     # DSA public keys generally don't wrap
    }

def get_ec_private_template():
    """Returns a template for EC private keys."""
    return {
        Attribute.TOKEN: True,
        Attribute.SENSITIVE: True,
        Attribute.SIGN: True,
        Attribute.DECRYPT: False,  # EC private keys typically for signing/key agreement, not decrypt
        Attribute.UNWRAP: True,
        Attribute.EXTRACTABLE: False,
        Attribute.PRIVATE: True,
    }

def get_ec_public_template():
    """Returns a template for unwrapped EC public keys."""
    return {
        Attribute.TOKEN: True,
        Attribute.VERIFY: True,
        Attribute.ENCRYPT: True,  # EC public keys can encrypt (e.g., using ECIES)
        Attribute.WRAP: True,  # Can wrap symmetric keys
    }

# --- Cryptographic Operations ---

def wrap_key(session):
    """Wraps a key using another key on the HSM token."""
    try:
        list_all_keys(session)

        print("\nSelect a wrapping scenario:")
        print("1. Wrap AES key with RSA public key")
        print("2. Wrap AES key with another AES key")
        print("0. Exit\n")

        choice = input("Enter your choice (0-2): ").strip()

        if choice == '0':
            print("Returning to main menu...")
            return
        elif choice not in ['1', '2']:
            print("Invalid choice. Please try again.")
            return

        if choice == '1':
            print("\nWrapping AES key with RSA public key...")
            rsa_pub_for_wrapping_label = input(
                "Enter the label of the RSA public key for wrapping: ").strip()
            aes_to_be_wrapped_by_rsa_label = input(
                "Enter the label of the AES key to be wrapped by RSA: ").strip()

            print("--- Locating Keys ---")
            rsa_wrapping_public_key = find_key_in_session(
                session, rsa_pub_for_wrapping_label, ObjectClass.PUBLIC_KEY, KeyType.RSA)
            aes_key_to_be_wrapped_by_rsa = find_key_in_session(
                session, aes_to_be_wrapped_by_rsa_label, ObjectClass.SECRET_KEY, KeyType.AES)
            print("--- Finished Locating Keys ---\n")

            if not rsa_wrapping_public_key or not aes_key_to_be_wrapped_by_rsa:
                print("❌ Required keys not found. Cannot proceed with wrapping.")
                return

            # Explicitly define the mechanism for RSA wrapping (e.g., RSA_PKCS_OAEP).          
            wrapped_aes_key = rsa_wrapping_public_key.wrap_key(
                aes_key_to_be_wrapped_by_rsa, mechanism=Mechanism.RSA_PKCS_OAEP)
            print(f"✅ Wrapped AES key successfully. Wrapped data length: {len(wrapped_aes_key)} bytes.")

            wrapped_file_name = f"{aes_to_be_wrapped_by_rsa_label}_wrapped_by_{rsa_pub_for_wrapping_label}.wrapped"
            with open(wrapped_file_name, 'wb') as f:
                f.write(wrapped_aes_key)
            print(f"✅ Wrapped key saved to file: {wrapped_file_name} in current working directory\n")

        elif choice == '2':
            print("\nWrapping AES key with another AES key...")
            aes_wrapping_label = input(
                "Enter the label of the AES key for wrapping: ").strip()
            aes_to_be_wrapped_label = input(
                "Enter the label of the AES key to be wrapped: ").strip()

            if aes_wrapping_label == aes_to_be_wrapped_label:
                print("❌ AES wrapping key and AES key to be wrapped cannot have the same label. Exiting...")
                return

            print("--- Locating Keys ---")
            aes_wrapping_key = find_key_in_session(
                session, aes_wrapping_label, ObjectClass.SECRET_KEY, KeyType.AES)
            aes_key_to_be_wrapped = find_key_in_session(
                session, aes_to_be_wrapped_label, ObjectClass.SECRET_KEY, KeyType.AES)
            print("--- Finished Locating Keys ---\n")

            if not aes_wrapping_key or not aes_key_to_be_wrapped:
                print("❌ Required keys not found. Cannot proceed with wrapping.")
                return

            wrapped_aes_key = aes_wrapping_key.wrap_key(aes_key_to_be_wrapped, mechanism=Mechanism.AES_KEY_WRAP)
            print(f"✅ Wrapped AES key successfully. Wrapped data length: {len(wrapped_aes_key)} bytes.")

            wrapped_file_name = f"{aes_to_be_wrapped_label}_wrapped_by_{aes_wrapping_label}.wrapped"
            with open(wrapped_file_name, 'wb') as f:
                f.write(wrapped_aes_key)
            print(f"✅ Wrapped key saved to file: {wrapped_file_name} in current working directory\n")

    except (KeyUnextractable, KeyNotWrappable, ObjectHandleInvalid, MechanismInvalid,
            MechanismParamInvalid, PKCS11Error) as e:
        print(f"❌ Error during key wrapping: {e}")
        print("Please ensure the keys are compatible for wrapping and have the correct attributes (e.g., CKA_WRAP).")
    except Exception as e:
        print(f"❌ An unexpected error occurred during key wrapping: {e}")

def unwrap_key(session):
    """Unwraps a wrapped key file using a wrapping key on the HSM token."""
    try:
        list_all_keys(session)
        print("\nSelect an unwrapping scenario:")
        print("1. Unwrap AES key with RSA private key")
        print("2. Unwrap AES key with another AES key")
        print("0. Exit\n")

        choice = input("Enter your choice (0-2): ").strip()
        if choice == '0':
            print("Returning to main menu...")
            return
        elif choice not in ['1', '2']:
            print("Invalid choice. Please try again.")
            return

        if choice == '1':
            print("\nUnwrapping AES key with RSA private key...")
            rsa_priv_for_unwrapping_label = input(
                "Enter the label of the RSA private key for unwrapping: ").strip()
            wrapped_file_name = input(
                "Enter the file name of the wrapped AES key: ").strip()

            print("--- Locating Unwrapping Key and Wrapped Key Material ---")
            rsa_unwrapping_private_key = find_key_in_session(
                session, rsa_priv_for_unwrapping_label, ObjectClass.PRIVATE_KEY, KeyType.RSA)

            if not rsa_unwrapping_private_key:
                print(
                    f"❌ RSA private key with label '{rsa_priv_for_unwrapping_label}' not found. Cannot proceed.")
                return

            aes_key_to_be_unwrapped_by_rsa = None
            try:
                with open(wrapped_file_name, 'rb') as f:
                    aes_key_to_be_unwrapped_by_rsa = f.read()
                print(f"✅ Found wrapped AES key in file: {wrapped_file_name}")
            except FileNotFoundError:
                print(
                    f"❌ Wrapped AES key file '{wrapped_file_name}' not found. Cannot proceed.")
                return
            except PermissionError:
                print(f"❌ Permission denied while accessing file '{wrapped_file_name}'.")
                return
            except Exception as e:
                print(
                    f"❌ Error reading wrapped AES key file: {e}. Cannot proceed.")
                return

            print("--- Finished Locating Unwrapping Key and Wrapped Key Material ---\n")

            new_aes_label = ""
            while not new_aes_label:
                new_aes_label = input("Enter label for the unwrapped AES key: ").strip()
                if not new_aes_label:
                    print("New label for unwrapped key cannot be empty. Aborting unwrap.")

            unwrapped_aes_key = rsa_unwrapping_private_key.unwrap_key(
                key_type=KeyType.AES,
                object_class=ObjectClass.SECRET_KEY,
                label=new_aes_label,
                key_data=aes_key_to_be_unwrapped_by_rsa,
                mechanism=Mechanism.RSA_PKCS_OAEP, # Explicitly use RSA-OAEP for unwrap
                template=get_symmetric_template(),
                store=True,
            )

            print(f"✅ Unwrapped AES key successfully: {_get_key_label(unwrapped_aes_key)} ")
            print("Attributes of the unwrapped key:")
            print_key_attributes(unwrapped_aes_key)

        elif choice == '2':
            print("\nUnwrapping AES key with another AES key...")
            aes_unwrapping_label = input(
                "Enter the label of the AES key for unwrapping: ").strip()
            wrapped_file_name = input(
                "Enter the file name of the wrapped AES key: ").strip()

            aes_unwrapping_key = find_key_in_session(
                session, aes_unwrapping_label, ObjectClass.SECRET_KEY, KeyType.AES)

            if not aes_unwrapping_key:
                print(
                    f"❌ AES unwrapping key with label '{aes_unwrapping_label}' not found. Cannot proceed.")
                return

            aes_key_to_be_unwrapped = None
            try:
                with open(wrapped_file_name, 'rb') as f:
                    aes_key_to_be_unwrapped = f.read()
                print(f"✅ Found wrapped AES key in file: {wrapped_file_name}")
            except FileNotFoundError:
                print(
                    f"❌ Wrapped AES key file '{wrapped_file_name}' not found. Cannot proceed.")
                return
            except PermissionError:
                print(f"❌ Permission denied while accessing file '{wrapped_file_name}'.")
                return
            except Exception as e:
                print(
                    f"❌ Error reading wrapped AES key file: {e}. Cannot proceed.")
                return

            new_aes_label = ""
            while not new_aes_label:
                new_aes_label = input("Enter label for the unwrapped AES key: ").strip()
                if not new_aes_label:
                    print("New label for unwrapped key cannot be empty. Aborting unwrap.")

            unwrapped_aes_key = aes_unwrapping_key.unwrap_key(
                ObjectClass.SECRET_KEY,
                KeyType.AES,
                key_data=aes_key_to_be_unwrapped,
                mechanism=Mechanism.AES_KEY_WRAP,  # Explicitly use AES_KEY_WRAP for unwrap
                label=new_aes_label,
                store=True,
                template=get_symmetric_template()
            )
            print(f"✅ Unwrapped AES key successfully: {_get_key_label(unwrapped_aes_key)})")
            print("Attributes of the unwrapped key:")
            print_key_attributes(unwrapped_aes_key)

    except (TemplateInconsistent, TemplateIncomplete, FunctionFailed, WrappedKeyInvalid,
            WrappedKeyLenRange, WrappingKeyHandleInvalid, WrappingKeySizeRange,
            WrappingKeyTypeInconsistent, MechanismInvalid, MechanismParamInvalid,
            PKCS11Error) as e:
        print(f"❌ Error unwrapping key: {e}")
        print("Please ensure the keys are compatible for unwrapping and have the correct attributes (e.g., CKA_UNWRAP).")
    except Exception as e:
        print(f"An unexpected error occurred during key unwrapping: {e}")


def sign_data(session):
    """
    Signs data using a selected key on the HSM token.
    """
    try:
        key = get_key_for_crypto_op(session, Attribute.SIGN)
        if not key:
            return

        print("\nChoose data input method:")
        print("1. Sign data from a file")
        print("2. Sign data from a string")
        print("0. Exit")
        choice = input("Enter your choice (0-2): ").strip()

        data_to_sign = None
        file_name = None # Initialize file_name for later use

        if choice == '0':
            print("❌ Operation cancelled.")
            return
        elif choice == '1':
            file_name = input(
                "Enter the file name containing the data to sign: ").strip('"')
            if not file_name:
                print("❌ No file name provided. Cannot proceed.")
                return
            if not os.path.isfile(file_name):
                print(f"❌ File '{file_name}' does not exist. Cannot proceed.")
                return
            try:
                with open(file_name, 'rb') as f:
                    data_to_sign = f.read()
                print(f"Data read from file '{file_name}'.")
            except FileNotFoundError:
                print(f"❌ Error: File '{file_name}' not found. Please check the file path and try again.")
                return
            except PermissionError:
                print(f"❌ Error: Permission denied while accessing file '{file_name}'.")
                return
            except Exception as e:
                print(f"❌ Error reading file '{file_name}': {e}. Cannot proceed.")
                return
            if not data_to_sign:
                print("❌ No data read from file. Cannot proceed with signing.")
                return
        elif choice == '2':
            data_to_sign = input(
                "Enter the data to sign: ").strip().encode('utf-8')
            if not data_to_sign:
                print("❌ No data provided. Cannot proceed.")
                return
        else:
            print("❌ Invalid choice. Operation cancelled.")
            return

        # Use appropriate mechanism based on key type
        mechanism = None
        key_type_enum = key.__getitem__(Attribute.KEY_TYPE)

        if key_type_enum == KeyType.RSA:
            mechanism = Mechanism.RSA_PKCS
            # CKM_RSA_PKCS is a common signing mechanism for RSA
        elif key_type_enum == KeyType.EC:
            mechanism = Mechanism.ECDSA
            # CKM_ECDSA is common for EC signing
        elif key_type_enum == KeyType.AES:
            # AES is typically used for HMAC operations for signing
            mechanism = Mechanism.AES_KEY_GEN # Placeholder, typically HMAC with AES
            print("Note: AES signing usually involves HMAC. Ensure your key has CKA_SIGN attribute and mechanism is supported.")
        elif key_type_enum == KeyType.DSA:
            mechanism = Mechanism.DSA_SHA1 # Common DSA signing mechanism

        if mechanism is None:
            print(f"❌ No suitable signing mechanism found for key type: {key_type_enum.name}. Aborting.")
            return

        sig = key.sign(data_to_sign, mechanism=mechanism)
        print(f"✅ Data signed successfully. Signature (hex): {sig.hex()}")

        save_choice = input(
            "Save signature to a file? (yes/no) [default: yes]: ").strip().lower()
        if save_choice in ['', 'yes', 'y']:
            base_filename = "signature"
            if file_name:
                base_filename = os.path.splitext(os.path.basename(file_name))[0] + "_signature"
            sig_file_name = f"{base_filename}.bin"
            with open(sig_file_name, 'wb') as sig_file:
                sig_file.write(sig)
            print(f"Signature saved to '{sig_file_name}'.")
        else:
            print("Signature not saved to file.")

    except (MechansimInvalid, DataInvalid, DataLenRange, ArgumentsBad,
            PKCS11Error) as e:
        print(f"❌ Error signing data: {e}")
        print("Please ensure the key is capable of signing and the data is valid for the chosen mechanism.")
    except Exception as e:
        print(f"❌ An unexpected error occurred during signing: {e}")


def verify_signature(session):
    """
    Verifies a signature using a selected key on the HSM token.
    """
    try:
        key = get_key_for_crypto_op(session, Attribute.VERIFY)
        if not key:
            return

        print("\nChoose input method for data and signature:")
        print("1. Verify from files (data file and signature file)")
        print("2. Verify from string (data string and hex signature string)")
        print("0. Exit")
        choice = input("Enter your choice (0-2): ").strip()

        data_to_verify = None
        signature = None
        original_file_name = None # For clearer messages

        if choice == '0':
            print("Operation cancelled.")
            return
        elif choice == '1':
            original_file_name = input(
                "Enter the file name containing the original data: ").strip('"')
            sig_file_name = input(
                "Enter the file name containing the signature: ").strip('"')

            if not original_file_name or not sig_file_name:
                print("❌ Both data and signature file names are required. Cannot proceed.")
                return
            if not os.path.isfile(original_file_name):
                print(f"❌ Original data file '{original_file_name}' does not exist. Cannot proceed.")
                return
            if not os.path.isfile(sig_file_name):
                print(f"❌ Signature file '{sig_file_name}' does not exist. Cannot proceed.")
                return

            try:
                with open(original_file_name, 'rb') as f:
                    data_to_verify = f.read()
                with open(sig_file_name, 'rb') as sig_file:
                    signature = sig_file.read()
                print(
                    f"Data read from '{original_file_name}' and signature from '{sig_file_name}'.")
            except PermissionError:
                print(f"❌ Permission denied while accessing files.")
                return
            except Exception as e:
                print(
                    f"❌ An error occurred while reading files: {e}. Cannot proceed.")
                return
        elif choice == '2':
            data_to_verify = input(
                "Enter the original data string: ").strip().encode('utf-8')
            signature_hex = input(
                "Enter the signature as a hexadecimal string: ").strip()
            try:
                signature = bytes.fromhex(signature_hex)
            except ValueError:
                print("❌ Invalid hexadecimal format for signature. Cannot proceed.")
                return
            if not data_to_verify or not signature:
                print("❌ Data or signature not provided. Cannot proceed.")
                return
        else:
            print("Invalid choice. Operation cancelled.")
            return

        mechanism = None
        key_type_enum = key.__getitem__(Attribute.KEY_TYPE)

        if key_type_enum == KeyType.RSA:
            mechanism = Mechanism.RSA_PKCS
        elif key_type_enum == KeyType.EC:
            mechanism = Mechanism.ECDSA
        elif key_type_enum == KeyType.AES:
            # AES verification typically involves HMAC verification
            mechanism = Mechanism.AES_KEY_GEN # Placeholder, ensure key and mechanism are suitable for HMAC
            print("Note: AES verification usually involves HMAC. Ensure your key has CKA_VERIFY attribute and mechanism is supported.")
        elif key_type_enum == KeyType.DSA:
            mechanism = Mechanism.DSA_SHA1

        if mechanism is None:
            print(f"❌ No suitable verification mechanism found for key type: {key_type_enum.name}. Aborting.")
            return

        if key.verify(data_to_verify, signature, mechanism=mechanism):
            print("✅ Signature is valid.")
        else:
            print("❌ Signature is invalid.")

    except (DataInvalid, SignatureLenRange, SignatureInvalid, DataLenRange, ArgumentsBad,
            PKCS11Error) as e:
        print(f"❌ Error verifying signature: {e}")
        print("Please ensure the key is capable of verifying and the data/signature are valid for the chosen mechanism.")
    except Exception as e:
        print(f"❌ An unexpected error occurred during signature verification: {e}")


def encrypt_data(session):
    """
    Encrypts data using a selected key on the HSM token.
    """
    try:
        key = get_key_for_crypto_op(session, Attribute.ENCRYPT)
        if not key:
            return

        print("\nChoose data input method:")
        print("1. Encrypt data from a file")
        print("2. Encrypt data from a string")
        print("0. Exit")

        choice = input("Enter your choice (0-2): ").strip()
        data_to_encrypt = None
        input_file_name = None

        if choice == '0':
            print("Operation cancelled.")
            return
        elif choice == '1':
            input_file_name = input("Enter the file name containing the data to encrypt: ").strip('"')
            if not input_file_name:
                print("❌ No file name provided. Cannot proceed.")
                return
            if not os.path.isfile(input_file_name):
                print(f"❌ File '{input_file_name}' does not exist. Cannot proceed.")
                return
            try:
                with open(input_file_name, 'rb') as f:
                    data_to_encrypt = f.read()
                print(f"Data read from file '{input_file_name}'.")
            except PermissionError:
                print(f"❌ Error: Permission denied while accessing file '{input_file_name}'.")
                return
            except Exception as e:
                print(f"❌ Error reading file '{input_file_name}': {e}. Cannot proceed.")
                return
            if not data_to_encrypt:
                print("❌ No data read from file. Cannot proceed with encryption.")
                return

        elif choice == '2':
            data_to_encrypt = input(
                "Enter the data to encrypt: ").strip().encode('utf-8')
            if not data_to_encrypt:
                print("❌ No data provided. Cannot proceed.")
                return
        else:
            print("❌ Invalid choice. Operation cancelled.")
            return

        mechanism = None
        iv = None
        key_type_enum = key.__getitem__(Attribute.KEY_TYPE)

        if key_type_enum == KeyType.AES:
            mechanism = Mechanism.AES_CBC_PAD
            iv = session.generate_random(16)  # 16 bytes for AES IV
            print(f"Generated IV for AES encryption (hex): {iv.hex()} (SAVE THIS FOR DECRYPTION!)")
        elif key_type_enum == KeyType.DES3:
            mechanism = Mechanism.DES3_CBC_PAD
            iv = session.generate_random(8)  # 8 bytes for DES3 IV
            print(f"Generated IV for DES3 encryption (hex): {iv.hex()} (SAVE THIS FOR DECRYPTION!)")
        elif key_type_enum == KeyType.RSA:
            mechanism = Mechanism.RSA_PKCS_OAEP
            # For RSA_PKCS_OAEP, mechanism_param can be a digest and mgf. We use None for default.
            iv = None # RSA encryption does not typically use an IV in the same way CBC does
        else:
            print(f"❌ Unsupported key type '{key_type_enum.name}' for encryption or missing mechanism definition.")
            return

        print('Encrypting data...')
        print('This may take a while for large files or data.')
        encrypted_data = key.encrypt(data_to_encrypt, mechanism=mechanism, mechanism_param=iv)
        print(f"✅ Data encrypted successfully.")

        if choice == '1' and input_file_name:
            output_file_name = input_file_name + '.enc'
            with open(output_file_name, 'wb') as enc_file:
                enc_file.write(encrypted_data)
                print(f"✅ Encrypted data saved to '{output_file_name}'.")
        elif choice == '2':
            print(f"Encrypted data (hex): {encrypted_data.hex()}")

    except (MechanismInvalid, MechanismParamInvalid, FunctionFailed, FunctionCancelled,
            DataInvalid, DataLenRange, ArgumentsBad, PKCS11Error) as e:
        print(f"❌ Error encrypting data: {e}")
        print("Please ensure the key is capable of encryption and the data is valid for the chosen mechanism.")
    except Exception as e:
        print(f"❌ An unexpected error occurred during encryption: {e}")


def decrypt_data(session):
    """
    Decrypts data using a selected key on the HSM token.
    """
    try:
        key = get_key_for_crypto_op(session, Attribute.DECRYPT)
        if not key:
            return

        key_type_enum = key.__getitem__(Attribute.KEY_TYPE)

        print("\nChoose data input method:")
        print("1. Decrypt data from a file")
        print("2. Decrypt data from a string")
        print("0. Exit")

        choice = input("Enter your choice (0-2): ").strip()
        data_to_decrypt = None
        input_file_name = None

        if choice == '0':
            print("Operation cancelled.")
            return
        elif choice == '1':
            input_file_name = input(
                "Enter the file name containing the data to decrypt (e.g., original_file.txt.enc): ").strip('"')
            if not input_file_name:
                print("❌ No file name provided. Cannot proceed.")
                return
            if not os.path.isfile(input_file_name):
                print(f"❌ File '{input_file_name}' does not exist. Cannot proceed.")
                return
            try:
                with open(input_file_name, 'rb') as f:
                    data_to_decrypt = f.read()
                print(f"Data read from file '{input_file_name}'.")
            except PermissionError:
                print(f"❌ Error: Permission denied while accessing file '{input_file_name}'.")
                return
            except Exception as e:
                print(f"❌ Error reading file '{input_file_name}': {e}. Cannot proceed.")
                return

        elif choice == '2':
            data_to_decrypt_hex = input(
                "Enter the encrypted data as a hexadecimal string: ").strip()
            if not data_to_decrypt_hex:
                print("❌ No encrypted data provided. Cannot proceed.")
                return
            try:
                data_to_decrypt = bytes.fromhex(data_to_decrypt_hex)
            except ValueError:
                print("❌ Invalid hexadecimal format for encrypted data. Cannot proceed.")
                return
        else:
            print("❌ Invalid choice. Operation cancelled.")
            return

        mechanism = None
        iv_bytes = None

        if key_type_enum == KeyType.AES:
            mechanism = Mechanism.AES_CBC_PAD
            input_iv_hex = input("Enter the 16-byte IV (hex) used during encryption: ").strip()
            try:
                iv_bytes = bytes.fromhex(input_iv_hex)
                if len(iv_bytes) != 16:
                    print(f"❌ IV must be exactly 16 bytes (32 hex characters). Entered IV length: {len(iv_bytes)} bytes.")
                    return
            except ValueError:
                print("❌ Invalid hex format for IV.")
                return
        elif key_type_enum == KeyType.DES3:
            mechanism = Mechanism.DES3_CBC_PAD
            input_iv_hex = input("Enter the 8-byte IV (hex) used during encryption: ").strip()
            try:
                iv_bytes = bytes.fromhex(input_iv_hex)
                if len(iv_bytes) != 8:
                    print(f"❌ IV must be exactly 8 bytes (16 hex characters). Entered IV length: {len(iv_bytes)} bytes.")
                    return
            except ValueError:
                print("❌ Invalid hex format for IV.")
                return
        elif key_type_enum == KeyType.RSA:
            mechanism = Mechanism.RSA_PKCS_OAEP
            iv_bytes = None # No IV for RSA decryption in this context
        else:
            print(f"❌ Unsupported key type '{key_type_enum.name}' for decryption or missing mechanism definition.")
            return

        decrypted_data = key.decrypt(data_to_decrypt, mechanism=mechanism, mechanism_param=iv_bytes)
        print(f"✅ Data decrypted successfully.")

        if choice == '1' and input_file_name:
            if input_file_name.endswith('.enc'):
                dec_file_name = input_file_name[:-4]  # Remove .enc
            else:
                dec_file_name = input_file_name + '.dec'
            with open(dec_file_name, 'wb') as dec_file:
                dec_file.write(decrypted_data)
                print(f"✅ Decrypted data saved to '{dec_file_name}'.")
        elif choice == '2':
            try:
                print(f"Decrypted data (decoded): {decrypted_data.decode('utf-8')}")
            except UnicodeDecodeError:
                print(f"Decrypted data (raw hex): {decrypted_data.hex()}")
                print("Note: Could not decode to UTF-8. Displaying raw hex.")

    except (MechanismInvalid, MechanismParamInvalid, FunctionFailed, FunctionCancelled,
            ArgumentsBad, EncryptedDataInvalid, EncryptedDataLenRange, PKCS11Error) as e:
        print(f"❌ Error decrypting data: {e}")
        print("Please ensure the key is capable of decryption, the mechanism and IV match the encryption, and the data is valid.")
    except Exception as e:
        print(f"❌ An unexpected error occurred during decryption: {e}")


def main():
    """
    Main entry point for the HSM Tool.
    Initializes the PKCS#11 library and opens a session, then displays the menu.
    """
    print("\n" + "=" * 10 + " HSM Tool for PKCS#11 Operations " + "=" * 10)
    active_session = None
    try:
        active_session = open_session()
        if active_session:
            display_menu(active_session)
        else:
            print("❌ Failed to open PKCS#11 session. Exiting.")

    except Exception as e:
        print(f"A critical error occurred during startup: {e}. Exiting.")
    finally:
        if active_session:
            try:
                active_session.close()
                print("\n✅ Session closed.")
            except PKCS11Error as e:
                print(f"❌ Error closing PKCS#11 session: {e}")
        print("❌ HSM Tool has shut down.")


if __name__ == "__main__":
    main()

