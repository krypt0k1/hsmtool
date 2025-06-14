# -*- coding: utf-8 -*-
import argparse
import sys
import os
import platform
import subprocess # Required for preload usage

import pkcs11
from pkcs11 import ObjectClass, Attribute
# Import centralized constants and functions from hsm_tool_script
from hsm_tool_script import (
    initialize_pkcs11_library,
    print_key_attributes,
    NFAST_MODULE_ENV_VAR,
    NFAST_LINUX_PATH,
    NFAST_WINDOWS_PATH,
)
from pkcs11.exceptions import (
    AttributeTypeInvalid,
    AttributeValueInvalid,
    AttributeReadOnly,
    PKCS11Error,
    NoSuchToken,
)


def main():
    """
    Main function to parse arguments and modify the CKA_TRUSTED attribute.
    """
    parser = argparse.ArgumentParser(description="Modifies CKA_TRUSTED attribute of PKCS#11 keys.")
    parser.add_argument("--label", required=True, help="Label of the key to modify.")
    parser.add_argument("--algo", required=True, choices=['symmetric', 'asymmetric'], help="Algorithm type (symmetric/asymmetric).")
    parser.add_argument("--trusted", required=True, choices=['true', 'false'], help="Set CKA_TRUSTED to true/false.")
    parser.add_argument("--pin", required=True, help="Security Officer (SO) PIN for the token.")
    args = parser.parse_args()

    label = args.label
    algo = args.algo
    trusted_bool = True if args.trusted == "true" else False
    so_pin = args.pin

    try:
        lib = initialize_pkcs11_library() # Use the centralized function

        # Define the token to use
        # Only module protected keys allow this. Use rocs to change the protection method of your key to module protected
        # before running this script.
        # Modify the protection method of your key using rocs back its original method after running this script.
        # This token label is specific to nCipher HSMs and may need to be configurable.
        token = lib.get_token(token_label='loadshared accelerator')

        # Open a session to apply CKA_TRUSTED as CKU_SO (Security Officer)
        with token.open(so_pin=so_pin, rw=True) as session:
            key = None
            if algo == 'asymmetric':
                # CKA_TRUSTED is generally applied to CKO_PUBLIC_KEY for asymmetric keys.
                key = session.get_key(label=label, object_class=ObjectClass.PUBLIC_KEY)
            elif algo == 'symmetric':
                # CKA_TRUSTED is generally applied to CKO_SECRET_KEY for symmetric keys.
                key = session.get_key(label=label, object_class=ObjectClass.SECRET_KEY)

            if key:
                key.__setitem__(Attribute.TRUSTED, trusted_bool)
                print(f"✅ Successfully set CKA_TRUSTED to {trusted_bool} for key '{label}'.")
                print("\nUpdated Key Attributes:")
                print_key_attributes(key) # Use the centralized function
            else:
                print(f"❌ Error: Key with label '{label}' and algorithm type '{algo}' not found or is not a modifiable object class (public/secret key).", file=sys.stderr)
                sys.exit(1)

    except (AttributeTypeInvalid, AttributeValueInvalid, AttributeReadOnly,
            PKCS11Error, NoSuchToken) as e:
        print(f"❌ Error during key modification: {e}", file=sys.stderr)
        print("Please ensure the token is present, PIN is correct, and key label/type are accurate.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

