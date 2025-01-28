# hsmtool
Creates or uses an existing RSA Key Pair on a nShield HSM device. Wraps the RSA private key with an existing or newly generated AES wrapping key.  The file is exported in encrypted binary format. Generates a CSR using the RSA key stored in HSM via OpenSSL with the nfkm engine.
