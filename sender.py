"""
Encrypt a message with AES, encrypt the AES key with receiver's RSA public key,
compute HMAC over ciphertext, and write all to a JSON "Transmitted_Data" file.
"""
import argparse
import json
import base64
from os import urandom
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
# for all helper functions
from utils import(
    aes_encrypt,
    compute_hmac,
    rsa_encrypt_key,
    encrypt_and_send
)


def encrypt_and_send(public_key_path: str, message: str, output_path: str):
    # Generate AES key and IV
    aes_key = urandom(32)  # 256-bit key
    iv = urandom(16)       # 128-bit IV

    # Encrypt the plaintext message
    ciphertext = aes_encrypt(message.encode(), aes_key, iv)

    # Encrypt the AES key using the recipient's RSA public key
    encrypted_key = rsa_encrypt_key(aes_key, public_key_path)

    # Compute HMAC for integrity
    mac = compute_hmac(iv + ciphertext, aes_key)

    # Package everything into a JSON object
    payload = {
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "hmac": base64.b64encode(mac).decode()
    }

    # Save the payload to a file
    with open(output_path, "w") as out_file:
        json.dump(payload, out_file, indent=2)

    print(f"Message encrypted and saved to '{output_path}'.")


def main():
    parser = argparse.ArgumentParser(description="Sender: Encrypt and package message")
    parser.add_argument("--receiver-public", required=True, help="Receiver's RSA public key PEM file")
    parser.add_argument("--input", required=True, help="Path to plaintext message file (.txt)")
    parser.add_argument("--out", required=True, help="Path to output JSON Transmitted_Data file")
    args = parser.parse_args()

    # Read plaintext
    with open(args.input, "r") as f:
        plaintext = f.read()

    encrypt_and_send(args.receiver_public, plaintext, args.out)


if __name__ == "__main__":
    main()