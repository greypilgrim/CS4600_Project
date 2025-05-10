"""
Read the JSON Transmitted_Data file, verify HMAC, decrypt AES key with private RSA,
then decrypt the ciphertext to recover the plaintext message.
"""
from utils import receive_and_decrypt
import argparse


def main():
    parser = argparse.ArgumentParser(description="Receiver: Verify & decrypt message")
    parser.add_argument("--private", required=True, help="Receiver's RSA private key PEM file")
    parser.add_argument("--in", dest="infile", required=True, help="Path to input JSON Transmitted_Data file")
    parser.add_argument("--out", required=True, help="Path to output decrypted .txt file")
    args = parser.parse_args()

    try:
        plaintext = receive_and_decrypt(args.private, args.infile)
        with open(args.out, "w") as out_file:
            out_file.write(plaintext)
        print(f"Decrypted message written to {args.out}")
    except Exception as e:
        print(f"Error during decryption: {e}")


if __name__ == "__main__":
    main()
