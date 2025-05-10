import base64
import json
from os import urandom
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    load_pem_private_key,
    Encoding,
    PrivateFormat,
    NoEncryption,
    PublicFormat
)
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# AES w/ PKCS7 padding 

def pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(padded: bytes) -> bytes:
    pad_len = padded[-1]
    return padded[:-pad_len]

def aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(pad(plaintext)) + encryptor.finalize()

def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(padded)

# HMAC-SHA256

def compute_hmac(data: bytes, key: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def verify_hmac(data: bytes, key: bytes, tag: bytes) -> None:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    h.verify(tag)

# RSA key encapsulation

def rsa_encrypt_key(aes_key: bytes, pubkey_path: str) -> bytes:
    pub = load_pem_public_key(open(pubkey_path, "rb").read())
    return pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt_key(encrypted_key: bytes, privkey_path: str) -> bytes:
    priv = load_pem_private_key(open(privkey_path, "rb").read(), password=None)
    return priv.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def encrypt_and_send(public_key_path: str, message: str, output_file: str):
    aes_key = urandom(32)  # 256-bit key
    iv = urandom(16)       # 128-bit IV
    ciphertext = aes_encrypt(message.encode(), aes_key, iv)
    encrypted_key = rsa_encrypt_key(aes_key, public_key_path)
    mac = compute_hmac(iv + ciphertext, aes_key)

    payload = {
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "hmac": base64.b64encode(mac).decode()
    }

    with open(output_file, "w") as out_file:
        json.dump(payload, out_file, indent=2)

    print(f"Message encrypted and saved to '{output_file}'.")

def receive_and_decrypt(private_key_path: str, input_file: str) -> str:
    with open(input_file, "r") as in_file:
        payload = json.load(in_file)

    encrypted_key = base64.b64decode(payload["encrypted_key"])
    iv = base64.b64decode(payload["iv"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    mac = base64.b64decode(payload["hmac"])

    aes_key = rsa_decrypt_key(encrypted_key, private_key_path)
    verify_hmac(iv + ciphertext, aes_key, mac)
    plaintext = aes_decrypt(ciphertext, aes_key, iv)

    return plaintext.decode()

# RSA Key Generation

def generate_keys(private_key_path: str, public_key_path: str):
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize and save the private key
    with open(private_key_path, "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
        )

    # Generate and save the public key
    public_key = private_key.public_key()
    with open(public_key_path, "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )
        )
