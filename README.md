# Secure Encryption Demo

This project is an interactive web application demonstrating how modern cryptographic techniques protect sensitive information through a hybrid encryption approach using RSA and AES algorithms.

## Project Overview

The Secure Encryption App demonstrates a comprehensive encryption system that combines asymmetric (RSA) and symmetric (AES) encryption to provide secure message exchange with integrity protection. The application guides users through each step of the encryption and decryption process with detailed explanations of the cryptographic concepts.

## Security Features Demonstrated

- **RSA Key Generation**: Creation of 2048-bit public/private key pairs
- **Hybrid Encryption**: Using AES for message encryption and RSA for key protection
- **Message Authentication**: HMAC-SHA256 for message integrity verification
- **Secure Key Exchange**: Protection of symmetric keys using asymmetric encryption
- **Base64 Encoding**: Safe transmission of binary cryptographic data

## Technical Implementation

- **RSA-2048**: Asymmetric encryption for secure key exchange
- **AES-256-CBC**: Symmetric encryption with randomized initialization vectors
- **PKCS#7 Padding**: Ensures message length is a multiple of the AES block size
- **HMAC-SHA256**: Message authentication to prevent tampering
- **RSA-OAEP Padding**: Optimal Asymmetric Encryption Padding with SHA-256

## Requirements
- Python 3.11+
- Required Python libraries: 
  - cryptography
  - flask
  - werkzeug

## Running the Flask App
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Powershell run command(how to run the app):
  ```bash
   python app.py
  ```
