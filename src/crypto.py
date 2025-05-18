# crypto.py - Encryption/Decryption utilities
import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#? RSA Algorithm Steps:
# 1. Choose two large prime numbers p and q
# 2. Compute n = p * q (modulus for both public and private keys)
# 3. Compute r = (p-1)*(q-1) (Euler's totient function also refered to as phi)
# 4. Select public exponent e (common values: 3, 5, 17, or 65537)
# 5. Compute private exponent d = e^(-1) mod r (modular inverse)
#! Note: All operations must be performed with large integers for security


class CryptoManager:
    def __init__(self):
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

        # Convert public key to PEM format for sharing
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def encrypt_message(self, message, recipient_public_key_pem):
        """Encrypt a message using recipient's public key"""
        # Load recipient's public key
        recipient_key = serialization.load_pem_public_key(
            recipient_public_key_pem.encode(),
            backend=default_backend()
        )

        # Generate a random session key
        session_key = os.urandom(32)  # 256 bits for AES-256

        # Encrypt the message with the session key
        nonce = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.CTR(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()

        # Encrypt the session key with recipient's public key
        encrypted_key = recipient_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return {
            'encrypted_message': base64.b64encode(encrypted_message).decode(),
            'encrypted_key': base64.b64encode(encrypted_key).decode(),
            'nonce': base64.b64encode(nonce).decode()
        }

    def decrypt_message(self, encrypted_data):
        """Decrypt a message using our private key"""
        # Decrypt the session key with our private key
        encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
        session_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt the message with the session key
        encrypted_message = base64.b64decode(encrypted_data['encrypted_message'])
        nonce = base64.b64decode(encrypted_data['nonce'])

        cipher = Cipher(
            algorithms.AES(session_key),
            modes.CTR(nonce),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return (decryptor.update(encrypted_message) + decryptor.finalize()).decode()





