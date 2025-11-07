#!/usr/bin/env python3

import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class CryptoUtils:
    def __init__(self, key=None, iv=None):
        """Initialize with AES key and IV. If not provided, generate new ones."""
        if key is None:
            self.key = os.urandom(32)  # 256-bit key
        else:
            self.key = key if isinstance(key, bytes) else key.encode()
            
        if iv is None:
            self.iv = os.urandom(16)  # 128-bit IV
        else:
            self.iv = iv if isinstance(iv, bytes) else iv.encode()
    
    def get_key_b64(self):
        """Return base64 encoded key"""
        return base64.b64encode(self.key).decode()
    
    def get_iv_b64(self):
        """Return base64 encoded IV"""
        return base64.b64encode(self.iv).decode()
    
    def encrypt(self, plaintext):
        """Encrypt plaintext and return base64 encoded ciphertext"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        # Pad plaintext to multiple of 16 bytes
        padding_length = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + bytes([padding_length] * padding_length)
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        return base64.b64encode(ciphertext).decode()
    
    def decrypt(self, ciphertext_b64):
        """Decrypt base64 encoded ciphertext and return plaintext"""
        ciphertext = base64.b64decode(ciphertext_b64)
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]
        
        return plaintext.decode()
    
    def encrypt_json(self, data):
        """Encrypt JSON data"""
        json_str = json.dumps(data)
        return self.encrypt(json_str)
    
    def decrypt_json(self, ciphertext_b64):
        """Decrypt and parse JSON data"""
        plaintext = self.decrypt(ciphertext_b64)
        return json.loads(plaintext)

# Default shared key and IV for the system
DEFAULT_KEY = base64.b64decode("mtbN+9GJ5O/QEknWcPfs484Msqh+2vI2T9KUmbvmTps=")  # 32 bytes
DEFAULT_IV = base64.b64decode("jwrFJ5Okp4OXpUfes8UFWw==")  # 16 bytes

def get_default_crypto():
    """Get default crypto instance with shared key/IV"""
    return CryptoUtils(DEFAULT_KEY, DEFAULT_IV) 