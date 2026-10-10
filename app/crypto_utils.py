import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

_fernet = None


def get_fernet():
    global _fernet
    if _fernet is None:
        key = os.getenv('MFA_ENCRYPTION_KEY')
        if not key:
            raise RuntimeError("MFA_ENCRYPTION_KEY manquante dans .env")
        _fernet = Fernet(key.encode())
    return _fernet


def encrypt_secret(plain_text):
    if plain_text is None:
        return None
    return get_fernet().encrypt(plain_text.encode()).decode()


def decrypt_secret(encrypted_text):
    if encrypted_text is None:
        return None
    return get_fernet().decrypt(encrypted_text.encode()).decode()