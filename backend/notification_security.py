import os

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from fastapi import HTTPException

load_dotenv()

ENCRYPTED_PREFIX = "enc:v1:"


def get_notification_cipher():
    key = os.getenv("NOTIFICATION_ENCRYPTION_KEY")

    if not key:
        raise HTTPException(
            status_code=500,
            detail="Notification encryption key is not configured.",
        )

    try:
        return Fernet(key.encode())
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Notification encryption key is invalid.",
        )


def encrypt_notification_secret(secret):
    if not secret:
        return secret

    if secret.startswith(ENCRYPTED_PREFIX):
        return secret

    encrypted = get_notification_cipher().encrypt(secret.encode()).decode()
    return ENCRYPTED_PREFIX + encrypted


def decrypt_notification_secret(secret):
    if not secret:
        return ""

    # Existing configurations may contain plaintext passwords.
    # Continue supporting them until the password is replaced.
    if not secret.startswith(ENCRYPTED_PREFIX):
        return secret

    encrypted = secret[len(ENCRYPTED_PREFIX):]

    try:
        return get_notification_cipher().decrypt(
            encrypted.encode()
        ).decode()
    except (InvalidToken, ValueError):
        raise HTTPException(
            status_code=500,
            detail="Stored SMTP password could not be decrypted. Check the notification encryption key.",
        )
