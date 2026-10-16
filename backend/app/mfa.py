"""Authenticator app time based one time passwords (RFC 6238)."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from .db import DATA_DIR
from .secrets_store import decrypt, encrypt


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def uri(username: str, secret: str) -> str:
    return f"otpauth://totp/{quote('CERBERUS:' + username)}?secret={secret}&issuer=CERBERUS&algorithm=SHA1&digits=6&period=30"


def verify(secret: str, code: str, *, at: int | None = None) -> bool:
    if not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit():
        return False
    try:
        key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except ValueError:
        return False
    step = int(time.time() if at is None else at) // 30
    for counter in (step - 1, step, step + 1):
        digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = digest[-1] & 15
        number = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000
        if hmac.compare_digest(f"{number:06d}", code):
            return True
    return False


def read(value: str) -> str:
    return decrypt(value, DATA_DIR)


def protected(value: str) -> str:
    return encrypt(value, DATA_DIR)
