"""SHA-256 and Ed25519 signing with a "domain" label.

A domain label (like B3-ENTRY-V1) is glued in front of everything we sign.
So a signature made for an entry can never be reused as a signature for a
receipt, even if the bytes underneath were the same.
"""
import hashlib

from nacl.exceptions import CryptoError
from nacl.signing import SigningKey, VerifyKey

DOMAIN_ENTRY = b"B3-ENTRY-V1"
DOMAIN_BATCH = b"B3-BATCH-V1"
DOMAIN_AUTH = b"B3-AUTH-V1"
DOMAIN_RECEIPT = b"B3-RECEIPT-V1"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def generate_signing_key() -> SigningKey:
    return SigningKey.generate()


def verify_key_hex(signing_key: SigningKey) -> str:
    return signing_key.verify_key.encode().hex()


def _as_verify_key(key) -> VerifyKey:
    if isinstance(key, VerifyKey):
        return key
    if isinstance(key, (bytes, bytearray)):
        return VerifyKey(bytes(key))
    raise TypeError("expected a VerifyKey or 32 raw bytes")


def sign(domain: bytes, signing_key: SigningKey, payload: bytes) -> bytes:
    """Ed25519 signature (64 bytes) over domain + 0x00 + payload."""
    return signing_key.sign(domain + b"\x00" + payload).signature


def verify(domain: bytes, verify_key, payload: bytes, signature: bytes) -> bool:
    """True only if the signature is valid. Never raises on bad input."""
    try:
        _as_verify_key(verify_key).verify(domain + b"\x00" + payload, signature)
        return True
    except (CryptoError, ValueError, TypeError):
        return False
