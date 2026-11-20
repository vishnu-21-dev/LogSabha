"""Loading a witness key from a seed file.

The seed is the private part. This module never prints it, never logs it and
never puts it in an error message.
"""
import os

from nacl.signing import SigningKey


class KeyFileError(Exception):
    pass


def load_signing_key(path) -> SigningKey:
    """The file holds a 32-byte seed, either raw or as 64 hex characters."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        raise KeyFileError("cannot read the key file")
    if len(raw) == 32:
        seed = raw
    else:
        try:
            seed = bytes.fromhex(raw.strip().decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            raise KeyFileError("key file must hold a 32-byte seed (raw, or 64 hex characters)")
    if len(seed) != 32:
        raise KeyFileError("key file must hold a 32-byte seed (raw, or 64 hex characters)")
    return SigningKey(seed)


def write_new_key_file(path) -> str:
    """Create a new random seed file (refuses to overwrite). Returns the PUBLIC key in hex."""
    key = SigningKey.generate()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key.encode().hex())
    return key.verify_key.encode().hex()
