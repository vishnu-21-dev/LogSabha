"""Log entries.

hash = SHA-256 of the canonical JSON of the entry WITHOUT hash and sig.
sig  = Ed25519 signature over the hash (domain B3-ENTRY-V1).
Hashes and signatures are stored as hex text so entries stay plain JSON.
"""
from .canonical import canonical_json
from .signing import DOMAIN_ENTRY, sha256, sign, verify

BODY_FIELDS = (
    "witness_id", "boot_id", "seq", "ts_utc", "mono_ns", "event_type",
    "request_id", "direction", "dst", "bytes", "result", "prev_hash",
)
ENTRY_FIELDS = BODY_FIELDS + ("hash", "sig")

# prev_hash of the very first entry (seq 1): 32 zero bytes.
GENESIS_PREV_HASH = "00" * 32


def entry_body(entry: dict) -> dict:
    """The entry without its hash and sig fields."""
    return {k: v for k, v in entry.items() if k not in ("hash", "sig")}


def compute_entry_hash(entry: dict) -> str:
    return sha256(canonical_json(entry_body(entry))).hex()


def sign_entry(signing_key, body: dict) -> dict:
    """Take an entry body (all fields except hash and sig), return the full entry."""
    if set(body) != set(BODY_FIELDS):
        raise ValueError("entry body must have exactly these fields: " + ", ".join(BODY_FIELDS))
    entry_hash = sha256(canonical_json(body))
    signature = sign(DOMAIN_ENTRY, signing_key, entry_hash)
    return {**body, "hash": entry_hash.hex(), "sig": signature.hex()}


def verify_entry_signature(verify_key, entry: dict) -> bool:
    """Checks the signature over the STORED hash. (The chain checker also
    recomputes the hash from the content.)"""
    try:
        return verify(DOMAIN_ENTRY, verify_key, bytes.fromhex(entry["hash"]), bytes.fromhex(entry["sig"]))
    except (KeyError, ValueError, TypeError):
        return False


def append_entry(signing_key, chain: list, fields: dict) -> dict:
    """Add the next entry to chain. seq and prev_hash are filled in for you.

    fields = witness_id, boot_id, ts_utc, mono_ns, event_type, request_id,
             direction, dst, bytes, result
    """
    if chain:
        seq = chain[-1]["seq"] + 1
        prev_hash = chain[-1]["hash"]
    else:
        seq = 1
        prev_hash = GENESIS_PREV_HASH
    entry = sign_entry(signing_key, {**fields, "seq": seq, "prev_hash": prev_hash})
    chain.append(entry)
    return entry
