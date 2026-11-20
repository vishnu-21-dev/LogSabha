"""Signed batch header, authenticator and receipt.

Each one is a small flat dict plus a "sig" field. The signature covers
SHA-256 of the canonical JSON of the dict without "sig", with its own domain
label. Extra or missing fields make verification fail.
"""
from .canonical import canonical_json
from .merkle import merkle_root
from .signing import DOMAIN_AUTH, DOMAIN_BATCH, DOMAIN_RECEIPT, sha256, sign, verify

BATCH_FIELDS = (
    "witness_id", "boot_id", "batch_no", "first_seq", "last_seq",
    "entries_root", "receipts_root", "policy_hash",
)
AUTH_FIELDS = ("witness_id", "seq", "hash")
RECEIPT_FIELDS = (
    "recipient", "source", "source_batch", "source_root",
    "first_seq", "last_seq", "recipient_batch", "received_at",
)


def _sign_body(domain, signing_key, body, fields):
    if set(body) != set(fields):
        raise ValueError("fields must be exactly: " + ", ".join(fields))
    signature = sign(domain, signing_key, sha256(canonical_json(body)))
    return {**body, "sig": signature.hex()}


def _verify_body(domain, verify_key, msg, fields) -> bool:
    try:
        if not isinstance(msg, dict) or set(msg) != set(fields) | {"sig"}:
            return False
        body = {k: v for k, v in msg.items() if k != "sig"}
        return verify(domain, verify_key, sha256(canonical_json(body)), bytes.fromhex(msg["sig"]))
    except (TypeError, ValueError):
        return False


# --- batch header ---------------------------------------------------------

def entries_root_hex(entries) -> str:
    """Merkle root (hex) over the entry hashes of these entries."""
    return merkle_root([bytes.fromhex(e["hash"]) for e in entries]).hex()


def sign_batch_header(signing_key, header: dict) -> dict:
    return _sign_body(DOMAIN_BATCH, signing_key, header, BATCH_FIELDS)


def verify_batch_header(verify_key, header: dict) -> bool:
    return _verify_body(DOMAIN_BATCH, verify_key, header, BATCH_FIELDS)


def build_batch_header(signing_key, witness_id, boot_id, batch_no, entries, receipts_root, policy_hash) -> dict:
    """Seal a list of entries: computes seq range and entries_root, then signs."""
    return sign_batch_header(signing_key, {
        "witness_id": witness_id,
        "boot_id": boot_id,
        "batch_no": batch_no,
        "first_seq": entries[0]["seq"],
        "last_seq": entries[-1]["seq"],
        "entries_root": entries_root_hex(entries),
        "receipts_root": receipts_root,
        "policy_hash": policy_hash,
    })


# --- authenticator: (witness_id, seq, hash, sig) ---------------------------

def make_authenticator(signing_key, entry: dict) -> dict:
    return _sign_body(DOMAIN_AUTH, signing_key, {
        "witness_id": entry["witness_id"], "seq": entry["seq"], "hash": entry["hash"],
    }, AUTH_FIELDS)


def verify_authenticator(verify_key, auth: dict) -> bool:
    return _verify_body(DOMAIN_AUTH, verify_key, auth, AUTH_FIELDS)


# --- receipt ---------------------------------------------------------------

def sign_receipt(signing_key, receipt: dict) -> dict:
    """Signed by the RECIPIENT's key."""
    return _sign_body(DOMAIN_RECEIPT, signing_key, receipt, RECEIPT_FIELDS)


def verify_receipt(verify_key, receipt: dict) -> bool:
    return _verify_body(DOMAIN_RECEIPT, verify_key, receipt, RECEIPT_FIELDS)
