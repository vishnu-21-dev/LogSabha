"""logsabha_core: the one shared crypto library for all witnesses and the verifier.

No networking and no blockchain code lives here.
"""
from .canonical import canonical_json
from .chain import ChainResult, Failure, verify_chain
from .entry import (
    ENTRY_FIELDS, GENESIS_PREV_HASH, append_entry, compute_entry_hash,
    entry_body, sign_entry, verify_entry_signature,
)
from .merkle import inclusion_proof, leaf_hash, merkle_root, node_hash, verify_inclusion
from .messages import (
    build_batch_header, entries_root_hex, make_authenticator, sign_batch_header,
    sign_receipt, verify_authenticator, verify_batch_header, verify_receipt,
)
from .signing import (
    DOMAIN_AUTH, DOMAIN_BATCH, DOMAIN_ENTRY, DOMAIN_RECEIPT,
    generate_signing_key, sha256, sign, verify, verify_key_hex,
)
