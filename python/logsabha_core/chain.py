"""Hash-chain checker. Gives exact reasons: which seq failed, and why.

IMPORTANT LIMIT: this checker can only say "the chain is consistent and
signed by this key". If an attacker who controls the witness machine also
holds its key, they can rebuild the whole chain and it will still say VALID.
That is why we compare against OTHER witnesses and the on-chain root.
"""
from dataclasses import dataclass, field
from typing import List, Optional

from .entry import ENTRY_FIELDS, GENESIS_PREV_HASH, compute_entry_hash, verify_entry_signature

HASH_MISMATCH = "HASH_MISMATCH"              # content does not match its stored hash
BAD_SIGNATURE = "BAD_SIGNATURE"              # signature does not verify
BAD_PREV_HASH = "BAD_PREV_HASH"              # link to the previous entry is broken
SEQ_NOT_CONSECUTIVE = "SEQ_NOT_CONSECUTIVE"  # seq did not rise by exactly 1
WITNESS_CHANGED = "WITNESS_CHANGED"          # witness_id differs inside one chain
MALFORMED = "MALFORMED"                      # missing field or wrong type


@dataclass(frozen=True)
class Failure:
    seq: Optional[int]
    code: str
    message: str

    def __str__(self):
        return "seq %s: %s - %s" % (self.seq, self.code, self.message)


@dataclass
class ChainResult:
    failures: List[Failure] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.failures

    @property
    def first_failure(self) -> Optional[Failure]:
        return self.failures[0] if self.failures else None

    def __str__(self):
        return "VALID" if self.valid else "INVALID: " + "; ".join(str(f) for f in self.failures)


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def verify_chain(entries, verify_key, expected_first_seq=None, expected_prev_hash=None) -> ChainResult:
    """Check links, hashes, signatures and seq order of a list of entries.

    expected_first_seq / expected_prev_hash: when checking a slice that does
    not start at seq 1, pass what the first entry must link to.
    """
    result = ChainResult()
    prev = None

    for position, e in enumerate(entries):
        if not isinstance(e, dict):
            result.failures.append(Failure(None, MALFORMED, "entry at position %d is not an object" % position))
            prev = None
            continue

        seq = e.get("seq") if _is_int(e.get("seq")) else None
        missing = [f for f in ENTRY_FIELDS if f not in e]
        if missing or seq is None:
            result.failures.append(Failure(seq, MALFORMED, "missing or invalid fields: " + ", ".join(missing or ["seq"])))
            prev = None
            continue

        try:
            recomputed = compute_entry_hash(e)
        except (TypeError, ValueError) as err:
            result.failures.append(Failure(seq, MALFORMED, "cannot hash entry: %s" % err))
            prev = None
            continue

        if recomputed != e["hash"]:
            result.failures.append(Failure(seq, HASH_MISMATCH, "entry content does not match its hash (it was changed)"))

        if not verify_entry_signature(verify_key, e):
            result.failures.append(Failure(seq, BAD_SIGNATURE, "signature does not verify for this key"))

        if prev is not None:
            if e["witness_id"] != prev["witness_id"]:
                result.failures.append(Failure(seq, WITNESS_CHANGED, "witness_id differs from the previous entry"))
            if seq != prev["seq"] + 1:
                result.failures.append(Failure(seq, SEQ_NOT_CONSECUTIVE, "expected seq %d after seq %d" % (prev["seq"] + 1, prev["seq"])))
            if e["prev_hash"] != prev["hash"]:
                result.failures.append(Failure(seq, BAD_PREV_HASH, "prev_hash does not match the previous entry's hash"))
        else:
            if expected_first_seq is not None and seq != expected_first_seq:
                result.failures.append(Failure(seq, SEQ_NOT_CONSECUTIVE, "expected first seq %d" % expected_first_seq))
            wanted = expected_prev_hash
            if wanted is None and seq == 1:
                wanted = GENESIS_PREV_HASH
            if wanted is not None and e["prev_hash"] != wanted:
                result.failures.append(Failure(seq, BAD_PREV_HASH, "first entry does not link to the expected prev_hash"))

        prev = e

    return result
