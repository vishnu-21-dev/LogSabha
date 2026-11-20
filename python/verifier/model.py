"""Verdicts, findings and the evidence bundle loader."""
import json
from dataclasses import dataclass, field
from typing import List, Optional

MATCH = "MATCH"
MISMATCH = "MISMATCH"
CANNOT = "CANNOT VERIFY"
EXIT_CODE = {MATCH: 0, MISMATCH: 1, CANNOT: 2}

WARNING = "WARNING"                   # C6 only: never changes the verdict or the exit code

RULES = ("I1", "I2", "I3", "I4", "I5", "I6", "I7")             # integrity rules
CONSISTENCY_RULES = ("C1", "C2", "C3", "C4")                   # consistency rules (they read the policy)
ALL_RULES = RULES + CONSISTENCY_RULES + ("C6",)
RULE_TITLES = {
    "C1": "network to app: big egress records have an App witness event",
    "C2": "app to network: App witness outbound events have a Network witness event",
    "C3": "outside agrees: Outside witness totals match the Network witness",
    "C4": "silence: missed heartbeats or anchors, silence flags, planned pauses",
    "C6": "warnings: new destination, or too many bytes in 5 minutes",
    "I1": "chain links and hashes",
    "I2": "signatures against the on-chain keys",
    "I3": "anchor match (roots recomputed from the bundle vs the chain)",
    "I4": "sequence numbers",
    "I5": "authenticators held by the other witnesses",
    "I6": "receipts appear in the anchored receipts root",
    "I7": "one signed header per batch number",
}
CANONICAL_ORDER = ("app", "network", "outside")
DISPLAY = {"app": "App witness", "network": "Network witness", "outside": "Outside witness"}
BUNDLE_FORMAT = "logsabha-evidence-bundle"

LIST_FIELDS = ("entries", "batches", "windows", "receipts_issued", "receipts_received",
               "authenticators", "peer_headers", "conflicting_headers")


def display(witness_id):
    return DISPLAY.get(witness_id, "Witness '%s'" % witness_id)


def witness_sort_key(witness_id):
    if witness_id in CANONICAL_ORDER:
        return (0, CANONICAL_ORDER.index(witness_id), "")
    return (1, 0, str(witness_id))


def worst(results):
    for r in (MISMATCH, CANNOT, MATCH):
        if r in results:
            return r
    return CANNOT


@dataclass
class Finding:
    rule: str
    result: str
    subject: str                          # the witness this finding is about
    statement: str                        # one sentence: what was found
    code: str = ""                        # short machine label, e.g. "hash", "link", "deleted"
    witnesses: List[str] = field(default_factory=list)
    seq_range: Optional[tuple] = None
    time_range: str = "n/a"
    evidence: List[str] = field(default_factory=list)
    limitation: str = ""
    anchor_tx: Optional[str] = None
    answerable_by: str = ""
    policy_version: str = ""
    id: str = ""

    def sort_key(self):
        lo = self.seq_range[0] if self.seq_range else -1
        return (ALL_RULES.index(self.rule) if self.rule in ALL_RULES else 99, witness_sort_key(self.subject),
                lo, self.code, self.statement)

    def to_dict(self):
        return {
            "id": self.id, "result": self.result, "rule": self.rule, "rule_title": RULE_TITLES.get(self.rule, ""),
            "witnesses": [display(w) for w in (self.witnesses or ([self.subject] if self.subject else []))],
            "statement": self.statement, "time_range": self.time_range, "evidence": list(self.evidence),
            "limitation": self.limitation, "anchor_tx": self.anchor_tx, "answerable_by": self.answerable_by,
            "code": self.code, "policy_version": self.policy_version,
        }


class BundleError(Exception):
    pass


@dataclass
class Bundle:
    path: str
    witness_id: str
    data: dict

    def __getattr__(self, name):
        if name in LIST_FIELDS:
            return self.data[name]
        raise AttributeError(name)

    @property
    def by_seq(self):
        cache = self.__dict__.get("_by_seq")
        if cache is None:
            cache = {}
            for e in self.data["entries"]:
                if isinstance(e, dict) and isinstance(e.get("seq"), int) and not isinstance(e.get("seq"), bool):
                    cache.setdefault(e["seq"], e)
            self.__dict__["_by_seq"] = cache
        return cache


def load_bundle(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError:
        raise BundleError("the file cannot be read")
    except ValueError:
        raise BundleError("the file is not valid JSON")
    if not isinstance(data, dict) or data.get("format") != BUNDLE_FORMAT:
        raise BundleError("this is not a LogSabha evidence bundle")
    wid = data.get("witness_id")
    if not isinstance(wid, str) or not wid:
        raise BundleError("the bundle does not say which witness it came from")
    for name in LIST_FIELDS:
        if not isinstance(data.get(name), list):
            raise BundleError("the bundle has no '%s' list" % name)
    return Bundle(path=str(path), witness_id=wid, data=data)
