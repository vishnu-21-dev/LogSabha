"""The baseline: a single-host hash chain, anchored on the chain every 30 s by default.

Same design as Guardtime and OriginStamp: one party keeps its own hash chain of events and
periodically publishes the current head on a chain. It has NO peers and NO receipts. Nobody
outside this one process ever sees an entry before it is anchored. That is the whole point of
building it here: to show plainly what a single witness can and cannot catch, next to LogSabha.
"""
from .core import EMPTY_ANCHOR_ROOT, BaselineLog
from .verify import CANNOT, MATCH, MISMATCH, verify_baseline

__all__ = ["BaselineLog", "EMPTY_ANCHOR_ROOT", "verify_baseline", "MATCH", "MISMATCH", "CANNOT"]
