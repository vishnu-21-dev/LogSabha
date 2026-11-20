"""BaselineLog: the baseline's own hash chain, plus its periodic anchor.

No peers, no receipts, no batch merkle trees. Every entry links to the one before it
(seq, prev_hash, hash, sig), exactly like logsabha_core.append_entry does for anyone.

ANCHOR DESIGN (documented here because it differs from LogSabha's real batches):
the value put on the chain as "entries_root" is simply the HASH OF THE NEWEST ENTRY in the
new range (the chain head at that moment) -- not a Merkle root over a batch. That is enough,
because the chain's own prev_hash links already commit to every entry before it. This is the
same idea Guardtime and OriginStamp use: publish the current head, on a timer.
"""
import logging
import threading
import time
from datetime import datetime, timezone

from logsabha_core import GENESIS_PREV_HASH, append_entry

from .storage import Storage

log = logging.getLogger("baseline")

EMPTY_ANCHOR_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"   # SHA-256 of nothing
ZERO_POLICY_HASH = "00" * 32          # the baseline has no policy file; always the placeholder
ZERO_RECEIPTS_ROOT = EMPTY_ANCHOR_ROOT  # the baseline never has receipts


def iso(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + ("%03dZ" % (t % 1 * 1000))


class BaselineLog:
    def __init__(self, signing_key, witness_id, db_path, backend, clock=time.time):
        self._sk = signing_key
        self.witness_id = witness_id
        self.store = Storage(db_path)
        self.backend = backend
        self.clock = clock
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._chain = self.store.all_entries()
        last = self.store.last_anchor()
        self._next_batch_no = (last["batch_no"] + 1) if last else 1
        self._last_anchored_seq = last["last_seq"] if last else 0

    # ------------------------------------------------------------------ log
    def add_entry(self, event_type, request_id, direction, dst, bytes_, result):
        with self._lock:
            entry = append_entry(self._sk, self._chain, {
                "witness_id": self.witness_id, "boot_id": self.witness_id, "ts_utc": iso(self.clock()),
                "mono_ns": time.monotonic_ns(), "event_type": event_type, "request_id": request_id,
                "direction": direction, "dst": dst, "bytes": bytes_, "result": result,
            })
            self.store.add_entry(entry)
            return entry

    def head(self):
        with self._lock:
            return self._chain[-1]["hash"] if self._chain else GENESIS_PREV_HASH

    # --------------------------------------------------------------- anchor
    def anchor_now(self):
        """One anchor: everything new since the last one. Returns (header, tx_hash), or None if
        the backend raised (logged, left for the next call -- same as a real witness's retry)."""
        with self._lock:
            first_seq = self._last_anchored_seq + 1
            tail_seq = self._chain[-1]["seq"] if self._chain else 0
            if tail_seq >= first_seq:
                last_seq = tail_seq
                entries_root = self._chain[-1]["hash"]
            else:
                last_seq = first_seq - 1              # heartbeat: empty range
                entries_root = EMPTY_ANCHOR_ROOT
            batch_no = self._next_batch_no
            header = {"batch_no": batch_no, "first_seq": first_seq, "last_seq": last_seq,
                     "entries_root": entries_root, "receipts_root": ZERO_RECEIPTS_ROOT, "policy_hash": ZERO_POLICY_HASH}
        now = self.clock()
        try:
            tx = self.backend.submit({"batch_no": batch_no, "header": header})
        except Exception as err:
            log.warning("baseline anchor batch=%d FAILED at %s: %s", batch_no, iso(now), err)
            return None
        with self._lock:
            self.store.insert_anchor(batch_no, first_seq, last_seq, entries_root, tx, now)
            self._next_batch_no += 1
            self._last_anchored_seq = last_seq
        log.info("baseline anchor batch=%d range=%d-%d head=%s tx=%s at %s",
                batch_no, first_seq, last_seq, entries_root[:12], tx, iso(now))
        return header, tx

    def start(self, interval_seconds=30.0):
        """A background thread that anchors every interval_seconds. Real wall-clock time:
        there is no simulated clock here, so a tamper really does race the next anchor."""
        def loop():
            while not self._stop.wait(interval_seconds):
                self.anchor_now()
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()
        log.info("baseline anchor loop started: every %ss", interval_seconds)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
        self.store.close()

    def status(self):
        with self._lock:
            return {"witness_id": self.witness_id, "entries": len(self._chain), "head": self.head(),
                    "next_batch_no": self._next_batch_no, "last_anchored_seq": self._last_anchored_seq}
