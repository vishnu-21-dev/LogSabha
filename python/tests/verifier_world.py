"""Test helper (not a test file): builds a small, repeatable world of three witnesses and
the "chain" they anchor to. Only dummy fixed-seed keys are used.

Everything is driven by hand and in memory (no HTTP): add entries, close batches, exchange
receipts and authenticators, create anchor windows, anchor them. Tampered cases are then made
by editing COPIES of the exported bundles or of the database files.
"""
import hashlib
import json
import sqlite3

from logsabha_core import GENESIS_PREV_HASH, entries_root_hex, entry_body, sign_batch_header, sign_entry
from verifier.chain import StaticChainReader
from witness.anchor import AnchorBackend
from witness.export import build_bundle

from test_witness import KEYS, Wire, add, make

NAMES = ("app", "network", "outside")
PUB = {n: KEYS[n].verify_key.encode().hex() for n in NAMES}
SEEDS = {"app": 21, "network": 22, "outside": 23}      # the dummy seed byte used by test_witness.KEYS


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class Ledger:
    """A stand-in chain for in-memory worlds: it records the anchors the witnesses submit."""

    def __init__(self):
        self.anchors = {n: [] for n in NAMES}

    def reader(self, keys=None):
        return StaticChainReader(dict(keys or PUB), {n: [dict(a) for a in v] for n, v in self.anchors.items()},
                                 description="in-memory ledger (tests)")


class LedgerBackend(AnchorBackend):
    def __init__(self, ledger, name):
        self.ledger, self.name = ledger, name

    def submit(self, batch):
        h = batch["header"]
        tx = "0x" + hashlib.sha256(("%s:%d:%s" % (self.name, h["batch_no"], h["entries_root"])).encode()).hexdigest()
        known = {a["batch_no"] for a in self.ledger.anchors[self.name]}
        if h["batch_no"] not in known:
            self.ledger.anchors[self.name].append({
                "batch_no": h["batch_no"], "entries_root": h["entries_root"], "receipts_root": h["receipts_root"], "policy_hash": h["policy_hash"],
                "first_seq": h["first_seq"], "last_seq": h["last_seq"], "tx_hash": tx, "restart": False, "block_time": 0})
        return tx

    def get_confirmations(self, batch):
        return 1


class World:
    def __init__(self, tmp_path, backend_for=None, windows=3, rounds_per_window=2, entries_per_round=3, crash_app_in_window=2):
        self.tmp = tmp_path
        self.clock = Clock()
        self.wire = Wire()
        self.ledger = Ledger()
        backend_for = backend_for or (lambda name: LedgerBackend(self.ledger, name))
        self._backend_for = backend_for
        self.ws = {n: self._make(n) for n in NAMES}
        self.db = {n: tmp_path / (n + ".db") for n in NAMES}

        for window in range(1, windows + 1):
            for _ in range(rounds_per_window):
                self.step(entries_per_round)
            if window == crash_app_in_window:                   # the App witness stops without a clean shutdown
                self.ws["app"].store.close()
                self.ws["app"] = self._make("app")
                self.step(entries_per_round)
            self.anchor()
        # a few newest entries AFTER the last anchor: peers authenticate them, the chain does not know them yet
        self.step(entries_per_round)

    def _make(self, name):
        return make(self.tmp, name, wire=self.wire, backend=self._backend_for(name), clock=self.clock,
                    receipt_grace=0.0, required_confirmations=1)

    def step(self, n):
        for w in self.ws.values():
            add(w, n)
        self.clock.advance(1)
        for w in self.ws.values():
            w.close_batch()
        for w in self.ws.values():
            w.send_pending()
        self.clock.advance(1)

    def anchor(self):
        for w in self.ws.values():
            w.create_window()
        for w in self.ws.values():
            w.process_anchor_queue()

    def bundles(self):
        return {n: json.loads(json.dumps(build_bundle(self.db[n]))) for n in NAMES}

    def reader(self, keys=None):
        return self.ledger.reader(keys)


# ----------------------------------------------------------------- tamper helpers (all work on COPIES)
def copy_db(src, dst):
    """Copy a database safely (these are WAL databases: a plain file copy can miss recent rows)."""
    a, b = sqlite3.connect(str(src)), sqlite3.connect(str(dst))
    try:
        a.backup(b)
    finally:
        a.close()
        b.close()
    return dst


def rebuild_from(db_copy, signing_key, seq, extra_bytes=4096):
    """The strongest attack on a copy: the attacker HAS the witness's key. Change one entry's
    content, then rebuild every later entry (hashes, links, signatures), every batch header and every
    window root, all validly signed. Everything inside the copy stays consistent."""
    con = sqlite3.connect(str(db_copy))
    try:
        rows = con.execute("SELECT seq, entry_json FROM entries ORDER BY seq").fetchall()
        rebuilt, prev = [], None
        for s, text in rows:
            e = json.loads(text)
            if s < seq:
                prev = e
                rebuilt.append(e)
                continue
            body = entry_body(e)
            if s == seq:
                body["bytes"] = body["bytes"] + extra_bytes
            body["prev_hash"] = prev["hash"] if prev else GENESIS_PREV_HASH
            e = sign_entry(signing_key, body)
            prev = e
            rebuilt.append(e)
            con.execute("UPDATE entries SET entry_json=? WHERE seq=?", (json.dumps(e), s))
        by_seq = {e["seq"]: e for e in rebuilt}

        def root(lo, hi):
            return entries_root_hex([by_seq[s] for s in range(lo, hi + 1)] if hi >= lo else [])

        for batch_no, text in con.execute("SELECT batch_no, header_json FROM batches").fetchall():
            h = json.loads(text)
            body = {k: v for k, v in h.items() if k != "sig"}
            body["entries_root"] = root(h["first_seq"], h["last_seq"])
            con.execute("UPDATE batches SET header_json=? WHERE batch_no=?", (json.dumps(sign_batch_header(signing_key, body)), batch_no))
        for window_no, lo, hi in con.execute("SELECT window_no, first_seq, last_seq FROM windows").fetchall():
            con.execute("UPDATE windows SET entries_root=? WHERE window_no=?", (root(lo, hi), window_no))
        con.commit()
    finally:
        con.close()
    return db_copy


def forged_entry(signing_key, last_entry, ts_utc, witness_id):
    """One more entry, correctly chained and signed, dated `ts_utc`."""
    return sign_entry(signing_key, {
        "witness_id": witness_id, "boot_id": last_entry["boot_id"], "seq": last_entry["seq"] + 1, "ts_utc": ts_utc,
        "mono_ns": 1, "event_type": "export", "request_id": "r-forged", "direction": "out", "dst": "203.0.113.9",
        "bytes": 999, "result": "ok", "prev_hash": last_entry["hash"]})
