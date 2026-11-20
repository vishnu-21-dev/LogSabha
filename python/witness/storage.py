"""Durable storage for one witness, in SQLite.

Every change is committed before the call returns (synchronous=FULL), so a
crash or kill loses nothing that was already acknowledged.

Tables: entries, batches, peer_headers, receipts, authenticators, anchor_queue
(plus a tiny meta table).
"""
import json
import sqlite3
import threading
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(
    key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS entries(
    seq INTEGER PRIMARY KEY,
    boot_id TEXT NOT NULL,
    entry_json TEXT NOT NULL,
    batch_no INTEGER);                       -- NULL until a batch closes over it

CREATE TABLE IF NOT EXISTS batches(
    batch_no INTEGER PRIMARY KEY,
    boot_id TEXT NOT NULL,
    first_seq INTEGER NOT NULL,
    last_seq INTEGER NOT NULL,
    header_json TEXT NOT NULL,               -- the signed batch header
    created_at REAL NOT NULL);

CREATE TABLE IF NOT EXISTS peer_headers(     -- signed headers received from peers
    from_witness TEXT NOT NULL,
    batch_no INTEGER NOT NULL,
    header_json TEXT NOT NULL,
    received_at TEXT NOT NULL,
    PRIMARY KEY(from_witness, batch_no));

CREATE TABLE IF NOT EXISTS receipts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                      -- 'issued' (I signed it) or 'received' (a peer signed mine)
    peer TEXT NOT NULL,
    source_batch INTEGER NOT NULL,           -- the batch that was receipted
    receipt_hash TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    included_in_batch INTEGER,               -- issued only: my batch whose receipts_root covers it
    UNIQUE(kind, peer, source_batch));

CREATE TABLE IF NOT EXISTS authenticators(
    witness_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    hash TEXT NOT NULL,
    auth_json TEXT NOT NULL,
    PRIMARY KEY(witness_id, seq));

CREATE TABLE IF NOT EXISTS anchor_queue(
    batch_no INTEGER PRIMARY KEY,
    state TEXT NOT NULL,                     -- CREATED, PEER_RECEIPTED, SUBMITTED, CONFIRMED
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    next_attempt_at REAL NOT NULL DEFAULT 0,
    ref TEXT,
    updated_at REAL NOT NULL);
"""


class Storage:
    def __init__(self, path):
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._lock = threading.RLock()
        self._depth = 0
        self._db.executescript(SCHEMA)

    def close(self):
        with self._lock:
            self._db.close()

    @contextmanager
    def tx(self):
        """One all-or-nothing transaction. Nesting is allowed. Holding it also
        means no other thread touches the database at the same time."""
        with self._lock:
            outer = self._depth == 0
            if outer:
                self._db.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield self._db
            except BaseException:
                self._depth -= 1
                if outer:
                    self._db.execute("ROLLBACK")
                raise
            else:
                self._depth -= 1
                if outer:
                    self._db.execute("COMMIT")

    # ---- meta
    def get_meta(self, key):
        with self.tx() as db:
            row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            return row[0] if row else None

    def set_meta(self, key, value):
        with self.tx() as db:
            db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (key, value))

    # ---- entries
    def add_entry(self, entry):
        with self.tx() as db:
            db.execute("INSERT INTO entries(seq,boot_id,entry_json,batch_no) VALUES(?,?,?,NULL)",
                       (entry["seq"], entry["boot_id"], json.dumps(entry)))

    def last_entry(self):
        with self.tx() as db:
            row = db.execute("SELECT entry_json FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
            return json.loads(row[0]) if row else None

    def unbatched_entries(self):
        with self.tx() as db:
            rows = db.execute("SELECT entry_json FROM entries WHERE batch_no IS NULL ORDER BY seq").fetchall()
            return [json.loads(r[0]) for r in rows]

    def assign_entries(self, first_seq, last_seq, batch_no):
        with self.tx() as db:
            db.execute("UPDATE entries SET batch_no=? WHERE seq BETWEEN ? AND ?", (batch_no, first_seq, last_seq))

    def entries_between(self, first_seq, last_seq):
        with self.tx() as db:
            rows = db.execute("SELECT entry_json FROM entries WHERE seq BETWEEN ? AND ? ORDER BY seq",
                              (first_seq, last_seq)).fetchall()
            return [json.loads(r[0]) for r in rows]

    def count_entries(self):
        with self.tx() as db:
            return db.execute("SELECT COUNT(*) FROM entries").fetchone()[0]

    # ---- batches
    def last_batch_no(self):
        with self.tx() as db:
            return db.execute("SELECT COALESCE(MAX(batch_no),0) FROM batches").fetchone()[0]

    def last_batch_last_seq(self):
        with self.tx() as db:
            row = db.execute("SELECT last_seq FROM batches ORDER BY batch_no DESC LIMIT 1").fetchone()
            return row[0] if row else 0

    def insert_batch(self, batch_no, boot_id, first_seq, last_seq, header, created_at):
        with self.tx() as db:
            db.execute("INSERT INTO batches(batch_no,boot_id,first_seq,last_seq,header_json,created_at) "
                       "VALUES(?,?,?,?,?,?)",
                       (batch_no, boot_id, first_seq, last_seq, json.dumps(header), created_at))

    def get_batch(self, batch_no):
        with self.tx() as db:
            row = db.execute("SELECT batch_no, header_json, created_at FROM batches WHERE batch_no=?",
                             (batch_no,)).fetchone()
            return {"batch_no": row[0], "header": json.loads(row[1]), "created_at": row[2]} if row else None

    def list_batches(self):
        with self.tx() as db:
            rows = db.execute("SELECT batch_no, header_json, created_at FROM batches ORDER BY batch_no").fetchall()
            return [{"batch_no": r[0], "header": json.loads(r[1]), "created_at": r[2]} for r in rows]

    def batches_without_receipt_from(self, peer, limit):
        """Newest `limit` batches that this peer has not receipted yet, oldest first."""
        with self.tx() as db:
            rows = db.execute(
                "SELECT batch_no, header_json FROM batches WHERE batch_no NOT IN "
                "(SELECT source_batch FROM receipts WHERE kind='received' AND peer=?) "
                "ORDER BY batch_no DESC LIMIT ?", (peer, limit)).fetchall()
            return [{"batch_no": r[0], "header": json.loads(r[1])} for r in reversed(rows)]

    # ---- peer headers
    def get_peer_header(self, sender, batch_no):
        with self.tx() as db:
            row = db.execute("SELECT header_json FROM peer_headers WHERE from_witness=? AND batch_no=?",
                             (sender, batch_no)).fetchone()
            return json.loads(row[0]) if row else None

    def add_peer_header(self, sender, batch_no, header, received_at):
        with self.tx() as db:
            db.execute("INSERT OR IGNORE INTO peer_headers(from_witness,batch_no,header_json,received_at) "
                       "VALUES(?,?,?,?)", (sender, batch_no, json.dumps(header), received_at))

    def count_peer_headers(self):
        with self.tx() as db:
            return db.execute("SELECT COUNT(*) FROM peer_headers").fetchone()[0]

    # ---- receipts
    def get_receipt(self, kind, peer, source_batch):
        with self.tx() as db:
            row = db.execute("SELECT receipt_json FROM receipts WHERE kind=? AND peer=? AND source_batch=?",
                             (kind, peer, source_batch)).fetchone()
            return json.loads(row[0]) if row else None

    def add_receipt(self, kind, peer, source_batch, receipt_hash, receipt):
        with self.tx() as db:
            db.execute("INSERT OR IGNORE INTO receipts(kind,peer,source_batch,receipt_hash,receipt_json) "
                       "VALUES(?,?,?,?,?)", (kind, peer, source_batch, receipt_hash, json.dumps(receipt)))

    def unbatched_issued_receipts(self):
        """[(id, receipt_hash)] of receipts I issued that no batch covers yet."""
        with self.tx() as db:
            rows = db.execute("SELECT id, receipt_hash FROM receipts "
                              "WHERE kind='issued' AND included_in_batch IS NULL ORDER BY id").fetchall()
            return [(r[0], r[1]) for r in rows]

    def assign_receipts(self, ids, batch_no):
        with self.tx() as db:
            for rid in ids:
                db.execute("UPDATE receipts SET included_in_batch=? WHERE id=?", (batch_no, rid))

    def receipts_included_in(self, batch_no):
        with self.tx() as db:
            rows = db.execute("SELECT receipt_hash FROM receipts WHERE kind='issued' AND included_in_batch=? "
                              "ORDER BY id", (batch_no,)).fetchall()
            return [r[0] for r in rows]

    def count_receipts(self, kind):
        with self.tx() as db:
            return db.execute("SELECT COUNT(*) FROM receipts WHERE kind=?", (kind,)).fetchone()[0]

    # ---- authenticators
    def put_authenticator(self, auth):
        with self.tx() as db:
            db.execute("INSERT OR IGNORE INTO authenticators(witness_id,seq,hash,auth_json) VALUES(?,?,?,?)",
                       (auth["witness_id"], auth["seq"], auth["hash"], json.dumps(auth)))

    def get_authenticator(self, witness_id, seq):
        with self.tx() as db:
            row = db.execute("SELECT auth_json FROM authenticators WHERE witness_id=? AND seq=?",
                             (witness_id, seq)).fetchone()
            return json.loads(row[0]) if row else None

    def latest_authenticator_of(self, witness_id):
        with self.tx() as db:
            row = db.execute("SELECT auth_json FROM authenticators WHERE witness_id=? ORDER BY seq DESC LIMIT 1",
                             (witness_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def count_authenticators(self):
        with self.tx() as db:
            return db.execute("SELECT COUNT(*) FROM authenticators").fetchone()[0]

    # ---- anchor queue
    def enqueue(self, batch_no, now):
        with self.tx() as db:
            db.execute("INSERT OR IGNORE INTO anchor_queue(batch_no,state,updated_at) VALUES(?, 'CREATED', ?)",
                       (batch_no, now))

    def queue_rows(self, states):
        marks = ",".join("?" * len(states))
        with self.tx() as db:
            rows = db.execute(
                "SELECT q.batch_no, q.state, q.attempts, q.last_error, q.next_attempt_at, q.ref, b.created_at, b.header_json "
                "FROM anchor_queue q JOIN batches b USING(batch_no) "
                "WHERE q.state IN (%s) ORDER BY q.batch_no" % marks, tuple(states)).fetchall()
            return [{"batch_no": r[0], "state": r[1], "attempts": r[2], "last_error": r[3],
                     "next_attempt_at": r[4], "ref": r[5], "created_at": r[6], "header": json.loads(r[7])}
                    for r in rows]

    def set_queue_state(self, batch_no, state, now, ref=None):
        with self.tx() as db:
            if ref is None:
                db.execute("UPDATE anchor_queue SET state=?, updated_at=? WHERE batch_no=?", (state, now, batch_no))
            else:
                db.execute("UPDATE anchor_queue SET state=?, ref=?, last_error=NULL, updated_at=? WHERE batch_no=?",
                           (state, ref, now, batch_no))

    def mark_peer_receipted(self, batch_no, now):
        with self.tx() as db:
            db.execute("UPDATE anchor_queue SET state='PEER_RECEIPTED', updated_at=? "
                       "WHERE batch_no=? AND state='CREATED'", (now, batch_no))

    def record_failure(self, batch_no, error, next_attempt_at, now):
        with self.tx() as db:
            db.execute("UPDATE anchor_queue SET attempts=attempts+1, last_error=?, next_attempt_at=?, updated_at=? "
                       "WHERE batch_no=?", (error, next_attempt_at, now, batch_no))

    def queue_counts(self):
        with self.tx() as db:
            rows = db.execute("SELECT state, COUNT(*) FROM anchor_queue GROUP BY state").fetchall()
            return {r[0]: r[1] for r in rows}
