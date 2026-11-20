"""The witness itself. No web code here; api.py wraps this.

All hashing, signing, canonical JSON and Merkle work is done by logsabha_core.
"""
import logging
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import requests

from logsabha_core import (
    canonical_json, entries_root_hex, make_authenticator, merkle_root, sha256,
    sign_batch_header, sign_entry, sign_receipt, verify_authenticator,
    verify_batch_header, verify_receipt, GENESIS_PREV_HASH,
)

from .anchor import AnchorBackend
from .storage import Storage

log = logging.getLogger("witness")

ROLES = ("app", "network", "outside")
RESERVED_EVENT_TYPES = ("restart", "shutdown")   # only the witness itself may write these
PEER_RESEND_WINDOW = 50                          # how many recent batches we keep re-sending to a peer
ZERO_POLICY_HASH = "00" * 32                     # placeholder until real policies exist


class PeerError(Exception):
    """Sending to a peer failed (network down, or the peer said no)."""


class PeerRejected(Exception):
    """We refused a message from a peer."""

    def __init__(self, code, reason):
        super().__init__(reason)
        self.code = code
        self.reason = reason


@dataclass(frozen=True)
class Peer:
    name: str          # the peer's witness_id
    url: str           # e.g. http://127.0.0.1:8102
    verify_key: bytes  # the peer's public Ed25519 key (32 bytes). Public, not secret.


class HttpTransport:
    """Sends a signed header to a peer over HTTP and returns the JSON reply."""

    def __call__(self, peer, payload):
        try:
            r = requests.post(peer.url.rstrip("/") + "/peer/header", json=payload, timeout=(1.0, 3.0))
        except requests.RequestException as err:
            raise PeerError("cannot reach %s: %s" % (peer.name, type(err).__name__))
        if r.status_code != 200:
            raise PeerError("%s answered %d" % (peer.name, r.status_code))
        try:
            return r.json()
        except ValueError:
            raise PeerError("%s sent a reply that is not JSON" % peer.name)


class Witness:
    def __init__(self, name, role, signing_key, db_path, peers=(), backend=None, transport=None,
                 batch_interval=2.0, receipt_grace=10.0, required_confirmations=1, clock=time.time,
                 anchor_interval=30.0):
        if role not in ROLES:
            raise ValueError("role must be one of: " + ", ".join(ROLES))
        self.name = name
        self.role = role
        self._sk = signing_key
        self.peers = {p.name: p for p in peers}
        self.backend = backend
        self.transport = transport or HttpTransport()
        self.batch_interval = batch_interval      # peer exchange rhythm (2 s)
        self.anchor_interval = anchor_interval    # on-chain anchor rhythm (30 s)
        self.receipt_grace = receipt_grace
        self.required_confirmations = required_confirmations
        self.clock = clock
        self.boot_id = uuid.uuid4().hex             # new on every start
        self.store = Storage(db_path)
        self._stop = threading.Event()
        self._threads = []
        self._peer_backoff = {}
        # The policy is hashed into every batch header. Milliseconds, because canonical JSON has no floats.
        self.policy_hash = sha256(canonical_json({
            "v": 1, "role": role, "batch_interval_ms": int(batch_interval * 1000),
        })).hex()
        self._boot()

    # ------------------------------------------------------------------ time
    def _ts(self):
        dt = datetime.fromtimestamp(self.clock(), timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (dt.microsecond // 1000)

    # --------------------------------------------------------------- entries
    def _append(self, event_type, request_id, direction, dst, bytes_, result):
        """Build, sign and store the next entry. Caller must hold store.tx()."""
        last = self.store.last_entry()
        entry = sign_entry(self._sk, {
            "witness_id": self.name,
            "boot_id": self.boot_id,
            "seq": last["seq"] + 1 if last else 1,
            "ts_utc": self._ts(),
            "mono_ns": time.monotonic_ns(),
            "event_type": event_type,
            "request_id": request_id,
            "direction": direction,
            "dst": dst,
            "bytes": bytes_,
            "result": result,
            "prev_hash": last["hash"] if last else GENESIS_PREV_HASH,
        })
        self.store.add_entry(entry)
        return entry

    def _boot(self):
        """Write the signed restart marker. It says how the previous run ended."""
        with self.store.tx():
            stored = self.store.get_meta("witness_id")
            if stored is None:
                self.store.set_meta("witness_id", self.name)
                self.store.set_meta("role", self.role)
            elif stored != self.name:
                raise ValueError("this database belongs to another witness")
            last = self.store.last_entry()
            if last is None:
                how = "first_boot"
            elif last["event_type"] == "shutdown":
                how = "after_shutdown"
            else:
                how = "after_crash"
            self._append("restart", None, "local", None, 0, how)

    def add_entry(self, event_type, request_id, direction, dst, bytes_, result):
        if event_type in RESERVED_EVENT_TYPES:
            raise ValueError("event_type %r is reserved for the witness itself" % event_type)
        if not isinstance(event_type, str) or not event_type:
            raise ValueError("event_type must be a non-empty string")
        if isinstance(bytes_, bool) or not isinstance(bytes_, int) or bytes_ < 0:
            raise ValueError("bytes must be a whole number, 0 or more")
        for label, value in (("request_id", request_id), ("direction", direction), ("dst", dst), ("result", result)):
            if value is not None and not isinstance(value, str):
                raise ValueError("%s must be text" % label)
        with self.store.tx():
            return self._append(event_type, request_id, direction, dst, bytes_, result)

    def latest_authenticator(self):
        last = self.store.last_entry()
        return make_authenticator(self._sk, last) if last else None

    # --------------------------------------------------------------- batches
    def close_batch(self):
        """Seal everything since the last batch. Runs even when there is nothing new
        (an empty batch is a heartbeat), so silence shows up as missing batches."""
        with self.store.tx():
            batch_no = self.store.last_batch_no() + 1
            entries = self.store.unbatched_entries()
            if entries:
                first_seq, last_seq = entries[0]["seq"], entries[-1]["seq"]
            else:
                # empty batch: the range is empty (last = first - 1)
                last_seq = self.store.last_batch_last_seq()
                first_seq = last_seq + 1
            receipts = self.store.unbatched_issued_receipts()
            receipts_root = merkle_root([bytes.fromhex(h) for _, h in receipts]).hex()
            header = sign_batch_header(self._sk, {
                "witness_id": self.name,
                "boot_id": self.boot_id,
                "batch_no": batch_no,
                "first_seq": first_seq,
                "last_seq": last_seq,
                "entries_root": entries_root_hex(entries),
                "receipts_root": receipts_root,
                "policy_hash": self.policy_hash,
            })
            now = self.clock()
            self.store.insert_batch(batch_no, self.boot_id, first_seq, last_seq, header, now)
            if entries:
                self.store.assign_entries(first_seq, last_seq, batch_no)
            self.store.assign_receipts([rid for rid, _ in receipts], batch_no)
            return header

    # ---------------------------------------------------------- anchor windows
    def create_window(self):
        """Close one anchor window: everything sealed in 2-second batches since the last window.
        One window = one on-chain anchor. An empty window is a heartbeat (last_seq = first_seq - 1).
        Returns the window, or None if no new batch was sealed since the last window."""
        with self.store.tx():
            prev = self.store.last_window()
            prev_last_batch = prev["last_batch"] if prev else 0
            newest_batch = self.store.last_batch_no()
            if newest_batch <= prev_last_batch:
                return None
            first_batch, last_batch = prev_last_batch + 1, newest_batch
            first_seq = (prev["last_seq"] if prev else 0) + 1
            last_seq = self.store.get_batch(last_batch)["header"]["last_seq"]
            entries = self.store.entries_between(first_seq, last_seq) if last_seq >= first_seq else []
            receipt_hashes = self.store.receipts_included_between(first_batch, last_batch)
            now = self.clock()
            window = {
                "window_no": (prev["window_no"] if prev else 0) + 1,
                "first_batch": first_batch,
                "last_batch": last_batch,
                "first_seq": first_seq,
                "last_seq": last_seq,
                "entries_root": entries_root_hex(entries),
                "receipts_root": merkle_root([bytes.fromhex(h) for h in receipt_hashes]).hex(),
                "policy_hash": ZERO_POLICY_HASH,
                "created_at": now,
            }
            self.store.insert_window(window)
            self.store.enqueue(window["window_no"], now)
            self.store.refresh_peer_receipted(now)
            return window

    # ---------------------------------------------------------- peer exchange
    def handle_peer_header(self, payload):
        """A peer sent us its signed header (+ its latest authenticator). Check, store, reply with a receipt."""
        if not isinstance(payload, dict) or not isinstance(payload.get("header"), dict):
            raise PeerRejected(400, "malformed message")
        header = payload["header"]
        auth = payload.get("authenticator")
        sender = header.get("witness_id")
        peer = self.peers.get(sender) if isinstance(sender, str) else None
        if peer is None:
            raise PeerRejected(403, "unknown sender")
        if not verify_batch_header(peer.verify_key, header):
            raise PeerRejected(403, "bad header signature")
        if auth is not None:
            if not (isinstance(auth, dict) and auth.get("witness_id") == sender
                    and verify_authenticator(peer.verify_key, auth)):
                raise PeerRejected(403, "bad authenticator")
        batch_no = header["batch_no"]
        if isinstance(batch_no, bool) or not isinstance(batch_no, int) or batch_no < 1:
            raise PeerRejected(400, "bad batch number")

        conflict = False
        with self.store.tx():
            existing = self.store.get_peer_header(sender, batch_no)
            if existing is not None and existing != header:
                # The sender signed two versions of one batch. Keep the second one as evidence.
                # (Saved here, inside a transaction that commits; the 409 is raised after it.)
                self.store.add_conflicting_header(sender, batch_no, header, self._ts())
                conflict = True
            else:
                self.store.add_peer_header(sender, batch_no, header, self._ts())
                if auth is not None:
                    self.store.put_authenticator(auth)
                receipt = self.store.get_receipt("issued", sender, batch_no)
                if receipt is None:
                    receipt = sign_receipt(self._sk, {
                        "recipient": self.name,
                        "source": sender,
                        "source_batch": batch_no,
                        "source_root": header["entries_root"],
                        "first_seq": header["first_seq"],
                        "last_seq": header["last_seq"],
                        # the receipt hash will be covered by the receipts_root of my NEXT batch
                        "recipient_batch": self.store.last_batch_no() + 1,
                        "received_at": self._ts(),
                    })
                    self.store.add_receipt("issued", sender, batch_no, sha256(canonical_json(receipt)).hex(), receipt)
        if conflict:
            raise PeerRejected(409, "a different header for this batch was already received")
        return {"receipt": receipt, "authenticator": self.latest_authenticator()}

    def _accept_reply(self, peer, batch_no, header, reply):
        """Check a peer's reply to our header. Returns True if the receipt was stored."""
        receipt = reply.get("receipt") if isinstance(reply, dict) else None
        auth = reply.get("authenticator") if isinstance(reply, dict) else None
        ok = (isinstance(receipt, dict)
              and verify_receipt(peer.verify_key, receipt)
              and receipt.get("recipient") == peer.name
              and receipt.get("source") == self.name
              and receipt.get("source_batch") == batch_no
              and receipt.get("source_root") == header["entries_root"]
              and receipt.get("first_seq") == header["first_seq"]
              and receipt.get("last_seq") == header["last_seq"])
        if ok and auth is not None:
            ok = (isinstance(auth, dict) and auth.get("witness_id") == peer.name
                  and verify_authenticator(peer.verify_key, auth))
        if not ok:
            log.warning("rejected a bad reply from peer %s for batch %s", peer.name, batch_no)
            return False
        with self.store.tx():
            self.store.add_receipt("received", peer.name, batch_no, sha256(canonical_json(receipt)).hex(), receipt)
            if auth is not None:
                self.store.put_authenticator(auth)
            self.store.refresh_peer_receipted(self.clock())
        return True

    def send_pending(self):
        """Send every recent batch header that a peer has not receipted yet. Returns receipts gained."""
        gained = 0
        for peer in self.peers.values():
            if self.clock() < self._peer_backoff.get(peer.name, 0):
                continue
            for batch in self.store.batches_without_receipt_from(peer.name, PEER_RESEND_WINDOW):
                payload = {"header": batch["header"], "authenticator": self.latest_authenticator()}
                try:
                    reply = self.transport(peer, payload)
                except PeerError as err:
                    log.info("peer %s not reachable now: %s", peer.name, err)
                    self._peer_backoff[peer.name] = self.clock() + 3
                    break
                if self._accept_reply(peer, batch["batch_no"], batch["header"], reply):
                    gained += 1
                else:
                    self._peer_backoff[peer.name] = self.clock() + 3
                    break
        return gained

    # ----------------------------------------------------------- anchor queue
    def process_anchor_queue(self):
        """Confirm what was submitted, then submit waiting batches in batch order.
        A failure keeps the batch queued and stops there, so order is never broken."""
        if self.backend is None:
            return
        now = self.clock()
        self.store.refresh_peer_receipted(now)

        for row in self.store.queue_rows(("SUBMITTED",)):
            try:
                count = self.backend.get_confirmations(
                    {"batch_no": row["batch_no"], "header": row["header"], "ref": row["ref"]})
            except Exception as err:  # the backend is outside our control: any failure means "try later"
                log.info("confirmations for batch %s not available: %s", row["batch_no"], err)
                continue
            if count >= self.required_confirmations:
                self.store.set_queue_state(row["batch_no"], "CONFIRMED", now)

        for row in self.store.queue_rows(("CREATED", "PEER_RECEIPTED")):
            if row["next_attempt_at"] > now:
                break
            waited = now - row["created_at"]
            if row["state"] == "CREATED" and waited < self.receipt_grace:
                break  # give the peers a moment to receipt it; later batches wait (order matters)
            try:
                ref = self.backend.submit({"batch_no": row["batch_no"], "header": row["header"]})
            except Exception as err:
                delay = min(2 ** min(row["attempts"] + 1, 5), 10)
                self.store.record_failure(row["batch_no"], str(err)[:200], now + delay, now)
                log.warning("anchor submit failed for batch %s (will retry): %s", row["batch_no"], err)
                break
            self.store.set_queue_state(row["batch_no"], "SUBMITTED", now, ref=ref)

    # --------------------------------------------------------------- lifecycle
    def start(self):
        """Start the background loops: close batches, talk to peers, drive the anchor queue."""
        def loop(fn, every):
            while not self._stop.wait(every):
                try:
                    fn()
                except Exception:
                    log.exception("background task %s failed; it will run again", fn.__name__)

        def batch_step():
            self.close_batch()
            self.send_pending()

        for fn, every in ((batch_step, self.batch_interval), (self.send_pending, 1.0),
                          (self.create_window, self.anchor_interval),
                          (self.process_anchor_queue, 1.0)):
            t = threading.Thread(target=loop, args=(fn, every), name=fn.__name__, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        """Clean shutdown: stop loops, write the signed shutdown marker, seal it in a last batch."""
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        self._threads = []
        with self.store.tx():
            self._append("shutdown", None, "local", None, 0, "clean")
        self.close_batch()
        self.create_window()      # so the shutdown marker is covered by an anchor window
        self.store.close()

    def status(self):
        last = self.store.last_entry()
        return {
            "witness_id": self.name,
            "role": self.role,
            "boot_id": self.boot_id,
            "last_seq": last["seq"] if last else 0,
            "entries": self.store.count_entries(),
            "batches": self.store.last_batch_no(),
            "windows": len(self.store.list_windows()),
            "queue": self.store.queue_counts(),
            "receipts_issued": self.store.count_receipts("issued"),
            "receipts_received": self.store.count_receipts("received"),
            "peer_headers": self.store.count_peer_headers(),
            "conflicting_headers": self.store.count_conflicting_headers(),
            "authenticators": self.store.count_authenticators(),
        }
