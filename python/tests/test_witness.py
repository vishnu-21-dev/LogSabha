"""Witness logic tests. Witnesses talk to each other directly in memory here
(no network); test_witness_processes.py does the real HTTP / multi-process runs."""
import json
import os

import pytest
from nacl.signing import SigningKey

from logsabha_core import (
    canonical_json, inclusion_proof, merkle_root, sha256, sign_batch_header,
    make_authenticator, verify_batch_header, verify_chain, verify_inclusion, verify_receipt,
)
from witness.anchor import AnchorBackend, FakeFileBackend
from witness.core import Peer, PeerError, PeerRejected, Witness
from witness.keys import KeyFileError, load_signing_key

KEYS = {n: SigningKey(bytes([i]) * 32) for i, n in enumerate(("app", "network", "outside", "mallory"), start=21)}
EMPTY_ROOT = sha256(b"").hex()


class Wire:
    """In-memory network: delivers a peer message straight to the target witness (as JSON)."""

    def __init__(self):
        self.targets = {}
        self.down = set()

    def __call__(self, peer, payload):
        if peer.name in self.down or peer.name not in self.targets:
            raise PeerError("%s is down" % peer.name)
        try:
            return self.targets[peer.name].handle_peer_header(json.loads(json.dumps(payload)))
        except PeerRejected as err:
            raise PeerError("%s answered %d" % (peer.name, err.code))


def make(tmp_path, name, wire=None, peers=("app", "network", "outside"), backend=None, **kw):
    role = name if name in ("app", "network", "outside") else "app"
    plist = [Peer(p, "http://x/" + p, KEYS[p].verify_key.encode()) for p in peers if p != name]
    w = Witness(name, role, KEYS[name], tmp_path / (name + ".db"), peers=plist,
                backend=backend, transport=wire, **kw)
    if wire is not None:
        wire.targets[name] = w
    return w


def add(w, n=1, bytes_=100):
    return [w.add_entry("export", "req-%d" % i, "out", "203.0.113.58", bytes_, "ok") for i in range(n)]


# ----------------------------------------------------------------- restart
def test_seq_continues_after_restart_and_boot_id_changes(tmp_path):
    w1 = make(tmp_path, "app")
    add(w1, 3)                                   # seq 1 is the restart marker, entries are 2,3,4
    assert w1.status()["last_seq"] == 4
    w1.stop()                                    # clean: shutdown marker is seq 5

    w2 = make(tmp_path, "app")
    assert w2.boot_id != w1.boot_id
    marker = w2.store.entries_between(6, 6)[0]
    assert (marker["event_type"], marker["result"]) == ("restart", "after_shutdown")
    nxt = add(w2, 1)[0]
    assert nxt["seq"] == 7 and nxt["boot_id"] == w2.boot_id and nxt["prev_hash"] == w2.store.entries_between(6, 6)[0]["hash"]

    entries = w2.store.entries_between(1, 7)
    assert [e["event_type"] for e in entries] == ["restart", "export", "export", "export", "shutdown", "restart", "export"]
    assert verify_chain(entries, KEYS["app"].verify_key).valid     # one unbroken signed chain across the restart
    w2.stop()


def test_a_start_after_a_kill_is_marked_after_crash(tmp_path):
    w1 = make(tmp_path, "app")
    add(w1, 2)                                   # no stop(): this is a crash
    w2 = make(tmp_path, "app")
    marker = w2.store.last_entry()
    assert (marker["event_type"], marker["result"]) == ("restart", "after_crash")
    w1.store.close()
    w2.store.close()


def test_reserved_event_types_and_bad_fields_are_refused(tmp_path):
    w = make(tmp_path, "app")
    for reserved in ("restart", "shutdown"):
        with pytest.raises(ValueError):
            w.add_entry(reserved, None, "local", None, 0, "forged marker")
    with pytest.raises(ValueError):
        w.add_entry("export", None, "out", "x", -5, "ok")
    with pytest.raises(ValueError):
        w.add_entry("export", None, "out", "x", True, "ok")
    with pytest.raises(ValueError):
        w.add_entry("export", 123, "out", "x", 1, "ok")
    w.store.close()


# ----------------------------------------------------------------- batches
def test_closed_batch_root_verifies_with_the_core_library(tmp_path):
    w = make(tmp_path, "app")
    add(w, 5)
    header = w.close_batch()
    assert (header["batch_no"], header["first_seq"], header["last_seq"]) == (1, 1, 6)   # marker + 5 entries

    entries = w.store.entries_between(header["first_seq"], header["last_seq"])
    hashes = [bytes.fromhex(e["hash"]) for e in entries]
    assert verify_batch_header(KEYS["app"].verify_key, header)
    assert merkle_root(hashes).hex() == header["entries_root"]
    for i, h in enumerate(hashes):
        assert verify_inclusion(h, i, len(hashes), inclusion_proof(hashes, i), bytes.fromhex(header["entries_root"]))
    assert header["receipts_root"] == EMPTY_ROOT

    # an empty batch is still produced and signed (a heartbeat)
    beat = w.close_batch()
    assert beat["batch_no"] == 2 and (beat["first_seq"], beat["last_seq"]) == (7, 6)
    assert beat["entries_root"] == EMPTY_ROOT
    assert verify_batch_header(KEYS["app"].verify_key, beat)
    # entries added later go into the next batch, continuing the range
    add(w, 2)
    nxt = w.close_batch()
    assert (nxt["batch_no"], nxt["first_seq"], nxt["last_seq"]) == (3, 7, 8)
    w.store.close()


# ------------------------------------------------------------ peer exchange
def test_two_witnesses_exchange_headers_and_receipts_and_receipt_hash_lands_in_next_batch(tmp_path):
    wire = Wire()
    a = make(tmp_path, "app", wire)
    b = make(tmp_path, "network", wire)
    add(a, 3)
    header_a = a.close_batch()

    assert a.send_pending() == 1                 # only network is up in this test (outside is not wired)
    assert b.store.get_peer_header("app", 1) == header_a
    assert a.store.queue_counts() == {"PEER_RECEIPTED": 1}

    # B signed a receipt for A's batch
    receipt = b.store.get_receipt("issued", "app", 1)
    assert verify_receipt(KEYS["network"].verify_key, receipt)
    assert receipt["source_root"] == header_a["entries_root"]
    assert receipt["recipient_batch"] == 1       # it will be covered by network's batch 1
    assert a.store.get_receipt("received", "network", 1) == receipt

    # authenticators were exchanged in both directions and stored
    auth_of_a = b.store.latest_authenticator_of("app")
    assert auth_of_a["seq"] == 4 and auth_of_a["hash"] == a.store.last_entry()["hash"]
    assert a.store.latest_authenticator_of("network") is not None

    # B's NEXT batch carries the receipt hash in its receipts_root
    receipt_hash = sha256(canonical_json(receipt))
    header_b = b.close_batch()
    assert header_b["batch_no"] == receipt["recipient_batch"]
    assert header_b["receipts_root"] == merkle_root([receipt_hash]).hex()
    assert header_b["receipts_root"] != EMPTY_ROOT
    # ...and only once: the batch after that has no receipts
    assert b.close_batch()["receipts_root"] == EMPTY_ROOT

    # sending again changes nothing (idempotent)
    assert a.send_pending() == 0
    assert b.handle_peer_header({"header": header_a, "authenticator": None})["receipt"] == receipt
    assert b.store.count_receipts("issued") == 1
    a.store.close()
    b.store.close()


def test_headers_and_authenticators_with_bad_signatures_or_keys_are_rejected(tmp_path):
    wire = Wire()
    a = make(tmp_path, "app", wire)
    b = make(tmp_path, "network", wire)
    add(a, 2)
    good = a.close_batch()
    good_auth = a.latest_authenticator()

    def nothing_stored():
        return (b.store.count_peer_headers(), b.store.count_receipts("issued"), b.store.count_authenticators()) == (0, 0, 0)

    def rejected(payload, code=403):
        with pytest.raises(PeerRejected) as err:
            b.handle_peer_header(payload)
        assert err.value.code == code
        assert nothing_stored()

    rejected({"header": {**good, "entries_root": "ff" * 32}, "authenticator": good_auth})         # changed after signing
    rejected({"header": {**good, "sig": "00" * 64}, "authenticator": good_auth})                  # bad signature
    forged = sign_batch_header(KEYS["mallory"], {k: v for k, v in good.items() if k != "sig"})    # claims to be app, wrong key
    rejected({"header": forged, "authenticator": good_auth})
    as_mallory = sign_batch_header(KEYS["mallory"], {**{k: v for k, v in good.items() if k != "sig"}, "witness_id": "mallory"})
    rejected({"header": as_mallory, "authenticator": None})                                       # unknown sender
    rejected({"header": good, "authenticator": {**good_auth, "hash": "11" * 32}})                 # bad authenticator
    wrong_key_auth = make_authenticator(KEYS["mallory"], a.store.last_entry())
    rejected({"header": good, "authenticator": wrong_key_auth})                                   # wrong key authenticator
    rejected({"header": good, "authenticator": {**good_auth, "witness_id": "outside"}})           # not the sender's
    rejected({"nonsense": 1}, code=400)

    # the good message still works afterwards
    assert b.handle_peer_header({"header": good, "authenticator": good_auth})["receipt"]
    # a second, DIFFERENT, properly signed header for the same batch number is refused (409)
    other = sign_batch_header(KEYS["app"], {**{k: v for k, v in good.items() if k != "sig"}, "entries_root": "aa" * 32})
    with pytest.raises(PeerRejected) as err:
        b.handle_peer_header({"header": other, "authenticator": None})
    assert err.value.code == 409
    a.store.close()
    b.store.close()


def test_a_bad_receipt_in_a_reply_is_not_accepted(tmp_path):
    wire = Wire()
    a = make(tmp_path, "app", wire, peers=("network",))
    b = make(tmp_path, "network", wire, peers=("app",))
    add(a, 1)
    a.close_batch()

    real = wire.__call__

    def lying(peer, payload):
        reply = real(peer, payload)
        # a receipt signed by the wrong key
        from logsabha_core import sign_receipt
        body = {k: v for k, v in reply["receipt"].items() if k != "sig"}
        return {"receipt": sign_receipt(KEYS["mallory"], body), "authenticator": reply["authenticator"]}

    a.transport = lying
    assert a.send_pending() == 0
    assert a.store.count_receipts("received") == 0
    assert a.store.queue_counts() == {"CREATED": 1}
    a.store.close()
    b.store.close()


def test_an_unreachable_peer_does_not_block_and_is_retried(tmp_path):
    t = [1000.0]
    wire = Wire()
    a = make(tmp_path, "app", wire, peers=("network",), clock=lambda: t[0])
    b = make(tmp_path, "network", wire, peers=("app",), clock=lambda: t[0])
    wire.down.add("network")
    add(a, 1)
    a.close_batch()
    assert a.send_pending() == 0
    wire.down.clear()
    assert a.send_pending() == 0                 # still in the short back-off
    t[0] += 10
    assert a.send_pending() == 1                 # delivered later; the batch was never lost
    a.store.close()
    b.store.close()


# -------------------------------------------------- crash / restart durability
def test_killing_and_restarting_a_witness_loses_no_entries_and_no_queued_batches(tmp_path):
    wire = Wire()
    anchors = tmp_path / "anchors.jsonl"
    a = make(tmp_path, "app", wire, peers=("network",), backend=FakeFileBackend(anchors))
    b = make(tmp_path, "network", wire, peers=("app",))
    add(a, 4)
    a.close_batch()
    add(a, 2)
    a.close_batch()
    add(a, 3)                                    # not yet in any batch
    a.send_pending()                             # receipt for both batches
    add(b, 1)
    b.close_batch()
    b.send_pending()                             # a now holds an issued receipt not yet in a batch
    before = a.status()
    entries_before = a.store.entries_between(1, before["last_seq"])

    # "kill": no stop(), no shutdown marker. Just open the same files again.
    a2 = make(tmp_path, "app", wire, peers=("network",), backend=FakeFileBackend(anchors))
    after = a2.status()
    assert after["entries"] == before["entries"] + 1                 # + the new restart marker only
    assert a2.store.entries_between(1, before["last_seq"]) == entries_before
    assert after["batches"] == before["batches"] == 2
    assert after["queue"] == before["queue"] == {"PEER_RECEIPTED": 2}
    assert after["receipts_issued"] == before["receipts_issued"] == 1
    assert after["receipts_received"] == before["receipts_received"] == 2
    assert after["authenticators"] == before["authenticators"]
    assert a2.store.last_entry()["result"] == "after_crash"

    # the 3 entries that were waiting get sealed by the next batch, nothing skipped
    h = a2.close_batch()
    assert (h["batch_no"], h["first_seq"], h["last_seq"]) == (3, 8, 11)
    assert verify_chain(a2.store.entries_between(1, 11), KEYS["app"].verify_key).valid
    # the queued batches still get anchored after the restart
    a2.process_anchor_queue()
    assert a2.store.queue_counts().get("SUBMITTED") == 2
    a.store.close()
    a2.store.close()
    b.store.close()


# ----------------------------------------------------------- anchor queue
class FlakyBackend(AnchorBackend):
    def __init__(self, inner, fail_times):
        self.inner = inner
        self.fail_times = fail_times
        self.calls = 0

    def submit(self, batch):
        self.calls += 1
        if self.fail_times > 0:
            self.fail_times -= 1
            raise RuntimeError("backend is down")
        return self.inner.submit(batch)

    def get_confirmations(self, batch):
        return self.inner.get_confirmations(batch)


def test_anchor_backend_failure_keeps_batch_queued_then_succeeds_on_retry(tmp_path):
    t = [1000.0]
    anchors = tmp_path / "anchors.jsonl"
    flaky = FlakyBackend(FakeFileBackend(anchors), fail_times=2)
    w = make(tmp_path, "app", peers=(), backend=flaky, receipt_grace=0, clock=lambda: t[0])
    for _ in range(3):
        add(w, 1)
        w.close_batch()

    w.process_anchor_queue()                      # 1st try fails
    rows = w.store.queue_rows(("CREATED", "PEER_RECEIPTED", "SUBMITTED", "CONFIRMED"))
    assert [(r["batch_no"], r["state"]) for r in rows] == [(1, "CREATED"), (2, "CREATED"), (3, "CREATED")]
    assert rows[0]["attempts"] == 1 and "backend is down" in rows[0]["last_error"]
    assert flaky.calls == 1                       # batches 2 and 3 did NOT jump the queue
    assert not anchors.exists()

    w.process_anchor_queue()                      # too early: still backing off, no new call
    assert flaky.calls == 1

    # a restart in the middle of the outage keeps the queue
    w2 = make(tmp_path, "app", peers=(), backend=flaky, receipt_grace=0, clock=lambda: t[0])
    assert w2.store.queue_counts() == {"CREATED": 3}

    t[0] += 100
    w2.process_anchor_queue()                     # 2nd try fails
    assert flaky.calls == 2
    t[0] += 100
    w2.process_anchor_queue()                     # 3rd try works, and the rest follow in order
    assert w2.store.queue_counts() == {"SUBMITTED": 3}
    assert [json.loads(l)["batch_no"] for l in anchors.read_text().splitlines()] == [1, 2, 3]
    w2.process_anchor_queue()
    assert w2.store.queue_counts() == {"CONFIRMED": 3}
    w.store.close()
    w2.store.close()


def test_submit_waits_for_a_peer_receipt_but_only_for_the_grace_period(tmp_path):
    t = [1000.0]
    anchors = tmp_path / "anchors.jsonl"
    w = make(tmp_path, "app", peers=(), backend=FakeFileBackend(anchors), receipt_grace=10, clock=lambda: t[0])
    add(w, 1)
    w.close_batch()
    w.process_anchor_queue()
    assert w.store.queue_counts() == {"CREATED": 1}      # waiting for a receipt
    t[0] += 11
    w.process_anchor_queue()
    assert w.store.queue_counts() == {"SUBMITTED": 1}    # a dead peer cannot block anchoring forever
    w.store.close()


# ------------------------------------------------------------------- keys
def test_key_file_loading_and_errors_never_show_the_seed(tmp_path):
    seed = bytes([7]) * 32
    raw, hexf, bad = tmp_path / "raw.seed", tmp_path / "hex.seed", tmp_path / "bad.seed"
    raw.write_bytes(seed)
    hexf.write_text(seed.hex() + "\n")
    bad.write_text("this is not a seed SECRETWORD")
    assert load_signing_key(raw).encode() == seed
    assert load_signing_key(hexf).encode() == seed
    with pytest.raises(KeyFileError) as err:
        load_signing_key(bad)
    assert "SECRETWORD" not in str(err.value)
    with pytest.raises(KeyFileError):
        load_signing_key(tmp_path / "missing.seed")
