"""Real processes talking over real HTTP on this machine."""
import json
import os
import socket
import subprocess
import sys
import time

import pytest
import requests
from nacl.signing import SigningKey

from logsabha_core import (
    merkle_root, verify_authenticator, verify_batch_header, verify_chain, verify_receipt,
)
from witness.storage import Storage

PY_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Proc:
    """One witness started with `python -m witness ...`."""

    def __init__(self, tmp_path, name, role, seed_byte, port, peers, extra_args=None, env=None):
        self.name, self.port = name, port
        self.sk = SigningKey(bytes([seed_byte]) * 32)        # dummy test seed
        self.seed_file = tmp_path / (name + ".seed")
        self.seed_file.write_text(self.sk.encode().hex())
        self.db = tmp_path / (name + ".db")
        self.anchors = tmp_path / (name + ".anchors.jsonl")
        self.log = tmp_path / (name + ".log")
        self.peers = peers          # list of (name, port, SigningKey)
        self.role = role
        self.proc = None
        self.env = env
        self.extra_args = extra_args if extra_args is not None else ["--backend", "fake", "--anchor-interval", "6"]

    def start(self):
        cmd = [sys.executable, "-m", "witness", "--role", self.role, "--name", self.name,
               "--port", str(self.port), "--key-file", str(self.seed_file),
               "--db", str(self.db), "--anchor-file", str(self.anchors)] + self.extra_args
        for pname, pport, psk in self.peers:
            cmd += ["--peer", "%s=http://127.0.0.1:%d=%s" % (pname, pport, psk.verify_key.encode().hex())]
        self.proc = subprocess.Popen(cmd, cwd=PY_DIR, stdout=open(self.log, "ab"), stderr=subprocess.STDOUT, env=self.env)
        deadline = time.time() + 25
        while time.time() < deadline:
            try:
                if requests.get(self.url("/status"), timeout=1).status_code == 200:
                    return
            except requests.RequestException:
                time.sleep(0.2)
        raise RuntimeError("witness %s did not start; see its log" % self.name)

    def url(self, path):
        return "http://127.0.0.1:%d%s" % (self.port, path)

    def status(self):
        return requests.get(self.url("/status"), timeout=3).json()

    def post_entry(self, **kw):
        body = {"event_type": "export", "request_id": "r", "direction": "out",
                "dst": "203.0.113.58", "bytes": 100, "result": "ok"}
        body.update(kw)
        return requests.post(self.url("/entries"), json=body, timeout=3)

    def kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()                 # hard kill: no clean shutdown, like a crash
            self.proc.wait(timeout=10)


def test_a_real_process_killed_and_restarted_loses_nothing(tmp_path, procs):
    w = Proc(tmp_path, "app", "app", 31, free_port(), [])
    procs.append(w)
    w.start()
    for i in range(5):
        assert w.post_entry(request_id="r%d" % i).status_code == 200
    assert w.post_entry(event_type="shutdown").status_code == 400      # forged marker refused over HTTP
    assert w.post_entry(bytes=-1).status_code == 422                   # invalid body refused
    time.sleep(5)                                                      # let a couple of batches close
    before = w.status()
    assert before["entries"] == 6 and before["batches"] >= 2          # marker + 5 entries
    w.kill()

    w.start()                                                          # same database, new process
    after = w.status()
    assert after["boot_id"] != before["boot_id"]
    assert after["entries"] == before["entries"] + 1                  # only the new restart marker is added
    assert after["last_seq"] == before["last_seq"] + 1
    assert after["batches"] >= before["batches"]
    entry = w.post_entry().json()
    assert entry["seq"] == after["last_seq"] + 1
    w.kill()

    store = Storage(w.db)
    entries = store.entries_between(1, store.last_entry()["seq"])
    assert verify_chain(entries, w.sk.verify_key).valid
    assert [e["result"] for e in entries if e["event_type"] == "restart"] == ["first_boot", "after_crash"]
    store.close()


def test_three_witnesses_as_three_processes_for_20_seconds(tmp_path, procs):
    specs = [("app", "app", 41), ("network", "network", 42), ("outside", "outside", 43)]
    ports = {n: free_port() for n, _, _ in specs}
    keys = {n: SigningKey(bytes([b]) * 32) for n, _, b in specs}
    for n, role, b in specs:
        others = [(m, ports[m], keys[m]) for m, _, _ in specs if m != n]
        procs.append(Proc(tmp_path, n, role, b, ports[n], others))
    by_name = {p.name: p for p in procs}
    for p in procs:
        p.start()

    t0 = time.time()
    # a few real entries while it runs
    for i in range(6):
        by_name["app"].post_entry(request_id="a%d" % i, bytes=2148)
    for i in range(4):
        by_name["network"].post_entry(event_type="flow", request_id="n%d" % i, bytes=2148)
    time.sleep(10)
    for i in range(3):
        by_name["outside"].post_entry(event_type="counter", request_id="o%d" % i, bytes=2121)
    time.sleep(max(0, 20 - (time.time() - t0)))

    live = {n: p.status() for n, p in by_name.items()}
    for p in procs:
        p.kill()

    print("\n  WITNESS   entries  batches  receipts_issued  receipts_received  peer_headers  queue")
    for n in ("app", "network", "outside"):
        s = live[n]
        print("  %-8s  %7d  %7d  %15d  %17d  %12d  %s" % (
            n, s["entries"], s["batches"], s["receipts_issued"], s["receipts_received"], s["peer_headers"], s["queue"]))

    for n, p in by_name.items():
        s = live[n]
        assert 8 <= s["batches"] <= 12, "expected about 10 batches in 20s, got %s" % s["batches"]
        # nearly every batch was receipted by both peers (the very latest may still be in flight)
        assert s["receipts_received"] >= 2 * (s["batches"] - 3)
        assert s["receipts_issued"] >= 2 * (s["batches"] - 3)

        store = Storage(p.db)
        # every stored header is genuine, ranges are contiguous, the entry chain is valid
        last_end = 0
        for b in store.list_batches():
            h = b["header"]
            assert verify_batch_header(p.sk.verify_key, h)
            assert h["first_seq"] == last_end + 1
            last_end = h["last_seq"]
            entries = store.entries_between(h["first_seq"], h["last_seq"])
            assert merkle_root([bytes.fromhex(e["hash"]) for e in entries]).hex() == h["entries_root"]
            # receipt hashes I issued are in the receipts_root of the batch that recorded them
            included = store.receipts_included_in(b["batch_no"])
            assert merkle_root([bytes.fromhex(x) for x in included]).hex() == h["receipts_root"]
        assert verify_chain(store.entries_between(1, store.last_entry()["seq"]), p.sk.verify_key).valid

        # receipts I hold are signed by the peers; authenticators I hold are signed by the peers
        for peer, _, psk in p.peers:
            for batch_no in range(1, s["batches"] - 2):
                r = store.get_receipt("received", peer, batch_no)
                if r is not None:
                    assert verify_receipt(psk.verify_key, r)
            auth = store.latest_authenticator_of(peer)
            assert auth is not None and verify_authenticator(psk.verify_key, auth)

        # one anchor window per 6 seconds went to the fake backend, in order (about 3 in 20 s)
        assert s["windows"] >= 2
        lines = [json.loads(l) for l in p.anchors.read_text().splitlines()]
        assert [l["batch_no"] for l in lines] == list(range(1, len(lines) + 1))
        assert len(lines) >= s["windows"] - 1   # at most the newest window may still be waiting
        store.close()
    print("  anchor file lines:", {n: len(p.anchors.read_text().splitlines()) for n, p in by_name.items()})
