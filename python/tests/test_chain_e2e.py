"""End-to-end: real Hardhat node + chain helper + witnesses. LOCAL chain only.

No private key appears here: the local node signs for its own unlocked test accounts,
and the witnesses' Ed25519 seeds are dummy bytes written to temp files.
"""
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time

import pytest
import requests
from nacl.signing import SigningKey

from logsabha_core import merkle_root
from witness.anchor import ChainAnchorBackend, ChainHelperError
from witness.core import Peer, Witness
from witness.storage import Storage

from test_witness_processes import Proc, free_port

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HELPER = os.path.join(REPO, "chain", "cli.js")
SOLIDITY = os.path.join(REPO, "Solidity")
EMPTY_ROOT = "0x" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ------------------------------------------------------------------ plumbing
def rpc_ready(port):
    try:
        r = requests.post("http://127.0.0.1:%d" % port, timeout=1,
                          json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []})
        return r.json().get("result") == "0x7a69"
    except (requests.RequestException, ValueError):
        return False


def kill_tree(proc):
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
    else:
        proc.kill()
    proc.wait(timeout=15)


@pytest.fixture(scope="module")
def node_port(tmp_path_factory):
    """One local Hardhat node for the whole file, on its own port (not 8545)."""
    port = free_port()
    log = tmp_path_factory.mktemp("node") / "node.log"   # the node prints its test accounts here; we never show it
    npx = shutil.which("npx")
    assert npx, "npx not found"
    proc = subprocess.Popen([npx, "hardhat", "node", "--hostname", "127.0.0.1", "--port", str(port)],
                            cwd=SOLIDITY, stdout=open(log, "wb"), stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 90
        while time.time() < deadline and not rpc_ready(port):
            assert proc.poll() is None, "hardhat node exited early"
            time.sleep(0.5)
        assert rpc_ready(port), "hardhat node did not start"
        yield port
    finally:
        kill_tree(proc)


def chain_env(rpc_port, deployment_file):
    env = dict(os.environ)
    env.update({"NETWORK": "localhost", "LOCAL_RPC_URL": "http://127.0.0.1:%d" % rpc_port,
                "LOCAL_CHAIN_ID": "31337", "CHAIN_DEPLOYMENT_FILE": str(deployment_file)})
    return env


def helper(env, command, payload=None, args=()):
    """Run the chain helper. Returns its parsed JSON answer (ok true or false)."""
    proc = subprocess.run(["node", HELPER, command, *args], input=json.dumps(payload) if payload is not None else None,
                          capture_output=True, text=True, timeout=120, env=env)
    return json.loads(proc.stdout.strip().splitlines()[-1])


def setup_local(env, seed_bytes):
    keys = {n: SigningKey(bytes([b]) * 32) for n, b in seed_bytes.items()}
    out = helper(env, "setup-local", {"witnesses": {n: k.verify_key.encode().hex() for n, k in keys.items()},
                                      "maxGapSeconds": 600})
    assert out["ok"], out
    return keys, out


class TcpProxy:
    """Plain TCP forwarder. Stopping it makes the chain unreachable while the node (and its
    memory) stays alive. A restarted `hardhat node` would start from an EMPTY chain."""

    def __init__(self, port, target_port):
        self.port, self.target = port, target_port
        self._srv = None
        self._conns = []

    def start(self):
        self._closing = False
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.port))
        self._srv.listen(64)
        self._srv.settimeout(0.2)
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self):
        while not self._closing:
            try:
                client, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        try:
            upstream = socket.create_connection(("127.0.0.1", self.target), timeout=5)
        except OSError:
            client.close()
            return
        self._conns += [client, upstream]

        def pump(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
        pump(upstream, client)

    def stop(self):
        self._closing = True
        self._thread.join(timeout=3)
        self._srv.close()
        for c in self._conns:
            try:
                c.close()
            except OSError:
                pass
        self._conns = []


def db_windows(db_path):
    """Window number -> queue state, read straight from SQLite (safe while the witness runs)."""
    con = sqlite3.connect(str(db_path), timeout=10)
    try:
        return dict(con.execute("SELECT window_no, state FROM anchor_queue").fetchall())
    finally:
        con.close()


def recompute_window_roots(store, w):
    """Roots recomputed ONLY from the witness's own entries and receipts, using logsabha_core."""
    entries = store.entries_between(w["first_seq"], w["last_seq"]) if w["last_seq"] >= w["first_seq"] else []
    entries_root = merkle_root([bytes.fromhex(e["hash"]) for e in entries]).hex()
    receipts = store.receipts_included_between(w["first_batch"], w["last_batch"])
    receipts_root = merkle_root([bytes.fromhex(h) for h in receipts]).hex()
    return "0x" + entries_root, "0x" + receipts_root


# --------------------------------------------------------------------- tests
def test_end_to_end_three_witnesses_anchor_on_the_local_chain_for_60_seconds(tmp_path, node_port, procs):
    deployment = tmp_path / "deployment.json"
    env = chain_env(node_port, deployment)
    seeds = {"app": 51, "network": 52, "outside": 53}
    keys, setup = setup_local(env, seeds)

    # owners and witness accounts: 6 different accounts, nobody is both
    accounts = setup["owners"] + [w["anchorAccount"] for w in setup["witnesses"].values()]
    assert len({a.lower() for a in accounts}) == 6

    ports = {n: free_port() for n in seeds}
    for n in seeds:
        peers = [(m, ports[m], keys[m]) for m in seeds if m != n]
        procs.append(Proc(tmp_path, n, n, seeds[n], ports[n], peers, env=env, extra_args=[
            "--backend", "chain", "--anchor-interval", "6", "--confirmations", "3", "--receipt-grace", "4",
            "--deployment-file", str(deployment)]))
    by_name = {p.name: p for p in procs}
    for p in procs:
        p.start()

    t0 = time.time()
    time.sleep(3)
    for i in range(6):
        by_name["app"].post_entry(request_id="a%d" % i, bytes=2148)
    for i in range(4):
        by_name["network"].post_entry(event_type="flow", request_id="n%d" % i, bytes=2148)
    time.sleep(9)
    for i in range(3):
        by_name["outside"].post_entry(event_type="counter", request_id="o%d" % i, bytes=2121)
    time.sleep(max(0, 60 - (time.time() - t0)))

    live = {n: p.status() for n, p in by_name.items()}
    for p in procs:
        p.kill()                                  # hard stop, like a crash

    # Drain: reopen each witness's own database (a restart) and let its queue finish.
    print("\n  AT STOP (after 60 s):")
    for n, p in by_name.items():
        print("    %-8s windows=%d queue=%s" % (n, live[n]["windows"], live[n]["queue"]))
    drained = {}
    for n, p in by_name.items():
        w = Witness(n, n, p.sk, p.db, peers=(), required_confirmations=3, receipt_grace=0, anchor_interval=6,
                    backend=ChainAnchorBackend(n, HELPER, deployment_file=deployment, env=env))
        deadline = time.time() + 90
        while time.time() < deadline:
            w.process_anchor_queue()
            states = w.store.queue_counts()
            if set(states) == {"CONFIRMED"}:
                break
            time.sleep(1)
        drained[n] = states
        w.store.close()

    print("\n  WITNESS   windows  on-chain  CONFIRMED  heartbeats  example tx hash")
    gas = {"entries": [], "heartbeat": []}
    for n, p in by_name.items():
        store = Storage(p.db)
        windows = store.list_windows()
        queue = {r["batch_no"]: r for r in store.queue_rows(("CONFIRMED",))}
        assert drained[n] == {"CONFIRMED": len(windows)}, "every window must end CONFIRMED: %s" % drained[n]

        chain = helper(env, "readAnchors", args=(n, "1", str(len(windows))))
        assert chain["ok"], chain
        assert chain["lastBatchNo"] == len(windows) and len(chain["anchors"]) == len(windows)

        heartbeats = 0
        for w, a in zip(windows, chain["anchors"]):
            assert a["batchNo"] == w["window_no"]
            # the chain's roots must equal roots recomputed from the witness's OWN database
            entries_root, receipts_root = recompute_window_roots(store, w)
            assert a["entriesRoot"] == entries_root == "0x" + w["entries_root"]
            assert a["receiptsRoot"] == receipts_root == "0x" + w["receipts_root"]
            assert (a["firstSeq"], a["lastSeq"]) == (w["first_seq"], w["last_seq"])
            assert a["policyHash"] == "0x" + "00" * 32
            assert queue[w["window_no"]]["ref"] == a["txHash"]       # the queue kept the same tx hash
            if w["last_seq"] < w["first_seq"]:
                heartbeats += 1
                assert a["entriesRoot"] == EMPTY_ROOT
                gas["heartbeat"].append(int(a["gasUsed"]))
            else:
                gas["entries"].append(int(a["gasUsed"]))
            conf = helper(env, "confirmations", args=(a["txHash"],))
            assert conf["ok"] and conf["confirmations"] >= 3
        # sequence ranges are contiguous across windows
        assert all(b["first_seq"] == a_["last_seq"] + 1 for a_, b in zip(windows, windows[1:]))
        assert len(windows) >= 7 and heartbeats >= 1
        print("  %-8s  %7d  %8d  %9d  %10d  %s" % (n, len(windows), len(chain["anchors"]), len(queue),
                                                    heartbeats, chain["anchors"][0]["txHash"]))
        store.close()

    for kind, values in gas.items():
        if values:
            print("  gasUsed per anchor, %-9s windows: min %d  max %d  avg %d  (n=%d)" % (
                kind, min(values), max(values), sum(values) // len(values), len(values)))


def test_a_replayed_anchor_is_rejected_by_the_chain(tmp_path, node_port):
    deployment = tmp_path / "deployment.json"
    env = chain_env(node_port, deployment)
    setup_local(env, {"app": 61, "network": 62, "outside": 63})
    backend = ChainAnchorBackend("app", HELPER, deployment_file=deployment, env=env)

    def batch(n, first, last, root="aa" * 32, receipts="bb" * 32):
        return {"batch_no": n, "header": {"batch_no": n, "first_seq": first, "last_seq": last, "entries_root": root,
                                         "receipts_root": receipts, "policy_hash": "00" * 32}}

    first = batch(1, 1, 5)
    tx1 = backend.submit(first)
    # the chain really holds it, and confirmations grow as the node keeps mining blocks
    time.sleep(4)
    assert backend.get_confirmations({**first, "ref": tx1}) >= 3

    payload = {"witnessId": "app", "batchNo": 1, "entriesRoot": "aa" * 32, "receiptsRoot": "bb" * 32,
               "policyHash": "00" * 32, "firstSeq": 1, "lastSeq": 5}

    # 1) the chain itself rejects the replay
    replay = helper(env, "anchor", {**payload, "skipPrecheck": True})
    assert replay["ok"] is False and "bad batch number (gap or replay)" in replay["error"]
    print("\n  chain says about a replay:", replay["error"])

    # 2) the helper's safe-repeat path returns the SAME transaction (no second tx)
    again = helper(env, "anchor", payload)
    assert again["ok"] and again["alreadyAnchored"] and again["txHash"] == tx1
    assert backend.submit(first) == tx1

    # 3) same batch number, different content: a conflict, never overwritten
    clash = helper(env, "anchor", {**payload, "entriesRoot": "cc" * 32})
    assert clash["ok"] is False and "conflict" in clash["error"]

    # 4) gaps are rejected by the chain; out-of-order numbers by the helper
    gap = helper(env, "anchor", {**payload, "batchNo": 2, "firstSeq": 9, "lastSeq": 10})
    assert gap["ok"] is False and "sequence gap" in gap["error"]
    far = helper(env, "anchor", {**payload, "batchNo": 7})
    assert far["ok"] is False and "out of order" in far["error"]

    # 5) a heartbeat (empty window) is accepted and uses the next batch number
    beat = batch(2, 6, 5, root=EMPTY_ROOT[2:])
    tx2 = backend.submit(beat)
    assert tx2 != tx1
    read = helper(env, "readAnchors", args=("app", "1", "2"))
    assert [a["batchNo"] for a in read["anchors"]] == [1, 2]
    assert read["lastSeq"] == 5                    # the heartbeat did not move lastSeq
    print("  gasUsed: normal anchor %s, heartbeat %s" % (read["anchors"][0]["gasUsed"], read["anchors"][1]["gasUsed"]))

    # the helper refuses anything but the local chain
    assert helper({**env, "NETWORK": "cyprus1"}, "readAnchors", args=("app", "1", "1"))["ok"] is False
    assert helper({**env, "LOCAL_RPC_URL": "http://203.0.113.5:8545"}, "readAnchors", args=("app", "1", "1"))["ok"] is False
    with pytest.raises(ChainHelperError):
        ChainAnchorBackend("ghost", HELPER, deployment_file=deployment, env=env).submit(batch(1, 1, 5))


def test_chain_stopped_for_20_seconds_anchors_stay_queued_then_go_through_in_order(tmp_path, node_port, procs):
    # The node keeps its memory; we cut the connection to it with a forwarder.
    proxy_port = free_port()
    proxy = TcpProxy(proxy_port, node_port)
    proxy.start()
    try:
        deployment = tmp_path / "deployment.json"
        env = chain_env(proxy_port, deployment)
        keys, _ = setup_local(env, {"app": 71, "network": 72, "outside": 73})

        w = Proc(tmp_path, "app", "app", 71, free_port(), [], env=env, extra_args=[
            "--backend", "chain", "--anchor-interval", "3", "--confirmations", "3", "--receipt-grace", "0",
            "--deployment-file", str(deployment)])
        procs.append(w)
        w.start()

        # chain up: windows are anchored and confirmed
        deadline = time.time() + 60
        while time.time() < deadline and list(db_windows(w.db).values()).count("CONFIRMED") < 2:
            time.sleep(1)
        before = db_windows(w.db)
        assert list(before.values()).count("CONFIRMED") >= 2

        # chain down for 20 seconds
        proxy.stop()
        down_from = len(before)
        for i in range(3):
            w.post_entry(request_id="during-outage-%d" % i)
            time.sleep(6.5)
        during = db_windows(w.db)
        stuck = {n: s for n, s in during.items() if n > max(n for n, s in before.items() if s == "CONFIRMED")}
        print("\n  while the chain was down: windows=%d, waiting=%s" % (
            len(during), sorted(set(s for s in stuck.values()))))
        assert len(during) >= len(before) + 4                          # new windows kept being created
        waiting = [n for n, s in during.items() if s in ("CREATED", "PEER_RECEIPTED")]
        assert len(waiting) >= 4                                       # ...and are queued, not lost
        assert set(range(1, len(during) + 1)) == set(during)           # no window number missing

        # chain back
        proxy.start()
        target = len(during)
        deadline = time.time() + 90
        while time.time() < deadline:
            now = db_windows(w.db)
            if all(now.get(n) == "CONFIRMED" for n in range(1, target + 1)):
                break
            time.sleep(1)
        now = db_windows(w.db)
        assert all(now.get(n) == "CONFIRMED" for n in range(1, target + 1)), now
        w.kill()

        # on chain: every window, in order; block numbers never go backwards
        store = Storage(w.db)
        windows = store.list_windows()[:target]          # the windows that existed when the chain came back
        chain = helper(env, "readAnchors", args=("app", "1", str(target)))
        assert chain["ok"] and [a["batchNo"] for a in chain["anchors"]] == [x["window_no"] for x in windows]
        blocks = [a["blockNumber"] for a in chain["anchors"]]
        assert blocks == sorted(blocks)
        for x, a in zip(windows, chain["anchors"]):
            assert a["entriesRoot"] == recompute_window_roots(store, x)[0]
        late = [a for a in chain["anchors"] if a["batchNo"] > down_from]
        print("  after it came back: %d anchors on chain, in order; blocks of the late ones: %s" % (
            len(chain["anchors"]), [a["blockNumber"] for a in late][:8]))
        store.close()
    finally:
        try:
            proxy.stop()
        except OSError:
            pass
