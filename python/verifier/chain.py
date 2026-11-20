"""Chain readers: where the verifier gets the on-chain facts.

The verifier takes witness PUBLIC KEYS and ANCHORS from here, and never from a bundle.
A chain reader is pluggable: the local-chain helper works now, Quai comes later.
"""
import json
import os
import subprocess

EMPTY_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"   # SHA-256 of nothing


class ChainError(Exception):
    """The chain could not be read (so nothing can be checked against it)."""


def hex_root(value):
    """Normal form for a 32-byte hex value: lower case, no 0x."""
    text = str(value).strip().lower()
    return text[2:] if text.startswith("0x") else text


class ChainReader:
    description = "chain reader"

    def witness_keys(self):
        """{witness_id: {"registered": bool, "active": bool, "public_key": hex or None,
        "last_batch_no": int, "last_seq": int}} for every witness registered on the chain."""
        raise NotImplementedError

    def anchors(self, witness_id, last_batch_no):
        """Anchors 1..last_batch_no of one witness, as a list of dicts with the keys
        batch_no, entries_root, receipts_root, first_seq, last_seq, tx_hash, restart, block_time."""
        raise NotImplementedError


def _anchor_from_helper(a):
    return {
        "batch_no": int(a["batchNo"]),
        "entries_root": hex_root(a["entriesRoot"]),
        "receipts_root": hex_root(a["receiptsRoot"]),
        "first_seq": int(a["firstSeq"]),
        "last_seq": int(a["lastSeq"]),
        "tx_hash": a.get("txHash"),
        "restart": bool(a.get("restart")),
        "block_time": a.get("blockTime"),
    }


class HelperChainReader(ChainReader):
    """Reads the local chain by running the Node helper (chain/cli.js). JSON out, one line."""

    def __init__(self, helper_path, deployment_file=None, env=None, node="node", timeout=120):
        self.helper_path = str(helper_path)
        self.node = node
        self.timeout = timeout
        self.env = dict(os.environ if env is None else env)
        if deployment_file is not None:
            self.env["CHAIN_DEPLOYMENT_FILE"] = str(deployment_file)
        self.description = "local chain, through the chain helper"

    def _run(self, *args):
        try:
            proc = subprocess.run([self.node, self.helper_path, *args], capture_output=True, text=True,
                                  timeout=self.timeout, env=self.env)
        except subprocess.TimeoutExpired:
            raise ChainError("the chain helper timed out after %ss" % self.timeout)
        except OSError as err:
            raise ChainError("cannot run the chain helper (%s)" % type(err).__name__)
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        try:
            out = json.loads(lines[-1])
        except (IndexError, ValueError):
            raise ChainError("the chain helper gave no JSON answer (exit code %d)" % proc.returncode)
        if not out.get("ok"):
            raise ChainError(str(out.get("error", "unknown chain helper error"))[:300])
        return out

    def witness_keys(self):
        out = self._run("readWitness")
        keys = {}
        for name, w in out["witnesses"].items():
            keys[name] = {"registered": bool(w.get("registered")), "active": bool(w.get("active")),
                          "public_key": w.get("edPubKey"), "last_batch_no": int(w.get("lastBatchNo", 0)),
                          "last_seq": int(w.get("lastSeq", 0))}
        return keys

    def anchors(self, witness_id, last_batch_no):
        if last_batch_no < 1:
            return []
        out = self._run("readAnchors", witness_id, "1", str(last_batch_no))
        return [_anchor_from_helper(a) for a in out["anchors"]]


class StaticChainReader(ChainReader):
    """Chain facts held in memory. For tests and for replaying a saved copy of chain data."""

    def __init__(self, keys, anchors, description="chain data held in memory"):
        self._keys = keys
        self._anchors = anchors
        self.description = description

    def witness_keys(self):
        out = {}
        for name, pub in self._keys.items():
            anchors = self._anchors.get(name, [])
            out[name] = {"registered": True, "active": True, "public_key": pub,
                         "last_batch_no": max((a["batch_no"] for a in anchors), default=0),
                         "last_seq": max((a["last_seq"] for a in anchors), default=0)}
        return out

    def anchors(self, witness_id, last_batch_no):
        return [dict(a) for a in self._anchors.get(witness_id, []) if a["batch_no"] <= last_batch_no]


class QuaiChainReader(ChainReader):
    """Placeholder. Reading the real Quai chain comes in a later step."""

    description = "Quai chain (not available yet)"

    def witness_keys(self):
        raise ChainError("the Quai chain reader is not built yet")

    def anchors(self, witness_id, last_batch_no):
        raise ChainError("the Quai chain reader is not built yet")
