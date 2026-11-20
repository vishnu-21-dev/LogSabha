"""The anchor backend interface, plus a FAKE backend for now.

A real backend (the blockchain one) will come in a later step. Only batch
headers (roots, hashes, sequence ranges) are ever handed to a backend.
"""
import json
import os
import subprocess
import threading


class AnchorBackend:
    """What the queue talks to. submit() may raise; the queue will retry."""

    def submit(self, batch: dict) -> str:
        """batch = {"batch_no": int, "header": signed batch header}.
        Returns a reference string for the submission."""
        raise NotImplementedError

    def get_confirmations(self, batch: dict) -> int:
        """How many confirmations the batch has (0 = not seen yet)."""
        raise NotImplementedError


class ChainHelperError(Exception):
    """The chain helper failed (chain unreachable, transaction rejected, ...). The queue retries."""


class ChainAnchorBackend(AnchorBackend):
    """Anchors on a chain by calling the Node.js helper in chain/ (JSON in on stdin, one JSON line out).

    The helper never needs a private key from us: on the local chain the node signs for
    the witness's own account; in Quai mode (later) it will read keys from .env or key files.
    """

    def __init__(self, witness_id, helper_path, deployment_file=None, env=None, node="node", timeout=90):
        self.witness_id = witness_id
        self.helper_path = str(helper_path)
        self.node = node
        self.timeout = timeout
        self.env = dict(os.environ if env is None else env)
        if deployment_file is not None:
            self.env["CHAIN_DEPLOYMENT_FILE"] = str(deployment_file)

    def _run(self, command, payload=None):
        try:
            proc = subprocess.run(
                [self.node, self.helper_path, command],
                input=json.dumps(payload) if payload is not None else None,
                capture_output=True, text=True, timeout=self.timeout, env=self.env)
        except subprocess.TimeoutExpired:
            raise ChainHelperError("chain helper timed out after %ss" % self.timeout)
        except OSError as err:
            raise ChainHelperError("cannot run the chain helper: %s" % type(err).__name__)
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        try:
            out = json.loads(lines[-1])
        except (IndexError, ValueError):
            raise ChainHelperError("chain helper gave no JSON answer (exit code %d)" % proc.returncode)
        if not out.get("ok"):
            raise ChainHelperError(str(out.get("error", "unknown chain helper error"))[:300])
        return out

    def submit(self, batch):
        h = batch["header"]
        out = self._run("anchor", {
            "witnessId": self.witness_id,
            "batchNo": h["batch_no"],
            "entriesRoot": h["entries_root"],
            "receiptsRoot": h["receipts_root"],
            "policyHash": h["policy_hash"],
            "firstSeq": h["first_seq"],
            "lastSeq": h["last_seq"],
        })
        return out["txHash"]

    def get_confirmations(self, batch):
        ref = batch.get("ref")
        if not ref:
            return 0
        return int(self._run("confirmations", {"txHash": ref})["confirmations"])


class FakeFileBackend(AnchorBackend):
    """Writes one JSON line per batch to a local file. No blockchain at all.
    Submitting the same batch twice does not write it twice."""

    def __init__(self, path):
        self.path = str(path)
        self._lock = threading.Lock()
        parent = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(parent, exist_ok=True)

    def _read_batch_nos(self):
        if not os.path.exists(self.path):
            return set()
        with open(self.path, "r", encoding="utf-8") as f:
            return {json.loads(line)["batch_no"] for line in f if line.strip()}

    def submit(self, batch):
        with self._lock:
            if batch["batch_no"] not in self._read_batch_nos():
                line = json.dumps({"batch_no": batch["batch_no"], "header": batch["header"]})
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            return "file:%s#%d" % (os.path.basename(self.path), batch["batch_no"])

    def get_confirmations(self, batch):
        with self._lock:
            return 1 if batch["batch_no"] in self._read_batch_nos() else 0
