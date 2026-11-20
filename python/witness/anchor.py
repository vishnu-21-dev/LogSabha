"""The anchor backend interface, plus a FAKE backend for now.

A real backend (the blockchain one) will come in a later step. Only batch
headers (roots, hashes, sequence ranges) are ever handed to a backend.
"""
import json
import os
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
