"""Sends log entries to a witness (POST /entries) without ever blocking the caller.

Entries wait in an in-memory queue and are sent in order. If the witness is down or slow,
the poster keeps retrying (it never skips an entry). Entries that the witness refuses
(HTTP 4xx) are dropped and counted, because retrying them can never succeed.

Limit, said plainly: the queue lives in memory. If the service itself crashes while the
witness is unreachable, the queued entries are lost. A later step can add a disk spool.
"""
import collections
import logging
import threading
import time

import requests

log = logging.getLogger("svc.poster")


class EntryPoster:
    def __init__(self, witness_url, timeout=2.0, retry_seconds=1.0, max_queue=10000):
        self.url = witness_url.rstrip("/") + "/entries"
        self.timeout = timeout
        self.retry_seconds = retry_seconds
        self.max_queue = max_queue
        self._queue = collections.deque()
        self._cond = threading.Condition()
        self._stop = False
        self.sent = 0
        self.dropped = 0
        self._session = requests.Session()
        self._session.trust_env = False        # never route witness traffic through a proxy
        self._thread = threading.Thread(target=self._run, name="entry-poster", daemon=True)
        self._thread.start()

    def post(self, event_type, request_id, direction, dst, bytes_, result):
        """Queue one entry. Returns immediately."""
        item = {"event_type": event_type, "request_id": request_id, "direction": direction,
                "dst": dst, "bytes": int(bytes_), "result": result}
        with self._cond:
            if len(self._queue) >= self.max_queue:
                self.dropped += 1
                log.error("entry queue is full; dropping an entry")
                return
            self._queue.append(item)
            self._cond.notify()

    def pending(self):
        with self._cond:
            return len(self._queue)

    def flush(self, timeout=10.0):
        """Wait until everything queued has been delivered. Returns True if the queue emptied."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.pending() == 0:
                return True
            time.sleep(0.05)
        return self.pending() == 0

    def close(self, flush_timeout=5.0):
        self.flush(flush_timeout)
        with self._cond:
            self._stop = True
            self._cond.notify()
        self._thread.join(timeout=2)

    def _run(self):
        while True:
            with self._cond:
                while not self._queue and not self._stop:
                    self._cond.wait()
                if self._stop and not self._queue:
                    return
                item = self._queue[0]
            try:
                r = self._session.post(self.url, json=item, timeout=self.timeout)
            except requests.RequestException:
                time.sleep(self.retry_seconds)          # witness unreachable: try the same entry again
                continue
            if r.status_code == 200:
                self.sent += 1
            elif 400 <= r.status_code < 500:
                self.dropped += 1
                log.error("witness refused an entry (HTTP %d); dropped", r.status_code)
            else:
                time.sleep(self.retry_seconds)
                continue
            with self._cond:
                self._queue.popleft()
                self._cond.notify_all()
