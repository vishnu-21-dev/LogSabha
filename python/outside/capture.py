"""Scapy mode: real packet capture of TCP flows toward the watched ports.

For each flow it records (source, destination, bytes, time) and posts it to the Outside witness.
"Bytes" here is TCP payload, so it includes HTTP headers: a few hundred bytes more per request
than sink mode's body-only count. Retransmitted packets are counted again (a known simplification).
Needs scapy and, on Windows, Npcap (with loopback support for same-machine traffic).
"""
import threading
import time


class FlowTable:
    """Adds up payload bytes per flow and turns finished or idle flows into records."""

    def __init__(self, watch_ports, idle_seconds=2.0):
        self.watch_ports = set(watch_ports)
        self.idle_seconds = idle_seconds
        self._flows = {}
        self._lock = threading.Lock()

    def add_packet(self, src, sport, dst, dport, payload_len, closing, now=None):
        if dport not in self.watch_ports:           # only traffic going TO a watched port
            return
        now = time.time() if now is None else now
        with self._lock:
            f = self._flows.setdefault((src, sport, dst, dport), {"bytes": 0, "last": now, "closed": False})
            f["bytes"] += payload_len
            f["last"] = now
            f["closed"] = f["closed"] or closing

    def collect_finished(self, now=None):
        """Remove and return flows that ended (FIN/RST) or have been quiet for idle_seconds."""
        now = time.time() if now is None else now
        done = []
        with self._lock:
            for key, f in list(self._flows.items()):
                quiet = now - f["last"]
                if (f["closed"] and quiet > 0.5) or quiet > self.idle_seconds:
                    del self._flows[key]
                    if f["bytes"] > 0:               # a bare handshake carried no data
                        done.append((key, f["bytes"]))
        return done


def run_capture(watch_ports, iface, poster, stop_event, idle_seconds=2.0):
    from scapy.all import IP, TCP, sniff     # imported here so sink mode works without scapy

    table = FlowTable(watch_ports, idle_seconds)

    def on_packet(pkt):
        if IP in pkt and TCP in pkt:
            ip, tcp = pkt[IP], pkt[TCP]
            table.add_packet(ip.src, tcp.sport, ip.dst, tcp.dport, len(tcp.payload), bool(int(tcp.flags) & 0x05))

    def flush_loop():
        while not stop_event.is_set():
            time.sleep(0.5)
            for (src, _sport, dst, dport), size in table.collect_finished():
                poster.post("flow", "", "in", "%s:%d" % (dst, dport), size, "ok;src=%s" % src)

    threading.Thread(target=flush_loop, name="flow-flusher", daemon=True).start()
    ports = " or ".join("dst port %d" % p for p in sorted(set(watch_ports)))
    sniff(iface=iface, filter="tcp and (%s)" % ports, prn=on_packet, store=False,
          stop_filter=lambda _pkt: stop_event.is_set())
    for (src, _sport, dst, dport), size in table.collect_finished(now=time.time() + 3600):   # flush what is left
        poster.post("flow", "", "in", "%s:%d" % (dst, dport), size, "ok;src=%s" % src)
