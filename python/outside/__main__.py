"""Start the outside witness's observation point. Every address and port is an argument.

  sink mode (default):  python -m outside --witness-url <Outside witness URL> --host <bind host> --port <port>
  scapy mode:           python -m outside --mode scapy --witness-url <Outside witness URL> \\
                            --iface <interface name> --watch-port <port> [--watch-port <port> ...]
"""
import argparse
import logging
import sys
import threading

from svc.poster import EntryPoster
from svc.stopfile import watch_stop_file


def main(argv=None):
    p = argparse.ArgumentParser(prog="outside", description="Outside witness observation point")
    p.add_argument("--mode", choices=("sink", "scapy"), default="sink")
    p.add_argument("--witness-url", required=True, help="URL of this capture's own Outside witness")
    p.add_argument("--host", help="sink mode: address to listen on")
    p.add_argument("--port", type=int, help="sink mode: port to listen on")
    p.add_argument("--iface", help="scapy mode: network interface to capture on")
    p.add_argument("--watch-port", type=int, action="append", default=[], help="scapy mode: TCP port to watch (repeatable)")
    p.add_argument("--idle-seconds", type=float, default=2.0)
    p.add_argument("--label", default="", help="deployment label shown in /__stats")
    p.add_argument("--stop-file", help="when this file appears, shut down cleanly")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO)
    poster = EntryPoster(args.witness_url)

    if args.mode == "sink":
        if not args.host or not args.port:
            p.error("sink mode needs --host and --port")
        from .sink import make_server
        server = make_server(args.host, args.port, poster, args.label)
        watch_stop_file(args.stop_file, lambda: threading.Thread(target=server.shutdown, daemon=True).start())
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    else:
        if not args.iface or not args.watch_port:
            p.error("scapy mode needs --iface and at least one --watch-port")
        stop = threading.Event()
        watch_stop_file(args.stop_file, stop.set)
        try:
            from .capture import run_capture
            run_capture(args.watch_port, args.iface, poster, stop, args.idle_seconds)
        except KeyboardInterrupt:
            pass
        except Exception as err:       # scapy missing, Npcap missing, no permission, bad interface ...
            print("scapy mode is not available here (%s: %s). Use --mode sink." % (type(err).__name__, err),
                  file=sys.stderr)
            poster.close(1)
            return 3
    poster.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
