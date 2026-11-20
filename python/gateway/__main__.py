"""Start the network gateway. Every address and port is an argument.

  python -m gateway --host <bind host> --port <port> --witness-url <Network witness URL>
"""
import argparse
import logging
import threading

from svc.poster import EntryPoster
from svc.stopfile import watch_stop_file

from .proxy import make_server


def main(argv=None):
    p = argparse.ArgumentParser(prog="gateway", description="Plain-HTTP gateway that reports to the Network witness")
    p.add_argument("--host", required=True, help="address to listen on")
    p.add_argument("--port", required=True, type=int)
    p.add_argument("--witness-url", required=True, help="URL of this gateway's own Network witness")
    p.add_argument("--label", default="", help="deployment label shown in /status")
    p.add_argument("--upstream-timeout", type=float, default=60.0)
    p.add_argument("--stop-file", help="when this file appears, shut down cleanly")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO)
    poster = EntryPoster(args.witness_url)
    server = make_server(args.host, args.port, poster, args.label, args.upstream_timeout)
    watch_stop_file(args.stop_file, lambda: threading.Thread(target=server.shutdown, daemon=True).start())
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        poster.close()


if __name__ == "__main__":
    main()
