"""Start the QuickPay demo app. Every address and port is an argument.

  python -m demo_app --host <bind host> --port <port> --db <file> \\
      --witness-url <App witness URL> --gateway-url <gateway URL> --demo-password <fake password>
"""
import argparse
import logging
import os

from svc.stopfile import serve_uvicorn

from .app import Settings, create_app


def main(argv=None):
    p = argparse.ArgumentParser(prog="demo_app", description="QuickPay, a fake fintech (demo)")
    p.add_argument("--host", required=True, help="address to listen on")
    p.add_argument("--port", required=True, type=int)
    p.add_argument("--db", required=True, help="SQLite file for the fake customers")
    p.add_argument("--witness-url", required=True, help="URL of this app's own App witness")
    p.add_argument("--gateway-url", required=True, help="URL of the gateway (used as an HTTP proxy)")
    p.add_argument("--demo-password", required=True, help="FAKE login password for the demo staff accounts")
    p.add_argument("--customers", type=int, default=200)
    p.add_argument("--max-export-bytes", type=int, default=20_000_000)
    p.add_argument("--label", default="", help="deployment label shown in /status")
    p.add_argument("--stop-file", help="when this file appears, shut down cleanly")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO)
    os.makedirs(os.path.dirname(os.path.abspath(args.db)), exist_ok=True)
    app = create_app(Settings(
        db_path=args.db, witness_url=args.witness_url, gateway_url=args.gateway_url,
        demo_password=args.demo_password, customers=args.customers,
        max_export_bytes=args.max_export_bytes, label=args.label))
    serve_uvicorn(app, args.host, args.port, args.stop_file)


if __name__ == "__main__":
    main()
