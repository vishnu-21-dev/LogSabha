"""Start one witness:

  python -m witness --role app --name app --port 8101 --key-file keys/app.seed \\
      --peer network=http://127.0.0.1:8102=<public key hex> \\
      --peer outside=http://127.0.0.1:8103=<public key hex>

--peer is NAME=URL=PUBLIC_KEY_HEX. Public keys are not secret. The seed file is.
"""
import argparse
import logging
import os
import sys

import uvicorn

from .anchor import FakeFileBackend
from .api import create_app
from .core import ROLES, Peer, Witness
from .keys import KeyFileError, load_signing_key


def parse_peer(text):
    parts = text.split("=")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("--peer must look like NAME=URL=PUBLIC_KEY_HEX")
    name, url, key_hex = parts
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        raise argparse.ArgumentTypeError("peer public key must be hex")
    if len(key) != 32:
        raise argparse.ArgumentTypeError("peer public key must be 32 bytes (64 hex characters)")
    return Peer(name=name, url=url, verify_key=key)


def main(argv=None):
    p = argparse.ArgumentParser(prog="witness", description="LogSabha witness agent")
    p.add_argument("--role", required=True, choices=ROLES)
    p.add_argument("--name", required=True, help="this witness's id")
    p.add_argument("--port", required=True, type=int)
    p.add_argument("--key-file", required=True, help="file holding this witness's Ed25519 seed")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--db", help="SQLite file (default data/<name>.db)")
    p.add_argument("--anchor-file", help="fake anchor backend output (default data/<name>.anchors.jsonl)")
    p.add_argument("--peer", action="append", default=[], type=parse_peer)
    p.add_argument("--batch-interval", type=float, default=2.0)
    p.add_argument("--receipt-grace", type=float, default=10.0,
                   help="seconds to wait for a peer receipt before anchoring a batch anyway")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    try:
        signing_key = load_signing_key(args.key_file)
    except KeyFileError as err:
        print("error:", err, file=sys.stderr)
        return 2

    db = args.db or os.path.join("data", args.name + ".db")
    anchor_file = args.anchor_file or os.path.join("data", args.name + ".anchors.jsonl")
    os.makedirs(os.path.dirname(os.path.abspath(db)), exist_ok=True)

    witness = Witness(
        name=args.name, role=args.role, signing_key=signing_key, db_path=db, peers=args.peer,
        backend=FakeFileBackend(anchor_file), batch_interval=args.batch_interval,
        receipt_grace=args.receipt_grace,
    )
    uvicorn.run(create_app(witness), host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
