"""Start one witness:

  python -m witness --role app --name app --port 8101 --key-file keys/app.seed \\
      --peer network=http://127.0.0.1:8102=<public key hex> \\
      --peer outside=http://127.0.0.1:8103=<public key hex>

--peer is NAME=URL=PUBLIC_KEY_HEX. Public keys are not secret. The seed file is.

Export what this witness knows as an evidence bundle (read only; the witness may keep running):

  python -m witness export --db data/app.db --out bundle-app.json
"""
import argparse
import logging
import os
import sys

from .anchor import ChainAnchorBackend, FakeFileBackend
from .api import create_app
from .core import ROLES, Peer, Witness
from .keys import KeyFileError, load_signing_key
from logsabha_core.policy import PolicyError, load_policy_file
from svc.stopfile import serve_uvicorn


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] == "export":                  # python -m witness export --db ... --out ...
        from .export import export_main
        return export_main(argv[1:])
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
                   help="seconds to wait for a peer receipt before anchoring a window anyway")
    p.add_argument("--anchor-interval", type=float, default=30.0,
                   help="seconds per anchor window; one on-chain anchor is made per window")
    p.add_argument("--backend", choices=("chain", "fake"), default="chain",
                   help="chain = call the chain helper (default); fake = write to a local file")
    p.add_argument("--confirmations", type=int, default=3, help="confirmations needed to mark CONFIRMED (chain backend)")
    p.add_argument("--policy-file", help="the policy JSON; its hash goes into every anchor window (default: no policy, zero hash)")
    p.add_argument("--stop-file", help="when this file appears, shut down cleanly (writes the shutdown marker)")
    p.add_argument("--chain-helper", default=os.path.join(REPO_ROOT, "chain", "cli.js"))
    p.add_argument("--deployment-file", default=os.path.join(REPO_ROOT, "chain", "deployment.localhost.json"),
                   help="addresses written by the helper's setup-local command")
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

    policy = None
    if args.policy_file:
        try:
            policy, _ = load_policy_file(args.policy_file)
        except PolicyError as err:
            print("error: policy file:", err, file=sys.stderr)
            return 2

    if args.backend == "fake":
        backend, confirmations = FakeFileBackend(anchor_file), 1
    else:
        backend = ChainAnchorBackend(args.name, args.chain_helper, deployment_file=args.deployment_file)
        confirmations = args.confirmations

    witness = Witness(
        name=args.name, role=args.role, signing_key=signing_key, db_path=db, peers=args.peer,
        backend=backend, batch_interval=args.batch_interval, receipt_grace=args.receipt_grace,
        required_confirmations=confirmations, anchor_interval=args.anchor_interval, policy=policy,
    )
    serve_uvicorn(create_app(witness), args.host, args.port, args.stop_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
