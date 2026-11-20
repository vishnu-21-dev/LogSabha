"""The offline verifier.

  python -m verifier verify --bundles app.json network.json outside.json \\
      --chain-helper <path to chain/cli.js> [--deployment-file <file>] [--json] [--explain] [--finding F-0042]

Exit codes: 0 all MATCH, 1 any MISMATCH, 2 any CANNOT VERIFY and no MISMATCH, 3 the command itself was wrong.
It reads files and the chain. It never contacts a live witness.
"""
import argparse
import json
import sys

from .chain import HelperChainReader
from .report import finding_report, human_report, json_report
from .rules import verify

USAGE_ERROR = 3


class _Parser(argparse.ArgumentParser):
    def error(self, message):                     # argparse would exit with 2, which means CANNOT VERIFY here
        self.print_usage(sys.stderr)
        print("error: %s" % message, file=sys.stderr)
        raise SystemExit(USAGE_ERROR)


def main(argv=None, reader=None):
    p = _Parser(prog="verifier", description="Offline verifier for LogSabha evidence bundles")
    sub = p.add_subparsers(dest="command", required=True, parser_class=_Parser)
    v = sub.add_parser("verify", help="check evidence bundles against the chain")
    v.add_argument("--bundles", nargs="+", required=True, metavar="FILE", help="evidence bundle files (from `python -m witness export`)")
    v.add_argument("--chain-helper", help="path to the chain helper (chain/cli.js)")
    v.add_argument("--deployment-file", help="the chain deployment file written by setup-local")
    v.add_argument("--node", default="node", help="the node program (default: node)")
    v.add_argument("--json", action="store_true", help="print the whole report as JSON")
    v.add_argument("--finding", metavar="F-0042", help="print only this finding (ids are stable for the same inputs)")
    v.add_argument("--explain", action="store_true", help="add a plain-words reason to each finding")
    v.add_argument("--all", action="store_true", help="also list the MATCH findings")
    args = p.parse_args(argv)

    if reader is None:
        if not args.chain_helper:
            p.error("--chain-helper is required (the verifier needs the chain to get the public keys)")
        reader = HelperChainReader(args.chain_helper, deployment_file=args.deployment_file, node=args.node)

    report = verify(args.bundles, reader)

    if args.finding:
        f = report.find(args.finding)
        if f is None:
            print("error: no finding %s in this report (it has %d findings)" % (args.finding, len(report.findings)), file=sys.stderr)
            return USAGE_ERROR
        if args.json:
            print(json.dumps(f.to_dict(), indent=2, sort_keys=True))
        else:
            print(finding_report(f, explain=args.explain))
        return {"MATCH": 0, "MISMATCH": 1, "CANNOT VERIFY": 2}[f.result]
    if args.json:
        print(json_report(report))
    else:
        print(human_report(report, explain=args.explain, show_all=args.all))
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
