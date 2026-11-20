"""Start, stop or inspect the demo.

  python -m launcher start  --config demo.config.json     (stays in the foreground; Ctrl+C or `stop` ends it)
  python -m launcher stop   --config demo.config.json     (asks a running `start` to shut everything down cleanly)
  python -m launcher status --config demo.config.json
"""
import argparse
import sys
import time

import requests

from . import BANNER, Stack, load_config


def main(argv=None):
    p = argparse.ArgumentParser(prog="launcher")
    p.add_argument("command", choices=("start", "stop", "status", "export"))
    p.add_argument("--config", required=True, help="JSON config file with every address and port")
    p.add_argument("--out-dir", help="export: folder for the three evidence bundles")
    args = p.parse_args(argv)
    stack = Stack(load_config(args.config))

    if args.command == "stop":
        stack.run_dir.mkdir(parents=True, exist_ok=True)
        stack.stack_stop_file.write_text("stop")
        print("stop requested; the running `start` will shut everything down cleanly")
        return 0

    if args.command == "export":
        if not args.out_dir:
            p.error("export needs --out-dir")
        paths = stack.export_bundles(args.out_dir, flush=True)      # flush all running witnesses, then export
        for name, path in paths.items():
            print("%-8s %s" % (name, path))
        return 0

    if args.command == "status":
        targets = {"app witness": stack.witness_url("app") + "/status", "network witness": stack.witness_url("network") + "/status",
                   "outside witness": stack.witness_url("outside") + "/status", "demo app": stack.app_url + "/status",
                   "gateway": stack.gateway_url + "/status"}
        for name, url in targets.items():
            try:
                print("%-16s %-32s up" % (name, url) if requests.get(url, timeout=1).ok else "%-16s %s error" % (name, url))
            except requests.RequestException:
                print("%-16s %-32s DOWN" % (name, url))
        return 0

    print(BANNER)
    stack.start()
    print("everything is up:")
    for label, url in (("QuickPay app", stack.app_url), ("gateway (proxy)", stack.gateway_url),
                       ("outside server", stack.outside_url), ("app witness", stack.witness_url("app")),
                       ("network witness", stack.witness_url("network")), ("outside witness", stack.witness_url("outside"))):
        print("  %-16s %s" % (label, url))
    print("logs and data: %s" % stack.data)
    print("stop with Ctrl+C, or run: python -m launcher stop --config %s" % args.config)
    try:
        while not stack.stack_stop_file.exists():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    print("stopping ...")
    print(stack.stop())
    return 0


if __name__ == "__main__":
    sys.exit(main())
