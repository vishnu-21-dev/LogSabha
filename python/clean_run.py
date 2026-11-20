"""A clean run against the QuickPay app: login, a few queries, one export to a normal
destination, and a nightly-backup export. Everything goes through the app. Nothing here is an attack.

  python clean_run.py --app-url <QuickPay URL> --username analyst --password <fake demo password> \\
      --export-url <normal destination URL> --backup-url <nightly backup destination URL>
"""
import argparse
import json
import sys

import requests


def run(app_url, username, password, export_url, backup_url, export_bytes=150_000, backup_bytes=400_000, queries=3):
    """Returns a list of {step, request_id, status, ...} for what was done."""
    s = requests.Session()
    s.trust_env = False
    done = []

    r = s.post(app_url + "/login", json={"username": username, "password": password}, timeout=10)
    r.raise_for_status()
    auth = {"Authorization": "Bearer " + r.json()["token"]}
    done.append({"step": "login", "request_id": r.headers["X-Request-ID"], "status": r.status_code})

    for i in range(queries):
        r = s.get(app_url + "/customers", params={"limit": 5 + i * 5}, headers=auth, timeout=10)
        r.raise_for_status()
        done.append({"step": "query", "request_id": r.headers["X-Request-ID"], "status": r.status_code,
                     "rows": len(r.json()["customers"])})

    for step, url, size, purpose in (("export", export_url, export_bytes, "partner-report"),
                                     ("nightly-backup", backup_url, backup_bytes, "nightly-backup")):
        r = s.post(app_url + "/export", json={"destination_url": url, "bytes": size, "purpose": purpose},
                   headers=auth, timeout=120)
        r.raise_for_status()
        done.append({"step": step, "request_id": r.headers["X-Request-ID"], "status": r.status_code,
                     "bytes": r.json()["bytes"], "destination": r.json()["destination"]})
    return done


def main(argv=None):
    p = argparse.ArgumentParser(description="QuickPay clean run")
    p.add_argument("--app-url", required=True)
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True, help="the FAKE demo password")
    p.add_argument("--export-url", required=True)
    p.add_argument("--backup-url", required=True)
    p.add_argument("--export-bytes", type=int, default=150_000)
    p.add_argument("--backup-bytes", type=int, default=400_000)
    args = p.parse_args(argv)
    print(json.dumps(run(args.app_url, args.username, args.password, args.export_url, args.backup_url,
                         args.export_bytes, args.backup_bytes), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
