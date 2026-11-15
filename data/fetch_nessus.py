#!/usr/bin/env python3
"""
ThreatRank - pull Nessus scan results through the local REST API

Nessus Essentials disables file export, but the data itself stays reachable: the
web UI renders it by calling the same REST API this script uses, with the same
credentials. Nothing here bypasses a licence check - it reads the user's own scan
results from their own scanner over the documented interface.

Output uses the CSV schema shared with parse_openvas.py and parse_nessus.py, so
compare_scanners.py works on it unchanged.

The password is read interactively and never stored, logged, or passed on the
command line.

Examples:
    python3 fetch_nessus.py --list
    python3 fetch_nessus.py --scan-name test-activemq-nessus --group A
    python3 fetch_nessus.py --scan-id 7 --group A --out processed/findings_nessus.csv
"""

import argparse
import csv
import datetime
import getpass
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

from parse_openvas import CSV_FIELDS, load_kev, one_line


def normalise_port(raw):
    """Nessus's `80 / tcp / www` into the `80/tcp` the rest of the schema uses.

    The API returns a display string carrying the service name as well as the port and the
    protocol. Writing it through unchanged made every Nessus row unmatchable against every
    OpenVAS row: measured on nine hosts scanned by both tools, 47 CVEs were shared and the
    count of shared (host, port, product) keys was **zero**, which reads as two tools that
    agree about nothing and is entirely an artefact of this field.

    Port 0 means the finding is not tied to a listening port, which OpenVAS writes as
    `general/<protocol>`, so that is what it becomes here.
    """
    parts = [p.strip() for p in str(raw or "").split("/")]
    number = parts[0] if parts else ""
    protocol = parts[1] if len(parts) > 1 and parts[1] else "tcp"
    if not number or not number.isdigit():
        return ""
    return f"general/{protocol}" if number == "0" else f"{number}/{protocol}"

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = "https://127.0.0.1:8834"

# Nessus severity integer -> the threat vocabulary used by the OpenVAS parser.
SEVERITY_MAP = {0: "Log", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Nessus uses a self-signed certificate on loopback; verification would only fail.
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def api(path, token=None, data=None):
    """Call the Nessus API and return the decoded JSON body."""
    url = BASE + path
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method="POST" if body else "GET")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("X-Cookie", f"token={token}")
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:200]
        sys.exit(f"API error {exc.code} on {path}: {detail}")


def login():
    user = os.environ.get("NESSUS_USER") or input("Nessus username: ")
    pw = os.environ.get("NESSUS_PASS") or getpass.getpass("Nessus password: ")
    tok = api("/session", data={"username": user, "password": pw}).get("token")
    if not tok:
        sys.exit("login failed")
    return tok


def logout(token):
    try:
        req = urllib.request.Request(BASE + "/session", method="DELETE")
        req.add_header("X-Cookie", f"token={token}")
        urllib.request.urlopen(req, context=CTX, timeout=30)
    except Exception:                                           # noqa: BLE001
        pass


def build_rows(scan, host_details, plugin_details, group, kev, max_cves):
    """Turn one scan's API responses into CSV rows.

    Shared by the live API path and the replay path, so a CSV rebuilt from the
    archive is identical to the one produced at fetch time.
    """
    scan_name = scan.get("info", {}).get("name", "unknown")
    rows = []

    for host in scan.get("hosts", []):
        hid = str(host["host_id"])
        host_ip = host.get("hostname", "")
        detail = host_details.get(hid, {})
        hostname = detail.get("info", {}).get("host-fqdn", "") or ""

        for vuln in detail.get("vulnerabilities", []):
            pid = vuln["plugin_id"]
            pd = plugin_details.get(f"{hid}:{pid}", {})
            attrs = {}
            for block in pd.get("info", {}).get("plugindescription", {}) \
                           .get("pluginattributes", {}).items():
                attrs[block[0]] = block[1]

            refs = attrs.get("ref_information", {}).get("ref", [])
            cves, cert_refs = [], 0
            for r in refs if isinstance(refs, list) else [refs]:
                name = (r.get("name") or "").lower()
                values = r.get("values", {}).get("value", [])
                values = values if isinstance(values, list) else [values]
                if name == "cve":
                    cves.extend(v for v in values if v)
                elif name in ("cert", "cert-bund", "dfn-cert", "iava", "iavb"):
                    cert_refs += len(values)

            risk = attrs.get("risk_information", {})
            cvss = (risk.get("cvss3_base_score")
                    or risk.get("cvss_base_score") or "0.0")

            kev_hits = sorted(c for c in cves if c in kev)
            sev = vuln.get("severity", 0)
            ports = pd.get("outputs", [{}])
            port = ""
            for o in ports:
                for pnum in (o.get("ports") or {}):
                    port = normalise_port(pnum)
                    break
                if port:
                    break

            rows.append({
                "source_file": f"nessus-api:{scan_name}",
                "group": group,
                "scanner": "nessus",
                "host": host_ip,
                "hostname": hostname,
                "port": port,
                "nvt_oid": str(pid),
                "nvt_name": vuln.get("plugin_name", ""),
                "nvt_family": vuln.get("plugin_family", ""),
                "threat": SEVERITY_MAP.get(sev, "Log"),
                "severity": str(cvss),
                "qod": "",            # Nessus exposes no QoD equivalent
                "solution_type": "",
                "cve_count": len(cves),
                "cves": ";".join(cves),
                "has_cve": bool(cves),
                "generic_nvt": len(cves) > max_cves,
                "kev_cves": ";".join(kev_hits),
                "has_kev": bool(kev_hits),
                "cert_ref_count": cert_refs,
                # The write-up, for the same reason the OpenVAS parser carries it: the
                # title names a product and a version range and the description says what
                # the weakness allows. Nessus splits it into a synopsis and a longer
                # description, and the synopsis is the sentence that names the impact.
                "description": one_line(" ".join(
                    t for t in (attrs.get("synopsis"), attrs.get("description")) if t)),
                "solution": one_line(attrs.get("solution") or ""),
            })
    return rows


def collect(token, scan_id, group, kev, max_cves, raw_path=None):
    """Fetch one scan from the API, archive the raw responses, and build rows.

    The archive matters because the API is the only way to get this data out of
    Essentials: without a stored copy, fixing a parser bug would mean rescanning,
    and a rescan is a different observation rather than a reproduction.
    """
    scan = api(f"/scans/{scan_id}", token)
    host_details, plugin_details = {}, {}

    for host in scan.get("hosts", []):
        hid = str(host["host_id"])
        detail = api(f"/scans/{scan_id}/hosts/{hid}", token)
        host_details[hid] = detail
        for vuln in detail.get("vulnerabilities", []):
            pid = vuln["plugin_id"]
            plugin_details[f"{hid}:{pid}"] = api(
                f"/scans/{scan_id}/hosts/{hid}/plugins/{pid}", token)

    if raw_path:
        os.makedirs(os.path.dirname(raw_path), exist_ok=True)
        with open(raw_path, "w", encoding="utf-8") as fh:
            json.dump({"scan": scan, "hosts": host_details,
                       "plugins": plugin_details}, fh, indent=2, ensure_ascii=False)
        print(f"raw API responses saved: {raw_path}")

    return build_rows(scan, host_details, plugin_details, group, kev, max_cves)


def collect_from_raw(path, group, kev, max_cves):
    """Rebuild rows from an archived raw response file, without touching the API."""
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    return build_rows(raw["scan"], raw.get("hosts", {}), raw.get("plugins", {}),
                      group, kev, max_cves)


def main():
    ap = argparse.ArgumentParser(description="Pull Nessus results via the local API")
    ap.add_argument("--list", action="store_true", help="list scans and exit")
    ap.add_argument("--scan-id", type=int)
    ap.add_argument("--scan-name")
    ap.add_argument("--group", default="unknown", help="A or B, for the bias comparison")
    ap.add_argument("--max-cves", type=int, default=3)
    ap.add_argument("-o", "--out", required=True,
                    help="output CSV. Required, and name the host or group in it "
                         "(e.g. processed/findings_nessus_a.csv). A shared generic "
                         "default once let one scan silently overwrite another: "
                         "see Defect A in scans.md")
    ap.add_argument("--raw", default="auto",
                    help="where to archive the raw API responses; "
                         "'auto' names it from the date and scan, 'none' disables")
    ap.add_argument("--from-raw", metavar="FILE",
                    help="rebuild the CSV from an archived raw response file "
                         "instead of querying the scanner; needs no credentials")
    ap.add_argument("--offline", action="store_true", help="use the cached KEV catalog")
    args = ap.parse_args()

    # Replay path: no login, no network, works from the archive alone.
    if args.from_raw:
        kev = load_kev(offline=args.offline)
        rows = collect_from_raw(args.from_raw, args.group, kev, args.max_cves)
        print(f"rebuilt {len(rows)} findings from {os.path.basename(args.from_raw)}")
        out = args.out if os.path.isabs(args.out) else os.path.join(HERE, args.out)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
            w.writeheader()
            w.writerows(rows)
        print(f"CSV written: {out}")
        return

    token = login()
    try:
        if args.list or not (args.scan_id or args.scan_name):
            scans = api("/scans", token).get("scans") or []
            if not scans:
                print("no scans found")
                return
            print(f"{'id':>5}  {'status':<12}  name")
            for s in scans:
                print(f"{s['id']:>5}  {s.get('status', ''):<12}  {s.get('name', '')}")
            if args.list:
                return
            print("\nchoose one with --scan-id or --scan-name")
            return

        scan_id = args.scan_id
        if scan_id is None:
            scans = api("/scans", token).get("scans") or []
            match = [s for s in scans if s.get("name") == args.scan_name]
            if not match:
                sys.exit(f"no scan named {args.scan_name!r}")
            scan_id = match[0]["id"]

        kev = load_kev(offline=args.offline)

        raw_path = None
        if args.raw != "none":
            if args.raw == "auto":
                info = api(f"/scans/{scan_id}", token).get("info", {})
                name = (info.get("name") or f"scan{scan_id}").replace(" ", "-")
                stamp = datetime.date.today().isoformat()
                raw_path = os.path.join(
                    HERE, "raw/nessus",
                    f"{stamp}_nessus_{args.group}_{name}.json")
            else:
                raw_path = args.raw if os.path.isabs(args.raw) \
                    else os.path.join(HERE, args.raw)

        rows = collect(token, scan_id, args.group, kev, args.max_cves, raw_path)
        print(f"collected {len(rows)} findings from scan {scan_id}")

        out = args.out
        if not os.path.isabs(out):
            out = os.path.join(os.path.dirname(os.path.abspath(__file__)), out)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
            w.writeheader()
            w.writerows(rows)
        print(f"CSV written: {out}")
    finally:
        logout(token)


if __name__ == "__main__":
    main()
