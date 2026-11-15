#!/usr/bin/env python3
"""
ThreatRank - OpenVAS/GVM XML report parser

Reads Greenbone report XML and emits a CSV plus the three numbers that gate the
project's design decisions:

  1. findings per host
  2. share of findings carrying a CVE ID
  3. share of findings touching the CISA KEV catalog

Every methodological choice is exposed as a flag rather than hard-coded, so the
report can state "under choice A the number is X, under choice B it is Y".
These choices matter: on a single ActiveMQ scan, CVE coverage ranged from 13.6%
to 62.5% depending only on which options were applied.

Standard library only - no dependencies to install.

Examples:
    python3 parse_openvas.py "raw/openvas/*.xml"
    python3 parse_openvas.py "raw/openvas/*.xml" --exclude-log --drop-generic-cves
    python3 parse_openvas.py "raw/openvas/*.xml" --compare
"""

import argparse
import csv
import glob
import json
import os
import sys
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
KEV_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kev_catalog.json")

CSV_FIELDS = [
    "source_file", "group", "scanner", "host", "hostname", "port",
    "nvt_oid", "nvt_name", "nvt_family", "threat", "severity", "qod",
    "solution_type", "cve_count", "cves", "has_cve", "generic_nvt",
    "kev_cves", "has_kev", "cert_ref_count",
    # Added 29 September 2026. The schema carried only the check title, so every model
    # built on it was reading a product name and a version range and could not tell a
    # denial of service from a privilege escalation. `description` is the NVT's own
    # summary, impact and insight, which say what the weakness allows; see nvt_text() for
    # why it is not the result's `<description>`. `solution` is carried because it is what
    # fix actions are grouped by.
    "description", "solution",
]


def one_line(value):
    """Collapse a multi-line scanner paragraph into one CSV-safe line."""
    return " ".join((value or "").split())


# Greenbone packs the whole NVT write-up into one pipe-separated string rather than into
# elements: `cvss_base_vector=...|summary=...|insight=...|impact=...|affected=...`.
TAG_WANTED = ("summary", "impact", "insight")


def nvt_text(nvt):
    """The parts of an NVT's write-up that say what the weakness allows.

    Not the result's own `<description>`, which is detection evidence: for a version check
    it reads "Installed version: 2.4.10 Fixed version: 2.4.49" and for a timestamp check it
    reads the packet counters. Feeding that to a model adds version numbers and port
    numbers and no meaning, and measured on 29 September it cost seven points of macro-F1.

    These fields say the thing the model needs. For TCP timestamps the impact is "the
    uptime of the remote host can sometimes be computed"; for Apache 2.4.49 the insight
    lists a null pointer dereference, a buffer overflow and an SSRF. A title cannot
    separate those two and this text can.
    """
    tags = text_of(nvt, "tags")
    if not tags:
        return ""
    out = []
    for part in tags.split("|"):
        key, _, value = part.partition("=")
        if key.strip() in TAG_WANTED and value.strip():
            out.append(value)
    return one_line(" ".join(out))


# ---------------------------------------------------------------- KEV catalog

def load_kev(offline=False):
    """Return the set of CVE IDs in the CISA KEV catalog.

    Cached to disk so a given analysis run stays reproducible even if CISA
    publishes an update mid-project.
    """
    if os.path.exists(KEV_CACHE):
        with open(KEV_CACHE, encoding="utf-8") as fh:
            data = json.load(fh)
        cves = {v["cveID"] for v in data.get("vulnerabilities", [])}
        print(f"  KEV: loaded {len(cves)} CVEs from cache "
              f"(catalogVersion={data.get('catalogVersion', '?')})")
        return cves

    if offline:
        print("  KEV: no cache and --offline given -> skipping KEV lookup")
        return set()

    print("  KEV: downloading from CISA ...")
    try:
        with urllib.request.urlopen(KEV_URL, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
    except Exception as exc:                                    # noqa: BLE001
        print(f"  KEV: download failed ({exc}) -> skipping KEV lookup")
        return set()

    with open(KEV_CACHE, "w", encoding="utf-8") as fh:
        fh.write(raw)
    data = json.loads(raw)
    cves = {v["cveID"] for v in data.get("vulnerabilities", [])}
    print(f"  KEV: {len(cves)} CVEs (cached to {os.path.basename(KEV_CACHE)})")
    return cves


# ---------------------------------------------------------------- XML parsing

def infer_meta(path):
    """Derive scanner and group from the filename convention.

    Expected: YYYY-MM-DD_scanner_group_target.xml
    """
    base = os.path.basename(path)
    parts = base.replace(".xml", "").split("_")
    scanner = parts[1] if len(parts) > 1 else "unknown"
    group = parts[2] if len(parts) > 2 else "unknown"
    return group, scanner


def text_of(elem, path, default=""):
    node = elem.find(path)
    return (node.text or default).strip() if node is not None else default


def parse_report(path, kev_cves, max_cves):
    """Extract every finding from one report file as a list of dicts."""
    group, scanner = infer_meta(path)
    tree = ET.parse(path)
    root = tree.getroot()

    rows = []
    for res in root.iter("result"):
        # <host> holds the IP as text with <asset>/<hostname> as children,
        # so .text gives the IP on its own.
        host_el = res.find("host")
        if host_el is None:
            continue
        host = (host_el.text or "").strip()
        hostname = text_of(host_el, "hostname")

        nvt = res.find("nvt")
        if nvt is None:
            continue

        cves, cert_refs, has_kev_ref = [], 0, False
        refs = nvt.find("refs")
        if refs is not None:
            for ref in refs.findall("ref"):
                rtype = (ref.get("type") or "").lower()
                rid = ref.get("id") or ""
                if rtype == "cve":
                    cves.append(rid)
                elif rtype in ("cert-bund", "dfn-cert"):
                    cert_refs += 1
                elif rtype == "cisa":
                    has_kev_ref = True

        kev_hits = sorted(c for c in cves if c in kev_cves)
        sol = nvt.find("solution")

        rows.append({
            "source_file": os.path.basename(path),
            "group": group,
            "scanner": scanner,
            "host": host,
            "hostname": hostname,
            "port": text_of(res, "port"),
            "nvt_oid": nvt.get("oid", ""),
            "nvt_name": text_of(nvt, "name"),
            "nvt_family": text_of(nvt, "family"),
            "threat": text_of(res, "threat"),
            "severity": text_of(res, "severity", "0.0"),
            "qod": text_of(res, "qod/value", "0"),
            "solution_type": (sol.get("type", "") if sol is not None else ""),
            "cve_count": len(cves),
            "cves": ";".join(cves),
            "has_cve": bool(cves),
            # An NVT carrying an unusually large CVE list is a generic check
            # (e.g. "default credentials"), not a host-specific vulnerability.
            # Observed: one such NVT listed 14 CVEs from unrelated vendors.
            "generic_nvt": len(cves) > max_cves,
            "kev_cves": ";".join(kev_hits),
            "has_kev": bool(kev_hits),
            "cert_ref_count": cert_refs,
            "description": nvt_text(nvt),
            "solution": one_line(sol.text if sol is not None else ""),
        })
    return rows


# ---------------------------------------------------------------- methodology

def apply_policy(rows, exclude_log, min_qod, drop_generic_cves):
    """Apply the methodological choices to the raw findings.

    Each option changes the resulting numbers, so whichever combination is used
    must be stated in the report.
    """
    out = []
    for r in rows:
        if exclude_log and r["threat"] == "Log":
            continue
        try:
            if float(r["qod"]) < min_qod:
                continue
        except ValueError:
            pass

        r = dict(r)
        if drop_generic_cves and r["generic_nvt"]:
            # Generic NVTs attach CVEs unrelated to this host. Left in place
            # they mislabel the host as KEV-positive.
            r["cves"] = ""
            r["cve_count"] = 0
            r["has_cve"] = False
            r["kev_cves"] = ""
            r["has_kev"] = False
        out.append(r)
    return out


def summarise(rows, label=""):
    """Compute the three headline numbers plus supporting detail."""
    n = len(rows)
    hosts = {r["host"] for r in rows}
    if n == 0:
        return {"label": label, "findings": 0, "hosts": 0}

    with_cve = sum(1 for r in rows if r["has_cve"])
    with_kev = sum(1 for r in rows if r["has_kev"])
    generic = sum(1 for r in rows if r["generic_nvt"])
    threats = Counter(r["threat"] for r in rows)
    return {
        "label": label,
        "findings": n,
        "hosts": len(hosts),
        "per_host": n / len(hosts),
        "with_cve": with_cve,
        "pct_cve": 100 * with_cve / n,
        "with_kev": with_kev,
        "pct_kev": 100 * with_kev / n,
        "generic": generic,
        "threats": threats,
    }


def print_summary(s):
    if s["findings"] == 0:
        print(f"\n[{s['label']}] no findings left after filtering")
        return
    t = s["threats"]
    print(f"\n[{s['label']}]")
    print(f"  hosts               : {s['hosts']}")
    print(f"  findings            : {s['findings']}  ({s['per_host']:.1f} per host)")
    print(f"  with CVE ID         : {s['with_cve']:>4}  ({s['pct_cve']:.1f}%)")
    print(f"  touching CISA KEV   : {s['with_kev']:>4}  ({s['pct_kev']:.1f}%)")
    print(f"  generic NVTs        : {s['generic']:>4}  (oversized CVE lists)")
    print("  severity            : " + "  ".join(
        f"{k}={t[k]}" for k in ("Critical", "High", "Medium", "Low", "Log") if t[k]))


# ---------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description="Convert OpenVAS XML reports to CSV and report the gating numbers",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="XML report files (globs accepted)")
    ap.add_argument("-o", "--out", default="processed/findings.csv",
                    help="CSV output path (default: processed/findings.csv)")
    ap.add_argument("--exclude-log", action="store_true",
                    help="drop Log-level findings (about half of a typical report)")
    ap.add_argument("--min-qod", type=float, default=0,
                    help="drop findings below this QoD (GVM's own default is 70)")
    ap.add_argument("--max-cves", type=int, default=3,
                    help="more than N CVEs on one finding marks a generic NVT (default: 3)")
    ap.add_argument("--drop-generic-cves", action="store_true",
                    help="ignore CVEs from generic NVTs, preventing false KEV labels")
    ap.add_argument("--compare", action="store_true",
                    help="show the numbers under every option combination")
    ap.add_argument("--offline", action="store_true",
                    help="do not fetch the KEV catalog; use cache only")
    args = ap.parse_args()

    paths = sorted({p for pat in args.files for p in glob.glob(pat)})
    if not paths:
        sys.exit("no files matched")

    print(f"{len(paths)} file(s) found")
    kev = load_kev(offline=args.offline)

    raw = []
    for p in paths:
        found = parse_report(p, kev, args.max_cves)
        print(f"  {os.path.basename(p)}: {len(found)} findings")
        raw.extend(found)

    if args.compare:
        # Show how much each methodological choice moves the numbers.
        print("\n" + "=" * 62)
        print("Sensitivity to methodological choices")
        print("=" * 62)
        combos = [
            ("raw, no filtering", dict(exclude_log=False, min_qod=0, drop_generic_cves=False)),
            ("exclude Log", dict(exclude_log=True, min_qod=0, drop_generic_cves=False)),
            ("QoD>=70 (GVM default)", dict(exclude_log=False, min_qod=70, drop_generic_cves=False)),
            ("drop generic-NVT CVEs", dict(exclude_log=False, min_qod=0, drop_generic_cves=True)),
            ("exclude Log + drop generic", dict(exclude_log=True, min_qod=0, drop_generic_cves=True)),
        ]
        for label, kw in combos:
            print_summary(summarise(apply_policy(raw, **kw), label))
        print("\nThe numbers move with the choices, so the report must state which was used.")

    rows = apply_policy(raw, args.exclude_log, args.min_qod, args.drop_generic_cves)
    policy = (f"exclude_log={args.exclude_log}, min_qod={args.min_qod}, "
              f"max_cves={args.max_cves}, drop_generic_cves={args.drop_generic_cves}")
    print("\n" + "=" * 62)
    print(f"Applied policy: {policy}")
    print("=" * 62)
    print_summary(summarise(rows, "result"))

    # Split by group: the A-vs-B gap is the evidence for selection bias.
    groups = sorted({r["group"] for r in rows})
    if len(groups) > 1:
        print("\n--- by group ---")
        for g in groups:
            print_summary(summarise([r for r in rows if r["group"] == g], f"group {g}"))

    out = args.out
    if not os.path.isabs(out):
        out = os.path.join(os.path.dirname(os.path.abspath(__file__)), out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"\nCSV written: {out}  ({len(rows)} rows)")


if __name__ == "__main__":
    main()
