#!/usr/bin/env python3
"""VulnCheck KEV, as a second opinion on which vulnerabilities are being exploited.

CISA KEV is this project's registered label and stays that way. It is also thin: across the
three-tier lab it marks seven findings, and every ordering compared against it closes all
seven by a tenth of the budget, so the metric reports a tie where the methods differ. A
catalogue three times the size gives the same question more room to answer.

WHY THIS IS A SECOND LABEL AND NOT A REPLACEMENT

The label was fixed before any of these results existed. Swapping it now, after seeing that
the first one is thin, is how a result stops being publishable regardless of which
catalogue is better. CISA KEV is also what the surrounding literature uses, so dropping it
costs comparability. Every record here carries `cisa_date_added`, so one file supports both
readings: the registered label is the subset where that field is set, and the wider
catalogue is the whole of it.

WHAT THIS CANNOT FIX

Both catalogues are keyed on CVE identifiers, so neither can grade the findings that cite
none -- 35 of 410 in this corpus, and the population the likelihood surrogate exists for.
Both are also silent about what an organisation is defending: a finding on a host that
cannot reach the declared goal is still marked exploited, so both penalise a method for
correctly narrowing its scope. More rows do not change either of those.

ATTRIBUTION

VulnCheck asks for prominent attribution in return for free use, and the data is to be
labelled VulnCheck KEV wherever it appears. The CSV column is named `vulncheck_kev` and the
paper names the source in the text, not only in a citation.

    python3 fetch_vulncheck.py                 fetch and snapshot the catalogue
    python3 fetch_vulncheck.py --compare       and report it against CISA KEV on the corpus
"""

import argparse
import collections
import csv
import datetime
import glob
import json
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BACKUP_URL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
OUT = os.path.join(HERE, "vulncheck_kev.json")


def read_key():
    key = os.environ.get("VULNCHECK_API_KEY")
    if key:
        return key.strip()
    path = os.path.join(HERE, ".vulncheck_api_key")
    if os.path.exists(path):
        return open(path, encoding="utf-8").read().strip()
    return None


def fetch(key):
    """The backup endpoint hands over the whole catalogue, usually as a link to an archive.

    Paging the index would work too and would be slower and less reproducible: a snapshot is
    one file with one timestamp, and that is what a result has to be pinned to.
    """
    req = urllib.request.Request(BACKUP_URL, headers={
        "Accept": "application/json",
        "Authorization": f"Bearer {key}",
        "User-Agent": "ThreatRank/1.0"})
    with urllib.request.urlopen(req, timeout=90) as resp:
        return json.loads(resp.read().decode())


def download(url):
    req = urllib.request.Request(url, headers={"User-Agent": "ThreatRank/1.0"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        return resp.read()


def load_records(payload):
    """Unwrap whatever shape the backup arrives in, and say so if it is not recognised."""
    data = payload.get("data") if isinstance(payload, dict) else payload
    if isinstance(data, list) and data and isinstance(data[0], dict) and "url" in data[0]:
        blob = download(data[0]["url"])
        if blob[:2] == b"PK":
            import io
            import zipfile
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                name = next(n for n in z.namelist() if n.endswith(".json"))
                return json.loads(z.read(name).decode())
        return json.loads(blob.decode())
    return data


def corpus_cves():
    found = set()
    for path in glob.glob(os.path.join(HERE, "processed", "findings_*.csv")):
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("threat") == "Log":
                    continue
                for c in (r.get("cves") or "").split(";"):
                    c = c.strip()
                    if c.startswith("CVE-"):
                        found.add(c)
    return found


def compare(records):
    """How many of the corpus's CVEs each catalogue marks, and how much the second adds."""
    vc, cisa = set(), set()
    for rec in records:
        cves = rec.get("cve") or []
        cves = cves if isinstance(cves, list) else [cves]
        for c in cves:
            if not c:
                continue
            vc.add(c)
            if rec.get("cisa_date_added"):
                cisa.add(c)

    corpus = corpus_cves()
    print(f"\ncatalogue         : {len(vc)} CVEs, of which {len(cisa)} carry a CISA date")
    print(f"corpus            : {len(corpus)} distinct CVEs cited by the findings\n")
    print(f"  {'label':26s} {'in corpus':>9}")
    print("  " + "-" * 38)
    print(f"  {'CISA KEV, registered':26s} {len(corpus & cisa):9d}")
    print(f"  {'VulnCheck KEV':26s} {len(corpus & vc):9d}")
    print(f"  {'added by VulnCheck':26s} {len((corpus & vc) - cisa):9d}")

    extra = sorted((corpus & vc) - cisa)
    if extra:
        print(f"\n  marked exploited by VulnCheck and not by CISA:")
        for c in extra[:20]:
            rec = next((r for r in records
                        if c in (r.get("cve") if isinstance(r.get("cve"), list)
                                 else [r.get("cve")])), {})
            print(f"    {c:18s} {(rec.get('vendorProject') or '')[:18]:18s} "
                  f"{(rec.get('product') or '')[:24]:24s} added {(rec.get('date_added') or '')[:10]}")
        if len(extra) > 20:
            print(f"    ... and {len(extra) - 20} more")
    # The number that decides whether this is worth wiring into the pipeline. Going from
    # seven positives to a few more does not make a thin label thick.
    print(f"\n  the registered label marks {len(corpus & cisa)} of the corpus's CVEs; the "
          f"wider one marks {len(corpus & vc)}.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--compare", action="store_true",
                    help="report the two catalogues against the corpus")
    ap.add_argument("--offline", action="store_true",
                    help="use the existing snapshot and make no request")
    args = ap.parse_args()

    if args.offline or (os.path.exists(OUT) and not args.compare):
        pass

    if not args.offline:
        key = read_key()
        if not key:
            sys.exit("No VulnCheck token. Put it in data/.vulncheck_api_key or set "
                     "$VULNCHECK_API_KEY. It is never written into a script and the file "
                     "is git-ignored.")
        try:
            payload = fetch(key)
        except urllib.error.HTTPError as e:
            sys.exit(f"VulnCheck returned HTTP {e.code}. 401 means the token is wrong or "
                     f"expired; 403 means the account is not licensed for this index.")
        records = load_records(payload)
        meta = payload.get("_meta", {}) if isinstance(payload, dict) else {}
        stamp = meta.get("timestamp") or datetime.date.today().isoformat()
        json.dump({"_source": "VulnCheck KEV", "_timestamp": stamp,
                   "_fetched": datetime.datetime.now().isoformat(timespec="seconds"),
                   "records": records},
                  open(OUT, "w", encoding="utf-8"), indent=1)
        print(f"VulnCheck KEV     : {len(records)} records, snapshot {stamp}")
        print(f"wrote {OUT}")
    else:
        if not os.path.exists(OUT):
            sys.exit(f"{OUT} does not exist yet, so there is nothing to read offline.")
        blob = json.load(open(OUT, encoding="utf-8"))
        records = blob["records"]
        print(f"VulnCheck KEV     : {len(records)} records, snapshot {blob['_timestamp']}")

    if args.compare:
        compare(records)


if __name__ == "__main__":
    main()
