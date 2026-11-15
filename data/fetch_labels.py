#!/usr/bin/env python3
"""Pin the two external label sources the learned stages train on.

EPSS supplies the target for the exploit-likelihood surrogate. NVD supplies the CWE
that Classification learns to predict. Both are public catalogues that change daily,
so both are captured as dated snapshots and read from disk afterwards, exactly as
kev_catalog.json already is. A number produced from a live lookup cannot be
reproduced tomorrow, and this project has already had to withdraw one result for a
related reason.

Two outputs, both written to data/:

  epss_lookup.csv    cve,epss,percentile   for the CVEs this corpus actually cites
  cwe_map.json       cve -> {cwes, description, published, cvss, cpes}

Only the CVEs present in processed/findings_*.csv are fetched. Downloading all of
NVD would take hours and none of it would be used.

USAGE

  python3 fetch_labels.py --epss                     build epss_lookup.csv
  python3 fetch_labels.py --cwe                      build cwe_map.json
  python3 fetch_labels.py --epss --cwe               both

The NVD key is read from data/.nvd_api_key, or from $NVD_API_KEY. It is never
written into this file: the key is gitignored, and a key committed to a repository
is a key that has to be rotated.

Without a key NVD allows 5 requests per 30 seconds; with one, 50. The script honours
whichever applies and resumes from an existing cwe_map.json, so an interrupted run
costs only the requests it had not yet made.
"""

import argparse
import csv
import glob
import gzip
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="


def corpus_cves():
    """Every distinct CVE cited anywhere in the processed findings."""
    cves = set()
    for path in sorted(glob.glob(os.path.join(HERE, "processed", "findings_*.csv"))):
        with open(path, encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                for c in (row.get("cves") or "").split(";"):
                    c = c.strip()
                    if c.startswith("CVE-"):
                        cves.add(c)
    return sorted(cves)


def newest_epss_snapshot():
    files = sorted(glob.glob(os.path.join(HERE, "epss_scores-*.csv.gz")))
    if not files:
        sys.exit("no epss_scores-YYYY-MM-DD.csv.gz in data/. Download one from\n"
                 "  https://epss.empiricalsecurity.com/epss_scores-current.csv.gz\n"
                 "and keep the dated filename it redirects to.")
    return files[-1]


def build_epss(wanted):
    snapshot = newest_epss_snapshot()
    with gzip.open(snapshot, "rt", encoding="utf-8") as fh:
        provenance = fh.readline().strip()          # #model_version:...,score_date:...
        reader = csv.DictReader(fh)
        found = {r["cve"]: (r["epss"], r["percentile"])
                 for r in reader if r["cve"] in wanted}

    out = os.path.join(HERE, "epss_lookup.csv")
    with open(out, "w", newline="", encoding="utf-8") as fh:
        fh.write(f"# source: {os.path.basename(snapshot)}\n")
        fh.write(f"# {provenance.lstrip('#')}\n")
        w = csv.writer(fh)
        w.writerow(["cve", "epss", "percentile"])
        for cve in sorted(found):
            w.writerow([cve, *found[cve]])

    missing = sorted(set(wanted) - set(found))
    print(f"EPSS  snapshot   {os.path.basename(snapshot)}")
    print(f"      provenance {provenance.lstrip('#')}")
    print(f"      matched    {len(found)} of {len(wanted)} corpus CVEs")
    if missing:
        # Reserved or very recent CVEs legitimately have no score yet. Naming them
        # matters: they are the rows the surrogate will have to be evaluated without.
        print(f"      no score   {len(missing)}: {', '.join(missing[:6])}"
              f"{' ...' if len(missing) > 6 else ''}")
    print(f"      wrote      {out}")



def cvss_of(cve_obj):
    """The CVSS vector NVD publishes, preferring the newest version present.

    Only what NVD states is recorded. The attack vector and the impact metrics are what
    the attack graph's Range and Consequence are defined from, and taking them from a
    published vector rather than from a table we write ourselves is the difference between
    an external label and one the project invented for itself.
    """
    metrics = cve_obj.get("metrics", {})
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        d = entries[0].get("cvssData", {})
        return {
            "version": ver,
            "vector": d.get("vectorString", ""),
            "attackVector": d.get("attackVector") or d.get("accessVector", ""),
            "confidentiality": d.get("confidentialityImpact", ""),
            "integrity": d.get("integrityImpact", ""),
            "availability": d.get("availabilityImpact", ""),
            "baseScore": d.get("baseScore", ""),
        }
    return {}


def cpes_of(cve_obj):
    """The products NVD says the CVE affects, as `vendor:product` without versions.

    This is the vendor-neutral key the correlation stage needs. Actions are currently keyed
    on a product parsed out of the scanner's check title, and titles are prose: one OpenVAS
    product fragments into `php` and `php 5.x`, and across tools the same PHP flaw is titled
    so differently that matching on the parsed name found three shared products in 138.

    Both scanners cite the same CVE identifiers, so routing through NVD's own product list
    replaces our regex over someone else's sentence with a lookup neither vendor wrote.

    Versions are dropped deliberately. The remediation is an upgrade of one component, so
    `php:php` is the job; carrying `5.6.40` in the key would fragment it again by the very
    versions the upgrade removes.

    The part letter is kept. A CVE in Apache running on Debian lists the operating system
    alongside the application, and a first version of this function discarded that letter
    and picked whichever name was cited most often. It produced a remediation group called
    `debian:debian_linux` on port 80 holding 26 Apache findings -- a job nobody can do.
    Downstream prefers `a` over `o` and `h`, which needs the letter to survive the cache.
    """
    found = set()
    for node in cve_obj.get("configurations", []):
        for match in node.get("nodes", []):
            for m in match.get("cpeMatch", []):
                parts = (m.get("criteria") or "").split(":")
                # cpe:2.3:<part>:vendor:product:version:...
                if len(parts) > 5 and parts[2] and parts[3] and parts[4]:
                    found.add(f"{parts[2]}:{parts[3]}:{parts[4]}")
    return sorted(found)


def read_key():
    key = os.environ.get("NVD_API_KEY")
    if key:
        return key.strip()
    path = os.path.join(HERE, ".nvd_api_key")
    if os.path.exists(path):
        return open(path, encoding="utf-8").read().strip()
    return None


def build_cwe(wanted):
    out = os.path.join(HERE, "cwe_map.json")
    have = {}
    if os.path.exists(out):
        have = json.load(open(out, encoding="utf-8"))
        # An entry cached before CVSS capture was added lacks the key entirely, so it is
        # refetched rather than silently left without the field it is now expected to carry.
        # An entry cached before a field was added lacks its key, so it is refetched
        # rather than silently left without something the pipeline now expects.
        stale = [k for k, v in have.items()
                 if "cvss" not in v or "cpes" not in v
                 or any(c.count(":") != 2 for c in (v.get("cpes") or []))]
        print(f"CWE   resuming, {len(have)} cached, {len(stale)} predate a current field")
        for k in stale:
            del have[k]

    key = read_key()
    # NVD publishes these limits: 5 requests per rolling 30s without a key, 50 with.
    # Sleeping a little longer than the quota implies is cheaper than being throttled.
    delay = 0.7 if key else 6.5
    print(f"CWE   api key    {'yes' if key else 'no'}, {delay}s between requests")

    todo = [c for c in wanted if c not in have]
    if not todo:
        print("CWE   nothing to fetch")
        return
    eta = len(todo) * delay / 60
    print(f"CWE   to fetch   {len(todo)} CVEs, about {eta:.0f} min")

    for i, cve in enumerate(todo, 1):
        req = urllib.request.Request(NVD_URL + cve, headers={"User-Agent": "ThreatRank/1.0"})
        if key:
            req.add_header("apiKey", key)
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            # 403 and 503 are how NVD signals throttling. Back off and retry once.
            print(f"      {cve}: HTTP {e.code}, backing off 30s")
            time.sleep(30)
            try:
                with urllib.request.urlopen(req, timeout=45) as resp:
                    data = json.loads(resp.read().decode())
            except Exception as e2:
                print(f"      {cve}: giving up ({e2})")
                continue
        except Exception as e:
            print(f"      {cve}: {e}")
            continue

        items = data.get("vulnerabilities") or []
        if not items:
            have[cve] = {"cwes": [], "description": "", "published": "",
                         "cvss": {}, "cpes": [], "note": "not in NVD"}
        else:
            v = items[0]["cve"]
            cwes = [d["value"] for w in v.get("weaknesses", []) for d in w.get("description", [])
                    if d["value"].startswith("CWE-")]
            desc = next((d["value"] for d in v.get("descriptions", []) if d["lang"] == "en"), "")
            have[cve] = {"cwes": sorted(set(cwes)), "description": desc,
                         "published": v.get("published", ""), "cvss": cvss_of(v),
                         "cpes": cpes_of(v)}

        if i % 25 == 0 or i == len(todo):
            json.dump(have, open(out, "w", encoding="utf-8"), indent=1, sort_keys=True)
            print(f"      {i}/{len(todo)} fetched, saved")
        time.sleep(delay)

    json.dump(have, open(out, "w", encoding="utf-8"), indent=1, sort_keys=True)
    labelled = sum(1 for v in have.values() if v["cwes"])
    with_cvss = sum(1 for v in have.values() if v.get("cvss", {}).get("attackVector"))
    print(f"CWE   wrote      {out}")
    print(f"      {labelled} of {len(have)} CVEs carry at least one CWE; "
          f"{len(have) - labelled} carry none and cannot supply a training label")
    print(f"      {with_cvss} of {len(have)} carry a CVSS attack vector")
    with_cpe = sum(1 for v in have.values() if v.get("cpes"))
    print(f"      {with_cpe} of {len(have)} name at least one affected product; "
          f"{len(have) - with_cpe} name none and fall back to the scanner's title")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--epss", action="store_true", help="build epss_lookup.csv")
    ap.add_argument("--cwe", action="store_true", help="build cwe_map.json")
    args = ap.parse_args()
    if not (args.epss or args.cwe):
        ap.error("choose --epss, --cwe, or both")

    wanted = corpus_cves()
    print(f"corpus: {len(wanted)} distinct CVEs cited in processed/findings_*.csv\n")
    if args.epss:
        build_epss(wanted)
        print()
    if args.cwe:
        build_cwe(wanted)


if __name__ == "__main__":
    main()
