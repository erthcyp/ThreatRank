#!/usr/bin/env python3
"""The same question for the likelihood surrogate: does the feed train it better?

Training the impact classifier on the scanner's plugin corpus beat training it on our own scan
results, on every field. The likelihood surrogate has the identical complaint in the identical
words -- leave-one-family-out at 0.482, which is the severity baseline -- so the same remedy is
worth the same test rather than the assumption that it carries over.

Two things differ from the impact case and either could change the answer.

**The target is EPSS, not a CVSS field.** EPSS is published per CVE for a far smaller set than
NVD covers, so a feed check citing a CVE with no EPSS score supplies no training row at all.
How many survive is the first thing this prints.

**The target is continuous.** The impact classifier predicts one of three labels and is graded
on macro-F1; this predicts `log10(EPSS)` and is graded on Spearman, which is far less forgiving
of a model that has learned the general shape but not the order within it.

Leakage is handled as before: a feed check whose OID or name matches a finding in the test set
is removed before training, and the count removed is printed, since a silent zero would mean
the filter is broken rather than that the corpora do not overlap.

    python3 feed_likelihood.py --cap 20000
"""

import argparse
import csv
import glob
import json
import os
import sys

import gzip
import numpy as np
from scipy.stats import spearmanr
from sklearn.model_selection import GroupKFold, LeaveOneGroupOut, cross_val_predict

import likelihood as L

HERE = os.path.dirname(os.path.abspath(__file__))


def read(pattern):
    rows, seen = [], set()
    paths = [p for part in pattern.split(",") for p in sorted(glob.glob(os.path.join(HERE, part)))]
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("threat") == "Log":
                    continue
                key = (r.get("host", ""), r["nvt_name"])
                if key in seen:
                    continue
                seen.add(key)
                rows.append(r)
    return rows


def full_epss():
    """Every score in the pinned snapshot, not only the corpus's own CVEs.

    `epss_lookup.csv` is deliberately filtered: it holds the 1,135 CVEs our findings cite, and
    that is the right file for scoring a scan. It is the wrong file for training on a check
    corpus, because a feed check citing any other CVE then supplies no row. Filtering it cost
    this experiment most of its training data -- 503 usable rows out of 20,000 checks -- and
    the snapshot on disk has 369,024.

    The same pinned file, so the provenance line printed here is the provenance of every EPSS
    number anywhere in this project.
    """
    path = L.os.path.join(HERE, "epss_scores-2026-09-08.csv.gz") \
        if hasattr(L, "os") else os.path.join(HERE, "epss_scores-2026-09-08.csv.gz")
    matches = sorted(glob.glob(os.path.join(HERE, "epss_scores-*.csv.gz")))
    if not matches:
        sys.exit("no epss_scores-YYYY-MM-DD.csv.gz in data/.")
    path = matches[-1]
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        provenance = fh.readline().strip()
        reader = csv.DictReader(fh)
        scores = {r["cve"]: float(r["epss"]) for r in reader}
    print(f"EPSS snapshot     : {os.path.basename(path)}")
    print(f"  {provenance.lstrip('#')}")
    print(f"  {len(scores)} CVEs, against {len(L.epss_lookup())} in the filtered lookup")
    return scores


def targeted(rows, epss):
    out = []
    for r in rows:
        y, c = L.target_for(r, epss)
        if y is not None:
            out.append((r, y, c))
    return out


def rho(y, pred):
    r = spearmanr(y, pred).statistic
    return 0.0 if np.isnan(r) else r


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--feed", default="processed/nvt_corpus.csv", metavar="CSV")
    # Named explicitly for the reason given in transfer.py: a findings_*2.csv glob also matches
    # the later Qualys scan, which is not a training input.
    ap.add_argument("--scans", default="processed/findings_openvas_[ab]2.csv,processed/findings_nessus_[ab]2.csv",
                    metavar="GLOB[,GLOB]")
    ap.add_argument("--cap", type=int, default=20000, metavar="N")
    ap.add_argument("-o", "--out", metavar="JSON",
                    default=os.path.join(HERE, "figures", "feed_likelihood.json"))
    args = ap.parse_args()

    epss = full_epss()
    scans = targeted(read(args.scans), epss)
    feed_rows = read(args.feed)
    if args.cap and len(feed_rows) > args.cap:
        rng = np.random.default_rng(0)
        feed_rows = [feed_rows[i] for i in
                     rng.choice(len(feed_rows), args.cap, replace=False)]
    feed = targeted(feed_rows, epss)

    test_oids = {r.get("nvt_oid", "") for r, _, _ in scans if r.get("nvt_oid")}
    test_names = {r["nvt_name"] for r, _, _ in scans}
    kept = [(r, y, c) for r, y, c in feed
            if r.get("nvt_oid", "") not in test_oids and r["nvt_name"] not in test_names]
    removed = len(feed) - len(kept)

    print(f"\nscan findings with a target : {len(scans)}")
    print(f"feed checks sampled         : {len(feed_rows)}")
    print(f"  of those, with a target   : {len(feed)}")
    print(f"  removed as seen in scans  : {removed}")
    if removed == 0:
        print("  WARNING: nothing removed. Check the filter before believing anything below.")
    print(f"  left for training         : {len(kept)}")
    fam_scan = {r.get("nvt_family", "") for r, _, _ in scans}
    fam_feed = {r.get("nvt_family", "") for r, _, _ in kept}
    print(f"  families, scans {len(fam_scan)} against feed {len(fam_feed)}\n")
    if len(kept) < 200:
        sys.exit("too few feed checks carry an EPSS score to train on. EPSS covers far less "
                 "than NVD does, and that is the answer to this experiment rather than a "
                 "failure of it.")

    Xs = L.build_matrix([r for r, _, _ in scans])
    ys = np.log10(np.maximum(np.array([y for _, y, _ in scans]), L.FLOOR))
    gs = np.array([c for _, _, c in scans])
    fam = np.array([(r.get("nvt_family") or "") for r, _, _ in scans])
    Xf = L.build_matrix([r for r, _, _ in kept])
    yf = np.log10(np.maximum(np.array([y for _, y, _ in kept]), L.FLOOR))
    folds = min(5, len(set(gs)))

    own = rho(ys, cross_val_predict(L.model(), Xs, ys, groups=gs,
                                    cv=GroupKFold(n_splits=folds)))
    from_feed = rho(ys, L.model().fit(Xf, yf).predict(Xs))
    severity = rho(ys, np.array([float(r.get("severity") or 0) for r, _, _ in scans]))

    # The figure this experiment exists for. Leave-one-family-out on the scan corpus is where
    # the surrogate falls to the severity baseline; trained on a corpus with four times the
    # families, the same held-out families are no longer unseen.
    own_lofo = rho(ys, cross_val_predict(L.model(), Xs, ys, groups=fam,
                                         cv=LeaveOneGroupOut()))

    results = {"scan_only": round(float(own), 4),
               "feed_only": round(float(from_feed), 4),
               "scan_only_leave_one_family_out": round(float(own_lofo), 4),
               "severity_baseline": round(float(severity), 4),
               "feed_rows": len(kept), "scan_rows": len(scans),
               "feed_families": len(fam_feed), "scan_families": len(fam_scan)}

    print(f"  {'training set':34s} {'Spearman':>9}")
    print("  " + "-" * 46)
    print(f"  {'scan only, CVE-grouped split':34s} {own:8.3f}")
    print(f"  {'scan only, leave-one-family-out':34s} {own_lofo:8.3f}")
    print(f"  {'feed only, tested on the scans':34s} {from_feed:8.3f}")
    print(f"  {'severity alone':34s} {severity:8.3f}")

    print()
    if from_feed > own + 0.02:
        print("  The feed trains a better surrogate, as it did the impact classifier.")
    elif from_feed > own_lofo + 0.02:
        print("  The feed does not beat the in-corpus number, but it does beat the")
        print("  leave-one-family-out number, which is the one that measures the weakness")
        print("  this experiment was run to address. That is the useful reading.")
    elif from_feed > severity + 0.02:
        print("  The feed-trained model beats severity but not the scan-trained one. More")
        print("  data about a wider population does not help this target as it helped the")
        print("  other; the difference between the two is worth reporting.")
    else:
        print("  The feed does not train a usable surrogate at all. EPSS coverage of the")
        print("  feed's CVEs is the first thing to check before reading this as a result")
        print("  about the method.")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump(results, open(args.out, "w", encoding="utf-8"), indent=1)
    print(f"\n  wrote {args.out}")


if __name__ == "__main__":
    main()
