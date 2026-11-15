#!/usr/bin/env python3
"""Does training on the scanner's whole check corpus beat training on our own scan results?

The impact classifier learns from 375 findings drawn from eleven hosts running about nine
products. Its weakness is known and measured: against a check family it has never seen it
scores 0.482, which is the severity baseline. The scanner's plugin feed holds 80,555 checks
across 47 families, carrying the same kind of text and the same CVE references, so it is the
obvious place to look for the diversity the scan corpus lacks.

**More data is not assumed to help.** Two hypotheses have already failed this session by being
plausible -- a ranking objective, and within-host comparative features -- and this one has a
visible reason to fail too: 57% of the feed is distribution security advisories, Fedora and
Debian and SuSE package updates, which are a different kind of check from the remote service
tests that actually fire against our hosts. A corpus can be two hundred times larger and still
be about something else.

THE COMPARISON

The test set is always our own findings, because those are what the pipeline scores. Three
training sets, one evaluation:

    scan only     the 375 findings, cross-validated -- the current model
    feed only     80,555 checks, tested on the findings
    both          the feed plus the scan corpus

LEAKAGE, WHICH IS THE WHOLE RISK HERE

A finding in our corpus was produced by a check that is *in* the feed. Training on that check
and testing on the finding it produced is memorisation with extra steps. Feed rows are removed
by OID and by check name before training, and the count removed is printed, because a silent
zero there would mean the filter is not working.

    python3 feed_training.py --feed processed/nvt_corpus.csv
"""

import argparse
import collections
import csv
import glob
import json
import os
import sys

import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import GroupKFold, cross_val_predict

import impact as I
import likelihood as L

HERE = os.path.dirname(os.path.abspath(__file__))


def read(path_or_glob):
    rows, seen = [], set()
    for path in sorted(glob.glob(os.path.join(HERE, path_or_glob))):
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


def labelled(rows, nvd):
    out = []
    for r in rows:
        v, c = I.vector_for(r, nvd)
        # v2 vectors speak PARTIAL/COMPLETE where v3 speaks LOW/HIGH; mixing the two
        # vocabularies in one target produced a three-example class with an F1 of zero.
        if v is not None and v.get("version", "").startswith(("3", "4")):
            out.append((r, v, c))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--feed", default="processed/nvt_corpus.csv", metavar="CSV")
    ap.add_argument("--scans", default="processed/findings_*2.csv", metavar="GLOB")
    ap.add_argument("--nvd", action="append", metavar="JSON", default=None,
                    help="label caches; nvd_impact.json is the slimmed one that fits in RAM")
    ap.add_argument("--cap", type=int, default=0, metavar="N",
                    help="sample this many feed rows, for a quick pass")
    ap.add_argument("-o", "--out", metavar="JSON",
                    default=os.path.join(HERE, "figures", "feed_training.json"))
    args = ap.parse_args()

    # Labels come from both caches: the corpus one covers the CVEs our scans cite, the bulk
    # one covers the far larger set the feed references.
    nvd = {}
    # nvd_impact.json rather than nvd_bulk.json: the full file expands past this machine's
    # free memory when loaded as a dictionary, and killed two runs before any model was fitted.
    for path in (args.nvd or ["cwe_map.json", "nvd_impact.json"]):
        full = os.path.join(HERE, path)
        if not os.path.exists(full):
            print(f"  note: {path} not present, skipped")
            continue
        blob = json.load(open(full, encoding="utf-8"))
        part = blob.get("cves", blob)
        # The slimmed file stores the impact fields flat; the corpus cache nests them under
        # "cvss". Normalise so vector_for() sees one shape.
        for cid, rec in part.items():
            nvd[cid] = rec if "cvss" in rec else {"cvss": rec}
        print(f"  labels from {path}: {len(part)} CVEs")

    scans = labelled(read(args.scans), nvd)
    feed_all = read(args.feed)
    if args.cap and len(feed_all) > args.cap:
        rng = np.random.default_rng(0)
        feed_all = [feed_all[i] for i in
                    rng.choice(len(feed_all), args.cap, replace=False)]
    feed = labelled(feed_all, nvd)

    # Remove the checks that produced our findings, by OID and by name.
    test_oids = {r.get("nvt_oid", "") for r, _, _ in scans if r.get("nvt_oid")}
    test_names = {r["nvt_name"] for r, _, _ in scans}
    kept = [(r, v, c) for r, v, c in feed
            if r.get("nvt_oid", "") not in test_oids and r["nvt_name"] not in test_names]
    removed = len(feed) - len(kept)

    print(f"\nscan findings with a v3+ vector : {len(scans)}")
    print(f"feed checks with a v3+ vector   : {len(feed)}")
    print(f"  removed as seen in the scans  : {removed}")
    if removed == 0:
        print("  WARNING: nothing was removed. Either the corpora genuinely do not overlap,")
        print("  or the filter is broken -- check before believing any number below.")
    print(f"  left for training              : {len(kept)}")
    fam_scan = {r.get("nvt_family", "") for r, _, _ in scans}
    fam_feed = {r.get("nvt_family", "") for r, _, _ in kept}
    print(f"  families, scans {len(fam_scan)} against feed {len(fam_feed)}\n")
    if len(kept) < 200 or len(scans) < 60:
        sys.exit("not enough on one side to compare training sets.")

    Xs = L.build_matrix([r for r, _, _ in scans])
    Xf = L.build_matrix([r for r, _, _ in kept])
    gs = np.array([c for _, _, c in scans])
    folds = min(5, len(set(gs)))

    results = {}
    print(f"  {'field':16s} {'scan only':>10} {'feed only':>10} {'both':>8} {'majority':>9}")
    print("  " + "-" * 58)
    for field in I.FIELDS:
        ys = np.array([v.get(field) or "NONE" for _, v, _ in scans])
        yf = np.array([v.get(field) or "NONE" for _, v, _ in kept])

        own = f1_score(ys, cross_val_predict(I.model(), Xs, ys, groups=gs,
                                             cv=GroupKFold(n_splits=folds)),
                       average="macro", zero_division=0)
        from_feed = f1_score(ys, I.model().fit(Xf, yf).predict(Xs),
                             average="macro", zero_division=0)
        both = f1_score(ys, I.model().fit(np.vstack([Xf, Xs]),
                                          np.concatenate([yf, ys])).predict(Xs),
                        average="macro", zero_division=0)
        base = f1_score(ys, DummyClassifier(strategy="most_frequent")
                        .fit(Xf, yf).predict(Xs), average="macro", zero_division=0)
        results[field] = {"scan_only": round(float(own), 4),
                          "feed_only": round(float(from_feed), 4),
                          "both": round(float(both), 4),
                          "majority": round(float(base), 4)}
        print(f"  {field:16s} {own:10.3f} {from_feed:10.3f} {both:8.3f} {base:9.3f}")

    # `both` is fitted on data that includes the test rows, so it is an upper bound and not a
    # result. It is printed because a large gap between it and `feed only` says the scan rows
    # carry something the feed does not, which is worth knowing even from a leaky number.
    print("\n  `both` trains on the test rows as well and is an upper bound, not a score.")
    gain = {f: results[f]["feed_only"] - results[f]["scan_only"] for f in I.FIELDS}
    worst = min(gain.values())
    if worst > 0.02:
        print("  The feed trains a better model than our own scans do, on every field.")
        print("  Train from the feed and keep the scans for evaluation.")
    elif max(gain.values()) < -0.02:
        print("  The feed trains a worse model on every field. Two hundred times the data")
        print("  about a different population is worth less than 375 rows about this one;")
        print("  report that, since it is the result people assume cannot happen.")
    else:
        print("  The two training sets are within noise of each other. The feed's size does")
        print("  not buy accuracy here, and the reason to prefer it is coverage of families")
        print("  the scans never show, which this table does not measure.")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump(results, open(args.out, "w", encoding="utf-8"), indent=1)
    print(f"\n  wrote {args.out}")


if __name__ == "__main__":
    main()
