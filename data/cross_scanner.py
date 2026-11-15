#!/usr/bin/env python3
"""Does a model trained on one scanner's wording work on another's?

Everything learned in this project is learned from OpenVAS. The features are its check titles,
its descriptions, its family names, its `solution_type`, its QoD. The plan the pipeline
produces is meant to cover both scanners, so if the models only work on the half they were
trained on, the coverage claim has a hole in exactly the place it claims to fill.

The shift is not simulated here. It is the real one: train on OpenVAS findings, predict on
Nessus findings, and grade both against the same external answer -- the CVSS impact metrics
NVD publishes for the CVEs each finding cites. Neither scanner wrote that label.

WHAT MAKES THIS HARDER THAN THE SHIFT ALREADY MEASURED

Two of the features do not exist on the Nessus side at all. `solution_type` is an OpenVAS
field, and Nessus exposes no QoD equivalent, so both arrive empty for every Nessus row. The
model meets a region of its input space it never saw in training, which is worse than the
covariate shift between scored and unscored findings within one scanner.

Three conditions are therefore reported, and the gap between them says where any loss comes
from:

    within OpenVAS        cross-validated, the reference
    OpenVAS to Nessus     all features, with the two OpenVAS-only fields empty
    OpenVAS to Nessus     text, severity, threat and port only -- the shared subset

If the third is close to the first, the answer is to train on what both tools provide and
accept a little less accuracy for a model that works on either. If the second is already
close, nothing needs changing. If both collapse, the models are OpenVAS-specific and the
paper says so.

    python3 cross_scanner.py
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
# The columns both tools populate. featurise() puts text at 0, the three categoricals at
# 1..3 and the numerics at 4..; blanking a categorical is what OneHotEncoder already does
# for an unseen value, so the shared-subset run blanks the two OpenVAS-only fields.
OPENVAS_ONLY = {"solution_type": 2, "qod": 5}


def load(pattern, scanner):
    rows, seen = [], set()
    for path in sorted(glob.glob(os.path.join(HERE, pattern))):
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("threat") == "Log":
                    continue
                if (r.get("scanner") or "").lower() != scanner:
                    continue
                key = (r["host"], r["nvt_name"])
                if key in seen:
                    continue
                seen.add(key)
                rows.append(r)
    return rows


def labelled(rows, nvd):
    out = []
    for r in rows:
        v, c = I.vector_for(r, nvd)
        if v is not None:
            out.append((r, v, c))
    return out


def blank_shared(X):
    """A copy of the feature matrix with the two OpenVAS-only columns emptied."""
    Z = X.copy()
    Z[:, OPENVAS_ONLY["solution_type"]] = ""
    Z[:, OPENVAS_ONLY["qod"]] = 0.0
    return Z


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default="processed/findings_*2.csv", metavar="GLOB")
    ap.add_argument("--nvd", default=os.path.join(HERE, "cwe_map.json"), metavar="JSON")
    ap.add_argument("-o", "--out", metavar="JSON",
                    default=os.path.join(HERE, "figures", "cross_scanner.json"))
    args = ap.parse_args()

    nvd = json.load(open(args.nvd, encoding="utf-8"))
    ov = labelled(load(args.corpus, "openvas"), nvd)
    ne = labelled(load(args.corpus, "nessus"), nvd)

    print(f"OpenVAS with a published vector : {len(ov)}   <- trains here")
    print(f"Nessus  with a published vector : {len(ne)}   <- tested here")
    if len(ne) < 15:
        sys.exit("too few Nessus findings carry a vector to say anything about transfer.")

    fams = collections.Counter((r.get("nvt_family") or "") for r, _, _ in ne)
    seen_fams = {(r.get("nvt_family") or "") for r, _, _ in ov}
    unseen = sum(n for f, n in fams.items() if f not in seen_fams)
    print(f"  Nessus families the OpenVAS side never shows: "
          f"{100*unseen/max(len(ne),1):.0f}% of its findings")
    print(f"  solution_type present on the Nessus side    : "
          f"{sum(1 for r, _, _ in ne if (r.get('solution_type') or '').strip())} of {len(ne)}")
    print(f"  qod present on the Nessus side              : "
          f"{sum(1 for r, _, _ in ne if (r.get('qod') or '').strip())} of {len(ne)}\n")

    Xov = L.build_matrix([r for r, _, _ in ov])
    Xne = L.build_matrix([r for r, _, _ in ne])
    gov = np.array([c for _, _, c in ov])
    folds = min(5, len(set(gov)))

    results = {}
    print(f"  {'field':16s} {'within OV':>10} {'to Nessus':>10} {'shared only':>12} "
          f"{'majority':>9}")
    print("  " + "-" * 62)
    for field in I.FIELDS:
        yov = np.array([v.get(field) or "NONE" for _, v, _ in ov])
        yne = np.array([v.get(field) or "NONE" for _, v, _ in ne])

        within = f1_score(yov, cross_val_predict(I.model(), Xov, yov, groups=gov,
                                                 cv=GroupKFold(n_splits=folds)),
                          average="macro", zero_division=0)
        full = f1_score(yne, I.model().fit(Xov, yov).predict(Xne),
                        average="macro", zero_division=0)
        shared = f1_score(yne,
                          I.model().fit(blank_shared(Xov), yov).predict(blank_shared(Xne)),
                          average="macro", zero_division=0)
        base = f1_score(yne, DummyClassifier(strategy="most_frequent")
                        .fit(Xov, yov).predict(Xne), average="macro", zero_division=0)
        results[field] = {"within_openvas": round(float(within), 4),
                          "to_nessus_all_features": round(float(full), 4),
                          "to_nessus_shared_only": round(float(shared), 4),
                          "majority_on_nessus": round(float(base), 4)}
        print(f"  {field:16s} {within:10.3f} {full:10.3f} {shared:12.3f} {base:9.3f}")

    print()
    worst_full = min(r["to_nessus_all_features"] - r["majority_on_nessus"]
                     for r in results.values())
    worst_shared = min(r["to_nessus_shared_only"] - r["majority_on_nessus"]
                       for r in results.values())
    if worst_full > 0.05:
        print("  The models carry across as they are. The two missing fields cost little,")
        print("  and the merged plan can use one model for both scanners.")
    elif worst_shared > 0.05:
        print("  Only the shared feature subset carries across. Train on what both tools")
        print("  provide: a little less accurate within OpenVAS, and usable on either.")
    else:
        print("  Neither condition clears the majority-class answer on Nessus findings.")
        print("  The models are OpenVAS-specific. The paper must say so, and the coverage")
        print("  claim must be stated for OpenVAS findings rather than for the merged plan.")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump(results, open(args.out, "w", encoding="utf-8"), indent=1)
    print(f"\n  wrote {args.out}")


if __name__ == "__main__":
    main()
