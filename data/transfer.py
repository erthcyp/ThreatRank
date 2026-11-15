#!/usr/bin/env python3
"""Does the likelihood surrogate survive the shift it is actually asked to cross?

The surrogate is trained on findings that carry a CVE, because those are the ones EPSS can
supply a target for, and it is used on findings that carry none. Its headline number is
measured entirely on the training population, so it says nothing about the population the
model exists for. That gap is the first thing a reader will press on, and until now the only
honest answer was that no external label exists for the other side.

WHY ABLATING THE CVE MEASURES NOTHING

The obvious test -- hide a finding's CVE and see whether the estimate holds -- does nothing
here. The feature vector is already CVE-free: text, family, solution type, threat, severity,
QoD, port. Hiding the identifier changes not one input. Leakage was never the risk.

WHAT THE RISK ACTUALLY IS

Covariate shift. Findings without a CVE are not a random sample of findings; measured on this
corpus they sit at half the QoD (median 15 against 30) and a point lower in severity, though
they share almost all of their families and solution types. A model fitted on the confident,
well-identified half may simply not apply to the tentative half.

So the shift is simulated instead of assumed. A classifier is fitted to tell the two
populations apart from the same features the surrogate uses; the CVE-bearing findings it
judges most CVE-like are held out, and the surrogate is trained on the remainder and scored
against published EPSS on that held-out, deliberately unrepresentative set. If the estimate
holds up on the findings that look least like its training data, that is evidence it carries
across. Leave-one-family-out is reported beside it, since an unseen family is the other way
the real population differs.

WHAT THIS STILL CANNOT SHOW

That the estimate is correct on findings with no CVE. Nothing available can show that: there
is no published probability to compare against, which is the whole reason the surrogate
exists. This measures whether performance survives a shift resembling the real one, on
findings where a target does exist. It is a stronger statement than the headline number and a
weaker one than the claim the pipeline would like to make, and it should be written as such.

    python3 transfer.py --findings processed/findings_openvas_b2.csv
"""

import argparse
import collections
import csv
import glob
import json
import os
import sys

import numpy as np
from scipy.stats import spearmanr
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import GroupKFold, LeaveOneGroupOut, cross_val_predict

import likelihood as L

HERE = os.path.dirname(os.path.abspath(__file__))


def load(patterns):
    rows, seen = [], set()
    for pattern in patterns:
        for path in sorted(glob.glob(os.path.join(HERE, pattern))):
            with open(path, encoding="utf-8") as fh:
                for r in csv.DictReader(fh):
                    if r.get("threat") == "Log":
                        continue
                    key = (r["host"], r["nvt_name"])
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append(r)
    return rows


def rho_of(y, pred):
    r = spearmanr(y, pred).statistic
    return 0.0 if np.isnan(r) else r


def describe(label, scored, unscored, field, numeric=False):
    if numeric:
        a = [float(r.get(field) or 0) for r in scored]
        b = [float(r.get(field) or 0) for r in unscored]
        print(f"  {label:22s} {np.median(a):8.1f} {np.median(b):9.1f}")
        return
    seen_values = {(r.get(field) or "") for r in scored}
    unseen = sum(1 for r in unscored if (r.get(field) or "") not in seen_values)
    print(f"  {label:22s} {len(seen_values):8d} "
          f"{100*unseen/max(len(unscored),1):8.0f}%")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", action="append", metavar="CSV_OR_GLOB",
                    default=None)
    ap.add_argument("--holdout", type=float, default=0.25, metavar="FRACTION",
                    help="share of the scored findings held out as the shifted test set")
    ap.add_argument("-o", "--out", metavar="JSON",
                    default=os.path.join(HERE, "figures", "transfer.json"),
                    help="where make_figures.py picks the results up")
    args = ap.parse_args()
    # The two-scanner corpus the paper names, as impact.py reads it. This used to be the glob
    # findings_*2.csv, which matched exactly these four files when it was written; the Qualys
    # robustness scan added later is also named *_b2 and joined the corpus silently, although the
    # paper states Qualys is not a training input.
    patterns = args.findings or ["processed/findings_openvas_a2.csv",
                                "processed/findings_openvas_b2.csv",
                                "processed/findings_nessus_a2.csv",
                                "processed/findings_nessus_b2.csv"]

    rows = load(patterns)
    epss = L.epss_lookup()
    labelled = [(r,) + L.target_for(r, epss) for r in rows]
    scored = [(r, y, c) for r, y, c in labelled if y is not None]
    unscored = [r for r, y, _ in labelled if y is None]

    print(f"corpus            : {len(rows)} findings, Log excluded, deduplicated")
    print(f"  with EPSS        : {len(scored)}   <- the surrogate trains here")
    print(f"  without          : {len(unscored)}   <- the surrogate is used here\n")
    if len(scored) < 60 or len(unscored) < 10:
        sys.exit("too few findings on one side of the split to say anything about transfer.")

    print("how the two populations differ")
    print(f"  {'feature':22s} {'values':>8} {'unseen':>9}")
    for f in ("nvt_family", "solution_type", "threat"):
        describe(f, [r for r, _, _ in scored], unscored, f)
    print(f"  {'feature':22s} {'median':>8} {'median':>9}")
    for f in ("severity", "qod"):
        describe(f, [r for r, _, _ in scored], unscored, f, numeric=True)

    X = L.build_matrix([r for r, _, _ in scored])
    y_raw = np.array([y for _, y, _ in scored])
    y = np.log10(np.maximum(y_raw, L.FLOOR))
    by_cve = np.array([c for _, _, c in scored])
    by_family = np.array([(r.get("nvt_family") or "") for r, _, _ in scored])

    # The reference number, repeated here so the comparison is like for like.
    folds = min(5, len(set(by_cve)))
    base = cross_val_predict(L.model(), X, y, groups=by_cve,
                             cv=GroupKFold(n_splits=folds))
    results = {}

    def record(name, value, n):
        results[name] = (round(float(value), 4), int(n))
        print(f"  {name:34s} {value:8.3f} {n:6d}")

    print(f"\n  {'evaluation':34s} {'Spearman':>9} {'n':>6}")
    print("  " + "-" * 52)
    record("CVE-grouped split, the headline", rho_of(y, base), len(y))

    # Which scored findings look most like the unscored ones. The classifier never sees a
    # target, only the same inputs the surrogate uses, so "looks CVE-less" is defined by the
    # features rather than by anything downstream of the label.
    Xall = L.build_matrix([r for r, _, _ in scored] + unscored)
    is_unscored = np.array([0] * len(scored) + [1] * len(unscored))
    pre = L.make_pre()
    Z = pre.fit_transform(Xall)
    clf = HistGradientBoostingClassifier(max_iter=200, max_leaf_nodes=15,
                                         random_state=0)
    clf.fit(Z, is_unscored)
    looks_unscored = clf.predict_proba(Z[:len(scored)])[:, 1]

    cut = int(len(scored) * (1 - args.holdout))
    order = np.argsort(-looks_unscored)
    test_idx, train_idx = order[:len(scored) - cut], order[len(scored) - cut:]
    model = L.model().fit(X[train_idx], y[train_idx])
    shifted = model.predict(X[test_idx])
    record("shifted hold-out, most CVE-like", rho_of(y[test_idx], shifted), len(test_idx))

    # The same split run the other way: if the number above is low simply because the
    # hold-out is small or odd, a random hold-out of the same size will be low too.
    rng = np.random.default_rng(0)
    random_idx = rng.permutation(len(scored))
    r_test, r_train = random_idx[:len(test_idx)], random_idx[len(test_idx):]
    r_model = L.model().fit(X[r_train], y[r_train])
    record("random hold-out, same size",
           rho_of(y[r_test], r_model.predict(X[r_test])), len(r_test))

    n_fam = len(set(by_family))
    if n_fam > 1:
        fam = cross_val_predict(L.model(), X, y, groups=by_family,
                                cv=LeaveOneGroupOut())
        record(f"leave-one-family-out, {n_fam} families", rho_of(y, fam), len(y))

    qod = np.array([float(r.get("qod") or 0) for r, _, _ in scored])
    low = qod <= np.median([float(r.get("qod") or 0) for r in unscored])
    if low.sum() >= 20 and (~low).sum() >= 40:
        m = L.model().fit(X[~low], y[~low])
        record("train high QoD, test low QoD", rho_of(y[low], m.predict(X[low])),
               int(low.sum()))

    print(f"\n  The shifted hold-out is the number that speaks to transfer. It is not proof")
    print(f"  that the estimate is right where no CVE exists; no available label can be.")
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump(results, open(args.out, "w", encoding="utf-8"), indent=1)
    print(f"  wrote {args.out}")


if __name__ == "__main__":
    main()
