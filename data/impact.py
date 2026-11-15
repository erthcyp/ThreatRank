#!/usr/bin/env python3
"""What a finding lets an attacker do, recovered from the report when no CVE says so.

The consequence term of `R = L x C` comes from the impact metrics of a published CVSS vector.
A finding citing no CVE has no vector, and until now those findings were given assumed values
and a label saying so. This is the classification stage rebuilt to supply them, in the same
shape as the likelihood surrogate: learn the mapping from how a scanner describes a finding to
what an external catalogue says, on the findings where both exist, and apply it where the
catalogue is silent.

TWO EARLIER TARGETS FAILED, AND THE REASONS ARE THE DESIGN OF THIS ONE

**CWE.** 129 classes over 410 findings with 39 of them holding a single example; collapsing to
pillars puts 58% in one class. The target was finer than the corpus could support.

**`(range, consequence)` as MulVAL categories.** We defined that answer set ourselves and
defined it incompletely: a finding that grants an attacker nothing had no correct entry to
choose, so the classifier answered `privEscalation` for 28 of 29 cases and was right by
accident when it was right at all.

The impact metrics avoid both. They are NIST's, not ours, so they are not ours to get wrong;
and `NONE` is a legitimate, well-populated value, so "this finding grants nothing" is an
answer the model is allowed to give. Measured on this corpus:

    confidentiality   NONE 44%   HIGH 35%   LOW 19%
    integrity         NONE 49%   HIGH 27%   LOW 23%
    availability      HIGH 48%   NONE 39%   LOW 11%

WHAT IS DELIBERATELY NOT PREDICTED

The attack vector, which supplies the graph's Range. 85% of this corpus is `NETWORK`, so a
model that always answers NETWORK scores 85% and has learned nothing. Range keeps its
published value where one exists and its assumed value where none does, and the paper says so
rather than reporting an accuracy that is really a base rate.

THE BASELINE THAT HAS TO BE BEATEN

Always answering the most common class. This is stated before the run, as the likelihood
threshold was, because a classifier on a skewed target can look accurate while ranking
nothing. Macro-F1 is the headline rather than accuracy, since the minority classes are the
ones the graph's consequence turns on.

    python3 impact.py                       evaluate against the published vectors
    python3 impact.py --predict out.csv     and write estimates for findings with no vector
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
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import GroupKFold, cross_val_predict
from sklearn.pipeline import Pipeline

import likelihood as L

HERE = os.path.dirname(os.path.abspath(__file__))
FIELDS = ("confidentiality", "integrity", "availability")
# Registered before the first run: the model must beat the majority-class answer on macro-F1
# for every field it is reported for, or the field is reported as a failure.
MARGIN = 0.05


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


def vector_for(row, nvd):
    """The CVSS vector of the first CVE that has one, and that CVE.

    First rather than worst: the impact metrics describe what the flaw does, and taking the
    maximum across several CVEs would describe a composite flaw that does not exist. The CVE
    is returned because it is the grouping key for the split.
    """
    for c in (row.get("cves") or "").split(";"):
        c = c.strip()
        if not c.startswith("CVE-"):
            continue
        v = (nvd.get(c) or {}).get("cvss") or {}
        if v.get("confidentiality"):
            return v, c
    return None, None


def model():
    return Pipeline([("pre", L.make_pre()),
                     ("clf", HistGradientBoostingClassifier(
                         max_iter=300, learning_rate=0.08, max_leaf_nodes=15,
                         l2_regularization=1.0, random_state=0))])


def text_model():
    """The published baseline: predict the impact from the finding's text alone.

    Studies that infer a CVSS metric from a vulnerability description do it with a bag-of-words
    representation of the text and a linear classifier~\\cite{amirov,xplaincvss,multimodal}. This
    reproduces that approach on the same labels and the same split, so the comparison isolates what
    the structured features add over the words: TF-IDF over the finding's name and description,
    1--2 grams, with L2-regularised logistic regression.
    """
    return Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2,
                                               sublinear_tf=True, max_features=4000)),
                     ("clf", LogisticRegression(max_iter=2000, class_weight="balanced",
                                                random_state=0))])


def text_of(row):
    return f"{row.get('nvt_name', '')} {row.get('description', '')}".strip()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", action="append", metavar="CSV_OR_GLOB", default=None)
    ap.add_argument("--nvd", default=os.path.join(HERE, "cwe_map.json"), metavar="JSON")
    ap.add_argument("--predict", metavar="CSV",
                    help="write estimates for the findings that have no published vector")
    ap.add_argument("-o", "--out", metavar="JSON",
                    default=os.path.join(HERE, "figures", "impact.json"))
    args = ap.parse_args()

    # The two-scanner corpus the paper names: OpenVAS and Nessus over groups A and B. A bare
    # findings_*2.csv glob would also pull in findings_qualys_b2.csv, which belongs to the later
    # robustness scan and is not part of the corpus the models are measured on.
    rows = load(args.findings or ["processed/findings_openvas_a2.csv",
                                  "processed/findings_openvas_b2.csv",
                                  "processed/findings_nessus_a2.csv",
                                  "processed/findings_nessus_b2.csv"])
    nvd = json.load(open(args.nvd, encoding="utf-8"))
    pairs = [(r,) + vector_for(r, nvd) for r in rows]
    have = [(r, v, c) for r, v, c in pairs if v is not None]
    missing = [r for r, v, _ in pairs if v is None]

    print(f"corpus            : {len(rows)} findings, Log excluded, deduplicated")
    print(f"  with a vector    : {len(have)}   <- the classifier trains here")
    print(f"  without          : {len(missing)}   <- it is used here, and these currently "
          f"carry assumed values")
    if len(have) < 80:
        sys.exit("too few published vectors to train or to evaluate.")

    X = L.build_matrix([r for r, _, _ in have])
    texts = [text_of(r) for r, _, _ in have]
    groups = np.array([c for _, _, c in have])
    folds = min(5, len(set(groups)))
    print(f"  split            : grouped by the CVE that supplied the vector, {folds} folds")
    print(f"  registered rule  : macro-F1 must beat the majority-class answer by "
          f"{MARGIN:.2f}\n")

    results, verdicts = {}, []
    for field in FIELDS:
        y = np.array([v.get(field) or "NONE" for _, v, _ in have])
        counts = collections.Counter(y)
        cv = GroupKFold(n_splits=folds)
        pred = cross_val_predict(model(), X, y, groups=groups, cv=cv)
        base = cross_val_predict(DummyClassifier(strategy="most_frequent"), X, y,
                                 groups=groups, cv=cv)
        pred_text = cross_val_predict(text_model(), texts, y, groups=groups, cv=cv)
        f1 = f1_score(y, pred, average="macro", zero_division=0)
        f1_base = f1_score(y, base, average="macro", zero_division=0)
        f1_text = f1_score(y, pred_text, average="macro", zero_division=0)
        acc = float((pred == y).mean())
        acc_base = float((base == y).mean())
        passed = f1 >= f1_base + MARGIN
        verdicts.append(passed)
        results[field] = {"macro_f1": round(f1, 4), "macro_f1_majority": round(f1_base, 4),
                          "macro_f1_text": round(f1_text, 4),
                          "accuracy": round(acc, 4), "accuracy_majority": round(acc_base, 4),
                          "classes": {k: v for k, v in counts.most_common()},
                          "beats_baseline": bool(passed)}
        print(f"  {field}")
        print(f"    classes        " + ", ".join(f"{k} {100*v/len(y):.0f}%"
                                                 for k, v in counts.most_common()))
        print(f"    macro-F1       {f1:.3f}   text baseline {f1_text:.3f}   "
              f"majority-class answer {f1_base:.3f}")
        print(f"    accuracy       {acc:.3f}   majority-class answer {acc_base:.3f}")
        print(f"    {'PASS' if passed else 'FAIL'}\n")

    print("  per-class detail for the field the graph leans on hardest:")
    y = np.array([v.get("confidentiality") or "NONE" for _, v, _ in have])
    pred = cross_val_predict(model(), X, y, groups=groups,
                             cv=GroupKFold(n_splits=folds))
    print("   " + classification_report(y, pred, zero_division=0).replace("\n", "\n   "))

    if all(verdicts):
        print("  Every field beats the majority-class answer. The assumed values for "
              "findings\n  with no published vector can be replaced by estimates.")
    else:
        failed = [f for f, ok in zip(FIELDS, verdicts) if not ok]
        print(f"  {', '.join(failed)} did not clear the registered margin. Those fields keep "
              f"their\n  assumed values, and the paper reports the failure rather than the "
              f"fields that passed.")

    if args.predict:
        if not all(verdicts):
            sys.exit("\nRefusing to write estimates while a field is below its baseline. "
                     "Reporting a\nnumber that failed its own registered rule is how this "
                     "project once announced a pass on a fail.")
        fitted = {f: model().fit(X, np.array([v.get(f) or "NONE" for _, v, _ in have]))
                  for f in FIELDS}
        Xm = L.build_matrix(missing)
        cols = {f: fitted[f].predict(Xm) for f in FIELDS} if missing else {f: [] for f in FIELDS}
        with open(args.predict, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["host", "port", "nvt_name"] + list(FIELDS) + ["source"])
            for i, r in enumerate(missing):
                w.writerow([r["host"], r.get("port", ""), r["nvt_name"]]
                           + [cols[f][i] for f in FIELDS] + ["estimated"])
        print(f"\n  wrote {args.predict}: {len(missing)} findings, marked `estimated` so a "
              f"reader can\n  always separate them from a published vector.")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump(results, open(args.out, "w", encoding="utf-8"), indent=1)
    print(f"  wrote {args.out}")


if __name__ == "__main__":
    main()
