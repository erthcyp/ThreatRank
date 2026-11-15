#!/usr/bin/env python3
"""Can a tuned model justify the Classification stage, or does the design have to change?

`signal_check.py` put a floor under the question with naive Bayes: 73.5% against a 64.3%
baseline, +9.2 points, almost all of it the majority class being predicted well. That is a
floor, not an attempt. This is the attempt.

Registered before running, in scans.md 9 September: **if a tuned model with class weighting
and the numeric fields cannot clear the baseline by roughly 20 points, the stage does not
stand up on this data and the design has to change rather than the model.**

WHAT IS DIFFERENT FROM THE FLOOR

Four things the naive Bayes run did not have, each chosen because it addresses something the
per-class breakdown showed was broken:

  TF-IDF rather than raw counts   common words stop dominating
  class weighting                 the three minority classes were at or below chance
  the numeric fields              severity and port were never used at all, and they are
                                  what ought to separate dos from privEscalation and local
                                  from remote
  gradient boosting               the model family the design actually specifies

Evaluation is unchanged: leave-one-host-out, every transformer fitted inside the fold.
**Macro-F1 is the headline, not accuracy.** Accuracy on this data mostly measures how often
the largest class is guessed correctly; macro-F1 weights all four classes equally and is what
Deliverable 2 commits to reporting.

sklearn's HistGradientBoosting stands in for XGBoost, which is not installed. It is the same
family and adequate for deciding whether the stage is viable; it is not the paper's model.
"""

import collections
import csv
import glob
import json
import os
import re
import sys
import warnings

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import LeaveOneGroupOut, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))


def label_map():
    m = json.load(open(os.path.join(HERE, "cwe_map.json"), encoding="utf-8"))
    out = {}
    for cve, v in m.items():
        cv = v.get("cvss") or {}
        av = cv.get("attackVector", "").upper()
        rng = ("remoteExploit" if av in ("NETWORK", "ADJACENT_NETWORK", "ADJACENT")
               else "localExploit" if av in ("LOCAL", "PHYSICAL") else None)
        hit = lambda k: cv.get(k, "").upper() not in ("", "NONE")
        cons = ("privEscalation" if (hit("confidentiality") or hit("integrity"))
                else "dos" if hit("availability") else None)
        if rng and cons:
            out[cve] = (rng, cons)
    return out


def port_number(field):
    """'80/tcp' -> 80. 'general/tcp' -> 0, which marks a finding not tied to a listening port."""
    m = re.match(r"(\d+)/", field or "")
    return int(m.group(1)) if m else 0


def dataset(unauth_only=False, dedupe=True):
    """Labelled findings, optionally restricted to unauthenticated scans, deduplicated.

    Two corrections the first version of this file lacked, both of which inflated the result:

    **Deduplication.** `target-b1` was scanned three times, unauthenticated, again after
    patching, and once with credentials. Those reports repeat the same finding on the same
    host, and 35% of rows were duplicates of a row already present. A duplicate row is not
    an independent observation and inflates whichever fold it lands in.

    **The credentialed scan.** It contributes 325 of 543 rows on its own, all from one host,
    which is a different population from the unauthenticated scans that group A and group B
    consist of. Including it makes one machine 75% of the corpus and the pooled metric
    becomes a measurement of that machine.
    """
    lab = label_map()
    rank_r = {"remoteExploit": 1, "localExploit": 0}
    rank_c = {"privEscalation": 1, "dos": 0}
    rows = []
    paths = sorted(glob.glob(os.path.join(HERE, "processed", "findings_*.csv")))
    if unauth_only:
        paths = [p for p in paths if "_auth" not in os.path.basename(p)]
    seen = set()
    for path in paths:
        for r in csv.DictReader(open(path, encoding="utf-8")):
            if r["threat"] == "Log":
                continue
            cves = [c.strip() for c in (r["cves"] or "").split(";") if c.strip().startswith("CVE-")]
            vals = [lab[c] for c in cves if c in lab]
            if not vals:
                continue
            y = (max(vals, key=lambda t: rank_r[t[0]])[0],
                 max(vals, key=lambda t: rank_c[t[1]])[1])
            try:
                sev = float(r["severity"] or 0)
            except ValueError:
                sev = 0.0
            try:
                qod = float(r["qod"] or 0)
            except ValueError:
                qod = 0.0
            if dedupe:
                k = (r["host"], r["nvt_name"])
                if k in seen:
                    continue
                seen.add(k)
            rows.append({
                "text": r["nvt_name"] or "",
                "family": r["nvt_family"] or "",
                "solution": r["solution_type"] or "",
                "threat": r["threat"] or "",
                "severity": sev,
                "qod": qod,
                "port": port_number(r["port"]),
                "is_host_level": 1.0 if str(r["port"]).startswith("general/") else 0.0,
                "host": r["host"],
                "y": f"{y[0]}/{y[1]}",
            })
    return rows


# Columns are addressed by position because pandas is not installed; the order here is
# the contract between build_matrix and make_pre.
COLS = ["text", "family", "solution", "threat", "severity", "qod", "port", "is_host_level"]
TXT, CAT, NUM = 0, [1, 2, 3], [4, 5, 6, 7]


def build_matrix(rows):
    return np.array([[r[c] for c in COLS] for r in rows], dtype=object)


def as_float(a):
    return np.asarray(a, dtype=float)


def make_pre(text_features=True, numeric=True, categorical=True):
    parts = []
    if text_features:
        parts.append(("txt", TfidfVectorizer(lowercase=True, ngram_range=(1, 2),
                                             min_df=2, max_features=3000,
                                             sublinear_tf=True), TXT))
    if categorical:
        parts.append(("cat", OneHotEncoder(handle_unknown="ignore"), CAT))
    if numeric:
        parts.append(("num", Pipeline([("cast", FunctionTransformer(as_float)),
                                       ("sc", StandardScaler())]), NUM))
    return ColumnTransformer(parts, remainder="drop", sparse_threshold=0.0)


def run(name, pipe, X, y, groups, weighted=False):
    cv = LeaveOneGroupOut()
    fit_params = {}
    if weighted:
        fit_params["clf__sample_weight"] = compute_sample_weight("balanced", y)
    pred = cross_val_predict(pipe, X, y, groups=groups, cv=cv, params=fit_params or None)
    return name, accuracy_score(y, pred), f1_score(y, pred, average="macro"), pred


def report_folds(rows):
    """Fold sizes matter here: a host contributing one finding scores 100% for guessing once."""
    c = collections.Counter(r["host"] for r in rows)
    print("    fold sizes:", ", ".join(f"{v}" for _, v in c.most_common()))
    tiny = sum(1 for v in c.values() if v < 5)
    if tiny:
        print(f"    {tiny} of {len(c)} hosts contribute fewer than 5 findings; a fold that small "
              f"cannot measure anything")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    rows = dataset(unauth_only=(mode == "unauth"))
    print(f"corpus            : {mode}, deduplicated on (host, finding name)")
    X = build_matrix(rows)
    y = np.array([r["y"] for r in rows])
    groups = np.array([r["host"] for r in rows])
    dist = collections.Counter(y)
    print(f"labelled findings : {len(rows)} across {len(set(groups))} hosts, Log excluded")
    for k, v in dist.most_common():
        print(f"    {v:4d}  {k}")
    base_acc = max(dist.values()) / len(rows)
    print(f"\nbaseline          : accuracy {100*base_acc:.1f}%, macro-F1 "
          f"{100*f1_score(y, [dist.most_common(1)[0][0]]*len(y), average='macro'):.1f}%")
    report_folds(rows)
    print("evaluation        : leave-one-host-out, all transformers fitted inside the fold")
    print("headline metric   : macro-F1, because accuracy here mostly measures the largest class\n")

    trials = [
        ("text only", make_pre(True, False, False),
         LogisticRegression(max_iter=2000, class_weight="balanced"), False),
        ("text + cat + num", make_pre(True, True, True),
         LogisticRegression(max_iter=2000, class_weight="balanced"), False),
        ("num + cat only", make_pre(False, True, True),
         LogisticRegression(max_iter=2000, class_weight="balanced"), False),
        ("gradient boosting", make_pre(True, True, True),
         HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1,
                                        max_leaf_nodes=15, l2_regularization=1.0,
                                        random_state=0), True),
    ]
    print(f"  {'model':22s} {'accuracy':>9} {'macro-F1':>10} {'F1 vs base':>12}")
    print("  " + "-" * 56)
    base_f1 = f1_score(y, [dist.most_common(1)[0][0]]*len(y), average="macro")
    best = None
    for name, pre, clf, w in trials:
        pipe = Pipeline([("pre", pre), ("clf", clf)])
        try:
            nm, acc, f1, pred = run(name, pipe, X, y, groups, weighted=w)
        except Exception as e:
            print(f"  {name:22s}  failed: {type(e).__name__}: {e}")
            continue
        print(f"  {nm:22s} {100*acc:8.1f}% {100*f1:9.1f}% {100*(f1-base_f1):+11.1f}")
        if best is None or f1 > best[1]:
            best = (nm, f1, acc, pred)

    if best:
        print(f"\nper class, {best[0]}:")
        print(classification_report(y, best[3], digits=3, zero_division=0))
        lift = 100 * (best[2] - base_acc)
        print(f"accuracy over baseline: {lift:+.1f} points   (threshold registered in advance: +20)")
        print()
        if lift < 20:
            print("VERDICT: below the registered threshold. On this data the stage does not stand")
            print("up, and the design has to change rather than the model. Options: predict fewer")
            print("classes, or drop Classification and take (range, consequence) from CVSS")
            print("directly for CVE-bearing findings while leaving the rest unscored on that axis.")
        else:
            print("VERDICT: clears the registered threshold. The stage is worth building.")


if __name__ == "__main__":
    main()
