#!/usr/bin/env python3
"""Predict what a finding lets an attacker do, when no published vector says.

The attack graph needs two properties per finding: a range, remote or local, and a
consequence, privilege escalation or denial of service. For a finding citing a CVE, NVD
publishes both in its CVSS vector and nothing has to be predicted. For a finding with no
CVE there is no vector, and until now `findings_to_mulval.py` filled the gap with a
constant: the most permissive pair the rule base admits.

That constant was wrong in a way the output made obvious. It asserted that
`TCP Timestamps Information Disclosure` grants privilege escalation, which no one would
defend, and it granted every uncatalogued finding the strongest capability available rather
than an estimated one. Assuming the worst is not scoring; it is asserting.

WHY NOT MAP THE SCANNER'S OWN SEVERITY BANDS

Greenbone bands findings Critical, High, Medium, Low, and mapping those onto the two
consequences would work today. It would also tie the design to one vendor: Nessus bands
differently, a third tool differently again, and each new tool would need someone to decide
what its labels mean. That moves the guess rather than removing it, and this pipeline
accepts any number of tools by design.

WHAT IS DONE INSTEAD

Train on the findings whose properties are published, predict for the ones whose are not.
Features come from the common schema, so nothing here knows which scanner produced a row.
Labels come from NVD. The cut points are learned from those labels rather than chosen.

THE LIMITATION THAT CANNOT BE MEASURED AWAY

The model trains on findings that carry a CVE and is applied to findings that do not, and
those are not the same population: `Apache HTTP Server < 2.4.49` and `Operating System End
of Life` are different kinds of sentence. The accuracy reported below is measured inside
the labelled population by leave-one-host-out. **It is not evidence that the model
transfers to the unlabelled one, and no such evidence can be obtained here, because the
findings in question have no ground truth by definition.**

The answer to that is not a better number. It is to mark every predicted fact as predicted,
and to report how much of the finished graph depends on one. `findings_to_mulval.py` writes
the marker and `consequence.py` reports the dependence.

    python3 classify.py         train, evaluate, and show what the unlabelled rows get
"""

import argparse
import collections
import csv
import json
import os
import sys
import warnings

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import LeaveOneGroupOut, cross_val_predict
from sklearn.metrics import classification_report, f1_score
from sklearn.pipeline import Pipeline

import likelihood as L

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))

REMOTE_VECTORS = ("NETWORK", "ADJACENT_NETWORK", "ADJACENT")
LOCAL_VECTORS = ("LOCAL", "PHYSICAL")

# An end-of-life condition is not an attack step. Nobody exploits the fact that a vendor
# stopped shipping fixes; it is a property of the host that makes other findings
# unfixable, and eol_lock.py measures it on its own terms. Predicting a range and a
# consequence for it would be inventing an exploit that does not exist.
EOL_MARKERS = ("end of life", "eol detection")


def is_end_of_life(row):
    name = (row.get("nvt_name") or "").lower()
    return any(m in name for m in EOL_MARKERS)


def published_properties(row, cvss_map):
    """(range, consequence) from the published CVSS vectors, worst case across CVEs."""
    rng = cons = None
    for cve in [c.strip() for c in (row.get("cves") or "").split(";")
                if c.strip().startswith("CVE-")]:
        vector = (cvss_map.get(cve) or {}).get("cvss") or {}
        av = (vector.get("attackVector") or "").upper()
        impacted = lambda k: (vector.get(k) or "").upper() not in ("", "NONE")
        this_rng = ("remoteExploit" if av in REMOTE_VECTORS
                    else "localExploit" if av in LOCAL_VECTORS else None)
        this_cons = ("privEscalation" if impacted("confidentiality") or impacted("integrity")
                     else "dos" if impacted("availability") else None)
        if this_rng and rng != "remoteExploit":
            rng = this_rng
        if this_cons and cons != "privEscalation":
            cons = this_cons
    return (rng, cons) if rng and cons else None


def model():
    return Pipeline([("pre", L.make_pre()),
                     ("clf", HistGradientBoostingClassifier(
                         max_iter=300, learning_rate=0.1, max_leaf_nodes=15,
                         l2_regularization=1.0, random_state=0))])


def split(rows, cvss_map):
    """Rows whose properties are published, and rows that need predicting."""
    labelled, unlabelled = [], []
    for r in rows:
        if is_end_of_life(r):
            continue
        props = published_properties(r, cvss_map)
        (labelled if props else unlabelled).append((r, props))
    return labelled, unlabelled


def predict(rows, cvss_map):
    """{id(row): (range, consequence)} for every row with no published vector.

    Fitted on every labelled row, because this produces properties rather than measuring
    how well they are produced. The measurement is in main(), where no model sees the host
    it is scoring.
    """
    labelled, unlabelled = split(rows, cvss_map)
    if not unlabelled:
        return {}
    if len(labelled) < 20:
        sys.exit("too few findings with a published vector to train on")
    fitted = model().fit(L.build_matrix([r for r, _ in labelled]),
                         np.array([f"{p[0]}/{p[1]}" for _, p in labelled]))
    out = {}
    for r, pred in zip([r for r, _ in unlabelled],
                       fitted.predict(L.build_matrix([r for r, _ in unlabelled]))):
        rng, cons = pred.split("/")
        out[id(r)] = (rng, cons)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cvss", default=os.path.join(HERE, "cwe_map.json"), metavar="JSON")
    args = ap.parse_args()

    cvss_map = json.load(open(args.cvss, encoding="utf-8"))
    rows = L.findings()
    labelled, unlabelled = split(rows, cvss_map)
    eol = [r for r in rows if is_end_of_life(r)]

    print(f"findings           : {len(rows)} on {len({r['host'] for r in rows})} hosts")
    print(f"  published vector : {len(labelled)}   <- trained on these")
    print(f"  no vector        : {len(unlabelled)}   <- predicted for these")
    print(f"  end of life      : {len(eol)}   <- excluded, measured by eol_lock.py instead\n")

    X = L.build_matrix([r for r, _ in labelled])
    y = np.array([f"{p[0]}/{p[1]}" for _, p in labelled])
    groups = np.array([r["host"] for r, _ in labelled])
    dist = collections.Counter(y)
    for k, v in dist.most_common():
        print(f"    {v:4d}  {k}")

    base = f1_score(y, [dist.most_common(1)[0][0]] * len(y), average="macro")
    pred = cross_val_predict(model(), X, y, groups=groups, cv=LeaveOneGroupOut())
    got = f1_score(y, pred, average="macro")
    print(f"\nleave-one-host-out, every transform fitted inside the fold")
    print(f"  macro-F1 {100*got:.1f}%   majority baseline {100*base:.1f}%   "
          f"{100*(got-base):+.1f}")
    print(classification_report(y, pred, digits=3, zero_division=0))

    print("**Measured inside the labelled population only.** It is not evidence that the")
    print("model transfers to the rows below, which have no ground truth by definition.\n")

    if unlabelled:
        guesses = predict(rows, cvss_map)
        print("what the unlabelled findings are predicted to be:")
        for r, _ in sorted(unlabelled, key=lambda t: -float(t[0].get("severity") or 0)):
            rng, cons = guesses[id(r)]
            print(f"  sev={r.get('severity','') or '0':>4}  {rng:14s} {cons:14s} "
                  f"{r['nvt_name'][:44]}")


if __name__ == "__main__":
    main()
