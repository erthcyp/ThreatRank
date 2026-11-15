#!/usr/bin/env python3
"""Does the text of a finding carry enough signal to predict what the graph needs?

The Classification stage rests on an assumption nobody has tested: that the wording of a
scanner check predicts the weakness it describes well enough to be useful. Measuring
`nvt_family` alone gave 69% against a 62% majority baseline, seven points, which is not
enough to justify the stage on its own. The text has to do the rest of the work, or the
stage does not stand up.

This answers that question and nothing more. It is a feasibility check, not the model:
multinomial naive Bayes over token counts, written in plain Python because the machine has
no scikit-learn. If the real model cannot beat this, the problem is the data.

WHAT IS PREDICTED

`(range, consequence)` as the attack graph consumes it, four classes, with the label taken
from the CVSS vector NVD publishes and multi-CVE findings resolved to the worst case each
axis admits. See scans.md, 8 September.

HOW IT IS EVALUATED

Leave-one-host-out. Findings on one machine are strongly correlated, so a random split would
train and test on the same Apache installation and report a number that means nothing. Every
count below is out-of-fold, and the vocabulary is rebuilt from the training hosts on each
fold so no test token is ever seen during fitting.

Three feature sets are compared against the majority-class baseline, because the useful
question is not whether the model works but where the signal actually is.
"""

import collections
import csv
import glob
import json
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def label_map():
    """(range, consequence) per CVE, from the CVSS vector NVD publishes."""
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


def rows_with_labels():
    """Findings that can be labelled, excluding Log-level detections.

    Log entries are service and product detections rather than weaknesses; including them
    would inflate every count with rows that have no weakness to classify.
    """
    lab = label_map()
    # Worst case each axis admits, matching the rule already used for the maximum EPSS.
    rank_r = {"remoteExploit": 1, "localExploit": 0}
    rank_c = {"privEscalation": 1, "dos": 0}
    out = []
    for path in sorted(glob.glob(os.path.join(HERE, "processed", "findings_*.csv"))):
        for r in csv.DictReader(open(path, encoding="utf-8")):
            if r["threat"] == "Log":
                continue
            cves = [c.strip() for c in (r["cves"] or "").split(";") if c.strip().startswith("CVE-")]
            vals = [lab[c] for c in cves if c in lab]
            if not vals:
                continue
            y = (max(vals, key=lambda t: rank_r[t[0]])[0],
                 max(vals, key=lambda t: rank_c[t[1]])[1])
            out.append({"host": r["host"], "name": r["nvt_name"], "family": r["nvt_family"],
                        "y": f"{y[0]}/{y[1]}"})
    return out


TOKEN = re.compile(r"[a-z]+")
STOP = {"the", "a", "an", "of", "in", "on", "for", "and", "or", "to", "is", "are", "was",
        "linux", "windows", "detection", "vulnerability", "vulnerabilities", "multiple"}


def tokens(text):
    """Lowercased words, three characters or more, minus stopwords.

    `linux` and `detection` are dropped deliberately: they appear in most check titles and
    would otherwise dominate the vocabulary without separating anything.
    """
    return [t for t in TOKEN.findall(text.lower()) if len(t) >= 3 and t not in STOP]


def featurise(row, mode):
    if mode == "family":
        return ["FAM=" + row["family"]]
    if mode == "text":
        return tokens(row["name"])
    return tokens(row["name"]) + ["FAM=" + row["family"]]


def train(rows, mode, alpha=0.3):
    """Multinomial naive Bayes. Returns (log priors, log likelihoods, vocabulary)."""
    classes = collections.Counter(r["y"] for r in rows)
    vocab = {f for r in rows for f in featurise(r, mode)}
    counts = {c: collections.Counter() for c in classes}
    totals = collections.Counter()
    for r in rows:
        for f in featurise(r, mode):
            counts[r["y"]][f] += 1
            totals[r["y"]] += 1
    n = len(rows)
    prior = {c: math.log(k / n) for c, k in classes.items()}
    denom = {c: totals[c] + alpha * len(vocab) for c in classes}
    return prior, counts, denom, vocab, alpha


def predict(model, row, mode):
    prior, counts, denom, vocab, alpha = model
    best, best_s = None, None
    for c in prior:
        s = prior[c]
        for f in featurise(row, mode):
            if f in vocab:
                s += math.log((counts[c][f] + alpha) / denom[c])
        if best_s is None or s > best_s:
            best, best_s = c, s
    return best


def evaluate(rows, mode):
    """Leave-one-host-out. Every prediction is made by a model that never saw that host."""
    hosts = sorted({r["host"] for r in rows})
    correct = total = 0
    per_class = collections.Counter()
    per_class_ok = collections.Counter()
    for h in hosts:
        tr = [r for r in rows if r["host"] != h]
        te = [r for r in rows if r["host"] == h]
        if not tr or not te:
            continue
        model = train(tr, mode)
        for r in te:
            p = predict(model, r, mode)
            total += 1
            per_class[r["y"]] += 1
            if p == r["y"]:
                correct += 1
                per_class_ok[r["y"]] += 1
    return correct / total if total else 0, total, per_class, per_class_ok


def main():
    rows = rows_with_labels()
    hosts = sorted({r["host"] for r in rows})
    dist = collections.Counter(r["y"] for r in rows)
    print(f"labelled findings : {len(rows)} across {len(hosts)} hosts, Log excluded")
    for k, v in dist.most_common():
        print(f"    {v:4d}  {k}")
    baseline = max(dist.values()) / len(rows)
    print(f"\nmajority baseline : {100*baseline:.1f}%  (always predict {dist.most_common(1)[0][0]})")
    print("evaluation        : leave-one-host-out, vocabulary refitted per fold\n")

    print(f"  {'features':16s} {'accuracy':>9} {'vs baseline':>12}")
    print("  " + "-" * 40)
    results = {}
    for mode in ("family", "text", "text+family"):
        acc, n, pc, pco = evaluate(rows, mode)
        results[mode] = (acc, pc, pco)
        print(f"  {mode:16s} {100*acc:8.1f}% {100*(acc-baseline):+11.1f}")

    print("\nper class, text+family:")
    acc, pc, pco = results["text+family"]
    for c, n in pc.most_common():
        print(f"    {c:32s} {pco[c]:4d}/{n:<4d}  {100*pco[c]/n:5.1f}%")

    lift = results["text+family"][0] - baseline
    print()
    if lift < 0.05:
        print("VERDICT: no usable signal. The text does not separate these classes, and the")
        print("stage cannot be justified on this data as it stands.")
    elif lift < 0.15:
        print("VERDICT: weak signal. Better than guessing, but not by enough to carry a stage")
        print("on its own. Report the margin honestly rather than the accuracy alone.")
    else:
        print("VERDICT: real signal. The text separates the classes well enough that the stage")
        print("is worth building, and a tuned model should improve on this floor.")


if __name__ == "__main__":
    main()
