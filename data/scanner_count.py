#!/usr/bin/env python3
"""Does adding a scanner improve the exploit-likelihood surrogate? A controlled ablation.

The headline likelihood number in fig_ml_baseline is already measured on the pooled corpus of
every unauthenticated report, which is OpenVAS **and** Nessus together (``likelihood.findings``
globs every ``findings_*.csv``). This script asks the question the paper does not yet answer:
how much of that number is the second scanner worth? It re-runs the *identical* surrogate
(same features, same model, same CVE-grouped split from ``likelihood.py``) while varying only
the set of scanners whose findings are available, and reports Spearman per scanner count.

DESIGN -- why it is a fair comparison, not a moving target

The confound in "more scanners is better" is that adding a scanner also changes the population
being scored, so a naive 1-vs-2 compares two different test sets. This isolates the training
contribution instead:

  * The **test population is fixed** across configurations: the OpenVAS CVE-bearing findings,
    which exist in every configuration. Their EPSS targets never change, so Spearman is
    comparable across configurations.
  * Folds are grouped **by the CVE that supplied the target** (the headline split). For each
    held-out fold, every training row -- from any scanner -- whose target CVE is in the fold is
    removed, so the second scanner can never leak the answer.
  * Two real effects of the added scanner both remain, because both are legitimate: more
    *training rows*, and richer *within-host context* features (``contextualise`` sees the
    host's findings from all scanners in the configuration, as a real scan would).

What this does NOT claim: that the added scanner improves *coverage* of real risk. That is a
different question answered on the budget/ranking figures, not here. This measures only whether
the per-CVE likelihood ordering gets better.

    export PATH=... ; python3 scanner_count.py
"""

import collections
import csv
import glob
import os
import sys

import numpy as np
from scipy.stats import spearmanr
from sklearn.model_selection import GroupKFold

import likelihood as L

HERE = os.path.dirname(os.path.abspath(__file__))

# Scanner configurations, in the order a defender would add them. Each is a cumulative set.
CONFIGS = [
    ("1: OpenVAS", {"openvas"}),
    ("2: + Nessus", {"openvas", "nessus"}),
    ("3: + Qualys", {"openvas", "nessus", "qualys"}),
]
FIXED_TEST_SCANNER = "openvas"   # the test population present in every configuration


def load_corpus():
    """Every non-Log, unauthenticated finding, deduplicated by (host, nvt_name), with scanner.

    Same file selection and dedup rule as ``likelihood.findings`` so the OpenVAS-only
    configuration reproduces the published headline, but the scanner column is kept so the
    corpus can be filtered.
    """
    rows, seen = [], set()
    for path in sorted(glob.glob(os.path.join(HERE, "processed", "findings_*.csv"))):
        name = os.path.basename(path)
        if "_auth" in name or "_patched" in name:
            continue
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("threat") == "Log":
                    continue
                key = (r.get("host", ""), r.get("nvt_name", ""))
                if key in seen:
                    continue
                seen.add(key)
                rows.append(r)
    return rows


def scored(rows, epss):
    """Attach (EPSS target, CVE) to each finding that has one; drop the rest."""
    out = []
    for r in rows:
        y, c = L.target_for(r, epss)
        if y is not None:
            out.append((r, y, c))
    return out


def run_config(all_rows, epss, scanners, test_scanner, n_splits=5):
    """Spearman of the surrogate on the fixed test population, trained on `scanners`.

    Returns (rho_pooled, per_fold_rhos, n_train_rows, n_test_rows, n_test_cves) or None if the
    configuration contributes no new scanner present in the corpus (e.g. Qualys not merged yet).
    """
    present = {r.get("scanner", "").lower() for r in all_rows}
    if not scanners & present:
        return None
    # Missing scanners are simply absent; the configuration is still valid on what exists.
    corpus = [r for r in all_rows if r.get("scanner", "").lower() in scanners]
    L.contextualise(corpus)                       # within-host context from THIS scanner set
    labelled = scored(corpus, epss)
    if not labelled:
        return None

    test = [(r, y, c) for (r, y, c) in labelled
            if r.get("scanner", "").lower() == test_scanner]
    if len(test) < 30:
        return None
    test_cves = np.array([c for _, _, c in test])
    y_test = np.log10(np.maximum(np.array([y for _, y, _ in test]), L.FLOOR))

    k = min(n_splits, len(set(test_cves)))
    gkf = GroupKFold(n_splits=k)
    idx = np.arange(len(test))
    oof = np.full(len(test), np.nan)
    per_fold = []
    n_train_last = 0
    for tr_i, te_i in gkf.split(idx, groups=test_cves):
        held = set(test_cves[te_i])
        # Train on every row of the configuration whose target CVE is not being tested.
        train = [(r, y) for (r, y, c) in labelled if c not in held]
        n_train_last = len(train)
        Xtr = L.build_matrix([r for r, _ in train])
        ytr = np.log10(np.maximum(np.array([y for _, y in train]), L.FLOOR))
        m = L.model().fit(Xtr, ytr)
        Xte = L.build_matrix([test[i][0] for i in te_i])
        p = m.predict(Xte)
        oof[te_i] = p
        if len(set(y_test[te_i])) > 1:
            rho_f = spearmanr(y_test[te_i], p).statistic
            if rho_f == rho_f:
                per_fold.append(rho_f)
    rho = spearmanr(y_test, oof).statistic
    rho = 0.0 if np.isnan(rho) else rho
    return rho, per_fold, n_train_last, len(test), len(set(test_cves))


def main():
    epss = L.epss_lookup()
    all_rows = load_corpus()
    present = collections.Counter(r.get("scanner", "").lower() for r in all_rows)
    print("corpus scanners   :", dict(present))

    # Severity baseline on the fixed test population (constant across configurations).
    base_rows = [r for r in all_rows if r.get("scanner", "").lower() == FIXED_TEST_SCANNER]
    L.contextualise(base_rows)
    base = scored(base_rows, epss)
    yb = np.log10(np.maximum(np.array([y for _, y, _ in base]), L.FLOOR))
    sev = np.array([float(r.get("severity") or 0) for r, _, _ in base])
    sev_rho = spearmanr(yb, sev).statistic
    print(f"fixed test        : {len(base)} OpenVAS CVE-bearing findings "
          f"({len({c for _,_,c in base})} CVEs)")
    print(f"severity baseline : Spearman {sev_rho:.3f}  (constant reference line)\n")

    print(f"  {'configuration':16s} {'Spearman':>9} {'fold mean±sd':>14} "
          f"{'train rows':>11} {'test rows':>10}")
    print("  " + "-" * 66)
    results = {}
    for label, scanners in CONFIGS:
        out = run_config(all_rows, epss, scanners, FIXED_TEST_SCANNER)
        if out is None:
            print(f"  {label:16s} {'--':>9}   (scanner not in corpus yet)")
            continue
        rho, folds, ntr, nte, ncve = out
        fm = f"{np.mean(folds):.3f}±{np.std(folds):.3f}" if folds else "    -"
        print(f"  {label:16s} {rho:8.3f} {fm:>14} {ntr:11d} {nte:10d}")
        results[label] = rho
    print()
    keys = [k for k, _ in CONFIGS if k in results]
    if len(keys) >= 2:
        d = results[keys[1]] - results[keys[0]]
        print(f"  1 -> 2 scanners : Spearman {results[keys[0]]:.3f} -> {results[keys[1]]:.3f} "
              f"(Δ {d:+.3f})")
        print("  Interpretation: a positive Δ means the added scanner's training rows and the")
        print("  richer per-host context improve the EPSS ordering on the same OpenVAS test;")
        print("  a Δ near zero (within the fold sd) means the extra scanner does not help the")
        print("  surrogate, which is itself a reportable, falsifiable result.")


if __name__ == "__main__":
    main()
