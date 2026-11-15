#!/usr/bin/env python3
"""Train the likelihood surrogate to rank, rather than to predict, and see whether it matters.

The surrogate is fitted with squared error on `log10(EPSS)` and reported with Spearman. Those
are not the same goal. Squared error cares how far an estimate is from a value; Spearman cares
only whether the order is right. Two findings whose true scores are 0.90 and 0.85 are ordered
wrongly by estimates of 0.50 and 0.55, and squared error sees a pair of equally mediocre
guesses rather than a mistake. Training against the metric that is reported is the textbook
correction, and this measures whether the correction buys anything here.

THE METHOD, AND WHY IT IS THIS ONE

Two rankers are compared against the pointwise regressor. The first is XGBoost's LambdaMART,
which is what the term normally means: `rank:ndcg` with boosted trees, query groups, and
gradients weighted towards the top of each list. The second is the pairwise transform, which
needs nothing beyond scikit-learn and isolates the objective from the learner.

THE QUERY GROUP, WHICH THIS PROBLEM DID NOT HAVE

Learning to rank assumes documents belong to queries and are ordered within one. Nothing in
this pipeline had a query: findings were ranked in a single global heap. The host is the
natural one -- an analyst asks what to fix on a machine, and the plan is consumed a machine at
a time -- so the host is the qid here. That choice is itself a finding: a global ordering is
not what the output is used for.

For the pairwise transform, for a pair of findings i and j with different targets,
the difference of their feature vectors is a training example labelled with the sign of the
difference of their targets. A classifier fitted on those differences scores a single finding
by `w . x`, and that score is the ranking. This is RankNet's objective without its network, it
is old, and it is a legitimate learning-to-rank method rather than a way of avoiding the term.

Pairs are sampled rather than enumerated: 363 findings make 65,703 pairs, most of them between
two items whose targets differ by nothing worth learning. Pairs are drawn only where the
targets differ by at least `--min-gap` in log space, which keeps the classifier from spending
its capacity separating 0.0011 from 0.0012.

WHAT IS HELD CONSTANT

The features, the target, and the fold assignment are identical to the pointwise model's, and
both are scored by the same Spearman under the same CVE-grouped split. Only the objective
differs, so a difference in the result is attributable to it. Where the two use different
learners -- a linear model on feature differences against a gradient-boosted tree -- that is
stated rather than hidden, and a pointwise linear model is reported as the third row so the
comparison does not confound the objective with the hypothesis class.

    python3 rank_objective.py --findings 'processed/findings_*2.csv'
"""

import argparse
import csv
import glob
import json
import os
import sys

import numpy as np
from scipy.stats import spearmanr
from sklearn.linear_model import LogisticRegression, Ridge
from sklearn.model_selection import GroupKFold

try:
    from xgboost import XGBRanker, XGBRegressor
except ImportError:
    XGBRanker = XGBRegressor = None

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


def sample_pairs(y, rng, n_pairs, min_gap):
    """Index pairs whose targets differ enough to carry an ordering worth learning."""
    n = len(y)
    out = []
    attempts = 0
    while len(out) < n_pairs and attempts < n_pairs * 40:
        attempts += 1
        i, j = rng.integers(0, n, 2)
        if i == j or abs(y[i] - y[j]) < min_gap:
            continue
        out.append((i, j))
    return out


def fit_pairwise(Z, y, rng, n_pairs, min_gap, seed=0):
    pairs = sample_pairs(y, rng, n_pairs, min_gap)
    if len(pairs) < 50:
        return None
    # Both orderings of every pair, so the classifier cannot learn a constant.
    diffs, labels = [], []
    for i, j in pairs:
        diffs.append(Z[i] - Z[j]); labels.append(1 if y[i] > y[j] else 0)
        diffs.append(Z[j] - Z[i]); labels.append(1 if y[j] > y[i] else 0)
    clf = LogisticRegression(max_iter=2000, C=1.0, random_state=seed)
    clf.fit(np.asarray(diffs), np.asarray(labels))
    return clf


def ndcg_at(scores, grades, qid, k):
    """Mean NDCG@k over query groups, with the usual 2^g - 1 gain.

    Reported beside Spearman because the two ask different questions and only one of them
    matches how the output is used. Spearman grades the whole pool at once and weights the
    300th place as heavily as the 3rd; a remediation plan is executed a host at a time and
    stops after a handful of jobs. A ranker trained to order within a host and then measured
    across every host at once is being graded on a task it was not set.
    """
    out = []
    for q in np.unique(qid):
        sel = qid == q
        if sel.sum() < 2:
            continue
        g = grades[sel].astype(float)
        order = np.argsort(-scores[sel], kind="stable")
        gains = (2 ** g[order] - 1)[:k]
        ideal = (2 ** np.sort(g)[::-1] - 1)[:k]
        discount = 1.0 / np.log2(np.arange(2, len(gains) + 2))
        idiscount = 1.0 / np.log2(np.arange(2, len(ideal) + 2))
        denom = float((ideal * idiscount).sum())
        if denom <= 0:
            continue
        out.append(float((gains * discount).sum()) / denom)
    return float(np.mean(out)) if out else float("nan")


def rho_of(y, pred):
    r = spearmanr(y, pred).statistic
    return 0.0 if np.isnan(r) else r


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", action="append", metavar="CSV_OR_GLOB", default=None)
    ap.add_argument("--context", action="store_true",
                    help="add the within-host comparative features; measured as harmful, "
                         "kept so the result can be reproduced")
    ap.add_argument("--pairs", type=int, default=20000, metavar="N")
    ap.add_argument("--min-gap", type=float, default=0.30, metavar="D",
                    help="smallest difference in log10(EPSS) worth learning from")
    ap.add_argument("-o", "--out", metavar="JSON",
                    default=os.path.join(HERE, "figures", "rank_objective.json"))
    args = ap.parse_args()
    patterns = args.findings or ["processed/findings_*2.csv"]

    rows = load(patterns)
    # Off unless asked for. These features were measured and they hurt: NDCG@5 for the
    # boosted tree fell from 0.616 to 0.534, most likely because the target is global while a
    # within-host rank is local and means something different on each machine. The switch
    # stays so the negative result can be reproduced.
    if args.context:
        L.contextualise(rows)
    epss = L.epss_lookup()
    scored = [(r,) + L.target_for(r, epss) for r in rows]
    scored = [(r, y, c) for r, y, c in scored if y is not None]
    if len(scored) < 60:
        sys.exit("too few scored findings to compare objectives.")

    X = L.build_matrix([r for r, _, _ in scored])
    y = np.log10(np.maximum(np.array([v for _, v, _ in scored]), L.FLOOR))
    groups = np.array([c for _, _, c in scored])
    folds = min(5, len(set(groups)))
    cv = GroupKFold(n_splits=folds)
    rng = np.random.default_rng(0)

    print(f"corpus            : {len(scored)} scored findings, {len(set(groups))} CVEs, "
          f"{folds} folds")
    print(f"within-host features: {'on' if args.context else 'off'}")
    print(f"pairs per fold    : up to {args.pairs}, minimum gap {args.min_gap} in log space\n")

    names = ["pointwise, boosted tree", "pointwise, linear", "pairwise, linear"]
    if XGBRanker is not None:
        # Two xgboost rows, not one. Comparing a scikit-learn regressor against an xgboost
        # ranker confounds the library with the objective, and an earlier reading of this
        # table treated the gap as "sklearn beats xgboost" when what it showed was
        # "a regressor beats a ranker on a rank-correlation metric computed globally".
        # XGBRegressor on the same target isolates the library.
        names.append("pointwise, XGBRegressor")
        names.append("LambdaMART, rank:ndcg")
    else:
        print("  xgboost not importable; LambdaMART row omitted\n")
    preds = {name: np.zeros(len(y)) for name in names}
    # Relevance has to be graded and non-negative for rank:ndcg. EPSS is continuous, so it is
    # cut into five bands by quantile: the bands carry the ordering the metric needs without
    # inventing thresholds of our own.
    grades = np.searchsorted(np.quantile(y, [0.2, 0.4, 0.6, 0.8]), y)
    # qid has to be an unsigned integer for XGBoost, so hosts are mapped to ids. Sorted by
    # name first, so the ids are stable across runs and a fold's grouping does not depend on
    # the order the CSVs happened to be read in.
    host_names = sorted({r["host"] for r, _, _ in scored})
    host_id = {h: i for i, h in enumerate(host_names)}
    hosts = np.array([host_id[r["host"]] for r, _, _ in scored], dtype=np.uint32)

    for train, test in cv.split(X, y, groups):
        # Text and categories are vectorised inside the fold, exactly as the pointwise model
        # does it, so the ranker gets no information the regressor does not have.
        pre = L.make_pre()
        Ztr = np.asarray(pre.fit_transform(X[train]), dtype=float)
        Zte = np.asarray(pre.transform(X[test]), dtype=float)

        preds["pointwise, boosted tree"][test] = (
            L.model().fit(X[train], y[train]).predict(X[test]))
        preds["pointwise, linear"][test] = (
            Ridge(alpha=1.0).fit(Ztr, y[train]).predict(Zte))
        clf = fit_pairwise(Ztr, y[train], rng, args.pairs, args.min_gap)
        if clf is None:
            sys.exit("not enough separated pairs in a fold; lower --min-gap.")
        preds["pairwise, linear"][test] = Zte @ clf.coef_.ravel()

        if XGBRegressor is not None:
            reg = XGBRegressor(n_estimators=300, learning_rate=0.08, max_leaves=15,
                               reg_lambda=1.0, tree_method="hist", random_state=0,
                               verbosity=0)
            reg.fit(Ztr, y[train])
            preds["pointwise, XGBRegressor"][test] = reg.predict(Zte)

        if XGBRanker is not None:
            # XGBoost requires the rows sorted by query group, so both halves are reordered
            # and the predictions put back where they came from.
            otr = np.argsort(hosts[train], kind="stable")
            ote = np.argsort(hosts[test], kind="stable")
            ranker = XGBRanker(objective="rank:ndcg", n_estimators=300,
                               learning_rate=0.08, max_leaves=15, tree_method="hist",
                               lambdarank_pair_method="mean", random_state=0,
                               verbosity=0)
            ranker.fit(Ztr[otr], grades[train][otr], qid=hosts[train][otr])
            out = np.empty(len(test))
            out[ote] = ranker.predict(Zte[ote])
            preds["LambdaMART, rank:ndcg"][test] = out

    severity = np.array([float(r.get("severity") or 0) for r, _, _ in scored])
    preds["severity alone"] = severity

    print(f"  {'model':28s} {'Spearman':>9} {'NDCG@5':>8} {'NDCG@10':>8}")
    print("  " + "-" * 58)
    results = {}
    for name, p in preds.items():
        r = rho_of(y, p)
        n5 = ndcg_at(p, grades, hosts, 5)
        n10 = ndcg_at(p, grades, hosts, 10)
        results[name] = {"spearman": round(float(r), 4),
                         "ndcg@5": round(n5, 4), "ndcg@10": round(n10, 4)}
        print(f"  {name:28s} {r:8.3f} {n5:8.3f} {n10:8.3f}")

    # The comparison that isolates the objective is between the two linear rows: same
    # hypothesis class, same features, same folds, different loss. The boosted tree is the
    # model actually in the pipeline and is reported so the absolute level is visible.
    def gap(a, b, metric):
        return results[a][metric] - results[b][metric]

    if "pointwise, XGBRegressor" in results:
        print("\n  library alone, same objective and target:")
        for m in ("spearman", "ndcg@5"):
            g = gap("pointwise, XGBRegressor", "pointwise, boosted tree", m)
            print(f"    {m:10s} {g:+.3f}   XGBRegressor against sklearn HistGB")

    print(f"\n  objective alone, tree against tree:")
    if "LambdaMART, rank:ndcg" in results:
        for m in ("spearman", "ndcg@5", "ndcg@10"):
            g = gap("LambdaMART, rank:ndcg", "pointwise, boosted tree", m)
            print(f"    {m:10s} {g:+.3f}")
        # The whole point of running both metrics. If the sign differs between them the
        # answer is not which model is better but which question is being asked, and the
        # question a plan poses is the per-host one.
        signs = {m: gap("LambdaMART, rank:ndcg", "pointwise, boosted tree", m)
                 for m in ("spearman", "ndcg@5")}
        if signs["spearman"] * signs["ndcg@5"] < 0:
            print("\n  The two metrics disagree about which model is better. Spearman grades")
            print("  one global ordering; NDCG@5 grades the top of each host's list, which is")
            print("  what an analyst works through. Report both and say which the plan uses.")
        else:
            print("\n  Both metrics agree, so the choice between them does not decide this.")
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump(results, open(args.out, "w", encoding="utf-8"), indent=1)
    print(f"\n  wrote {args.out}")


if __name__ == "__main__":
    main()
