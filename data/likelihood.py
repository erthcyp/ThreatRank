#!/usr/bin/env python3
"""Exploit likelihood L for every finding, including the ones with no CVE.

This is the first script in the project that produces a score rather than a measurement
about the data. It implements the upper head of the two-head design:

    has a CVE with a published EPSS score   ->  that score, no model involved
    anything else                           ->  a learned surrogate

The second case is the contribution. EPSS covers catalogued vulnerabilities; a default
credential, an end-of-life service or a weak TLS configuration has no CVE, therefore no EPSS
entry, and every published prioritisation scheme that starts from EPSS leaves it unscored.
The surrogate learns EPSS from what a scanner reports, so that those findings receive a
likelihood on the same scale rather than none at all.

WHY A REGRESSOR AND NOT A CLASSIFIER

R = L x C needs L to be a number. A class label would force us to decide what "high" is
worth, and a number this project invented is not something it can then grade itself against.
A regressor also keeps the ordering: 0.02 and 0.03 are close, which a classifier cannot
express. And the surrogate's output has to sit on the same scale as real EPSS, or the two
halves of this head cannot be ranked in one list.

EPSS itself is a classifier's probability, trained on whether exploitation was observed.
That route is closed to us: the only observation label available here is CISA KEV, and KEV
is what the ranking is graded against. Training on it would be leakage.

THE TARGET IS LOGGED, AND THAT IS NOT COSMETIC

Measured on this corpus: EPSS has median 0.0049 and mean 0.066, with 70.6% of scores below
0.01 and a thin tail reaching 0.99999. A squared-error model fitted to the raw score can
reach a low error by predicting the mean everywhere, which would separate nothing and still
look like it worked. Training on log10(EPSS) spends the model's capacity on the range where
the findings actually are. Predictions are inverted before use, so L stays a probability.

For the same reason the headline metric is Spearman rather than an error: the question is
whether the ordering is right, not whether the value is close.

REGISTERED IN ADVANCE

**The surrogate is worth building only if Spearman reaches 0.3 under the CVE split,
not merely under the host split, and beats both baselines below.** If it does not, findings without a CVE are ranked on
consequence alone, and that is a reportable result rather than a failure.

    python3 likelihood.py                 evaluate the surrogate
    python3 likelihood.py --score OUT     also write L for every finding to OUT
"""

import argparse
import collections
import csv
import glob
import os
import sys
import warnings

import numpy as np

from fix_actions import product_of
from scipy.stats import spearmanr
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingRegressor
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import GroupKFold, LeaveOneGroupOut, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))

FLOOR = 1e-5          # EPSS never reports zero; this only guards log10 against a bad row
THRESHOLD = 0.30      # registered before the first run


def epss_lookup():
    path = os.path.join(HERE, "epss_lookup.csv")
    if not os.path.exists(path):
        sys.exit("no epss_lookup.csv. Run: python3 fetch_labels.py --epss")
    with open(path, encoding="utf-8") as fh:
        rows = csv.DictReader(line for line in fh if not line.startswith("#"))
        return {r["cve"]: float(r["epss"]) for r in rows}


def cves_of(row):
    return [c.strip() for c in (row.get("cves") or "").split(";")
            if c.strip().startswith("CVE-")]


def port_number(field):
    """'80/tcp' -> 80. 'general/tcp' -> 0, marking a finding with no listening port."""
    head = (field or "").split("/")[0]
    return int(head) if head.isdigit() else 0


def findings():
    """Deduplicated, non-Log findings from the unauthenticated reports.

    Same corpus rule as every other measurement here: the credentialed rescan and the
    post-patch rescan are excluded because they repeat one machine, and rows repeating a
    finding already seen on the same host are not independent observations.
    """
    rows, seen = [], set()
    for path in sorted(glob.glob(os.path.join(HERE, "processed", "findings_*.csv"))):
        name = os.path.basename(path)
        if "_auth" in name or "_patched" in name:
            continue
        # Qualys is the independent peer of Experiment 4, not a training input (the paper says
        # so); its files arrived after this loop was written and were read in by the glob.
        if "_qualys" in name:
            continue
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


def target_for(row, epss):
    """The worst case any of a finding's CVEs admits, and the CVE that supplied it.

    Worst case rather than mean, matching the rule already used elsewhere in this project:
    a finding is as exploitable as its most exploitable component. The CVE is returned too
    because it is the grouping key for the second split; see evaluate().
    """
    scored = [(epss[c], c) for c in cves_of(row) if c in epss]
    if not scored:
        return None, None
    value, cve = max(scored)
    return value, cve


# Columns are addressed by position because pandas is not installed on this machine. This
# order is the contract between build_matrix and make_pre.
COLS = ["text", "family", "solution", "threat", "severity", "qod", "port", "is_host_level"]
TXT, CAT, NUM = 0, [1, 2, 3], [4, 5, 6, 7, 8, 9, 10, 11]


def contextualise(rows):
    """Annotate each finding with how it compares to the others on its own host.

    Every feature up to here describes a check in isolation: what it is called, what family it
    belongs to, how severe it is. None of them says whether this finding stands out among the
    others on the same machine, and that is the question a per-host ranking asks. Measured on
    this corpus, the scanner's raw severity beats every model we fitted at NDCG@5 within a
    host while losing to them badly on a global Spearman -- which is what a signal that orders
    within a group looks like when it is competing against estimates that do not.

    This is not leakage. The values are computed from inputs only -- severity, host, port,
    product -- and never from a target. It is also the deployment condition rather than a
    convenience: a scan arrives whole, so every finding on a host is in hand at the moment any
    of them is scored.
    """
    by_host = collections.defaultdict(list)
    for r in rows:
        by_host[r.get("host", "")].append(r)
    for host, group in by_host.items():
        sev = [float(r.get("severity") or 0) for r in group]
        mean = sum(sev) / max(len(sev), 1)
        order = sorted(range(len(group)), key=lambda i: sev[i])
        rank = [0.0] * len(group)
        for position, i in enumerate(order):
            rank[i] = position / max(len(group) - 1, 1)
        products = collections.Counter(product_of(r["nvt_name"]) for r in group)
        ports = collections.Counter(r.get("port", "") for r in group)
        for i, r in enumerate(group):
            r["_sev_rank"] = rank[i]
            r["_sev_gap"] = sev[i] - mean
            r["_product_share"] = products[product_of(r["nvt_name"])] / len(group)
            r["_port_share"] = ports[r.get("port", "")] / len(group)
    return rows


def featurise(row):
    def num(field):
        try:
            return float(row.get(field) or 0)
        except ValueError:
            return 0.0
    port_field = row.get("port", "")
    return [
        # Title and description together. Until 29 September the text field was the title
        # alone, which names a product and a version range and almost never says what the
        # weakness allows. The description does: the scanner writes "may allow an attacker
        # to execute arbitrary code" or "an attacker could obtain the uptime of the remote
        # host" in the same field. Models built on titles alone could not separate a
        # denial of service from a privilege escalation and fell back to the majority
        # class; this is the feature that was missing rather than a deficiency of the idea.
        # Empty for corpora parsed before the column existed, which degrades to the old
        # behaviour rather than failing.
        ((row.get("nvt_name") or "") + " " + (row.get("description") or "")).strip(),
        row.get("nvt_family") or "",
        row.get("solution_type") or "",
        row.get("threat") or "",
        num("severity"),
        num("qod"),
        port_number(port_field),
        1.0 if str(port_field).startswith("general/") else 0.0,
        # Within-host comparisons, zero when contextualise() has not been run so that a
        # caller which skips it degrades to the previous feature set rather than failing.
        num("_sev_rank"),
        num("_sev_gap"),
        num("_product_share"),
        num("_port_share"),
    ]


def build_matrix(rows):
    return np.array([featurise(r) for r in rows], dtype=object)


def make_pre():
    """Every transform here is fitted inside the fold; cross_val_predict guarantees it."""
    return ColumnTransformer(
        [("txt", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2,
                                 max_features=3000, sublinear_tf=True), TXT),
         ("cat", OneHotEncoder(handle_unknown="ignore"), CAT),
         ("num", Pipeline([("cast", FunctionTransformer(lambda a: np.asarray(a, float))),
                           ("sc", StandardScaler())]), NUM)],
        remainder="drop", sparse_threshold=0.0)


def model():
    return Pipeline([("pre", make_pre()),
                     ("reg", HistGradientBoostingRegressor(
                         max_iter=300, learning_rate=0.08, max_leaf_nodes=15,
                         l2_regularization=1.0, random_state=0))])


def report_folds(hosts):
    counts = collections.Counter(hosts)
    print("    fold sizes:", ", ".join(str(v) for _, v in counts.most_common()))
    tiny = sum(1 for v in counts.values() if v < 5)
    if tiny:
        print(f"    {tiny} of {len(counts)} hosts contribute fewer than 5 rows; a fold that "
              f"small measures nothing on its own")


def evaluate(rows, epss):
    labelled = [(r,) + target_for(r, epss) for r in rows]
    train = [(r, y, c) for r, y, c in labelled if y is not None]
    unscored = [r for r, y, _ in labelled if y is None]

    print(f"corpus            : {len(rows)} findings on "
          f"{len({r['host'] for r in rows})} hosts, Log excluded, deduplicated")
    print(f"  with an EPSS score : {len(train)}   <- the surrogate trains on these")
    print(f"  without one        : {len(unscored)}   <- the surrogate exists for these")
    if len(train) < 30:
        sys.exit("too few scored findings to evaluate. Refresh the snapshot first:\n"
                 "  python3 fetch_labels.py --epss")

    no_cve = sum(1 for r in unscored if not cves_of(r))
    print(f"      of those, {no_cve} carry no CVE at all and "
          f"{len(unscored) - no_cve} cite a CVE with no published score")

    X = build_matrix([r for r, _, _ in train])
    y_raw = np.array([y for _, y, _ in train])
    y = np.log10(np.maximum(y_raw, FLOOR))
    by_host = np.array([r["host"] for r, _, _ in train])
    by_cve = np.array([c for _, _, c in train])

    print(f"\ntarget            : log10(EPSS), median {np.median(y_raw):.5f}, "
          f"mean {y_raw.mean():.5f}, max {y_raw.max():.5f}")
    report_folds(by_host)

    # Two splits, because one of them is not enough here. Leave-one-host-out holds out a
    # machine, but the same check title, carrying the same CVE and therefore the same
    # target, appears on other machines: measured on this corpus, 7 of 11 hosts share 100%
    # of their CVEs with the training folds. A model can score well there by memorising the
    # title. Grouping by the CVE that supplied the target closes that route, and the gap
    # between the two numbers is how much of the first was memory.
    print("evaluation        : two splits. Every transform is fitted inside the fold.")
    print("                    by host, and by the CVE the target came from")
    print("headline metric   : Spearman, because the ordering is what the score is for\n")

    pred = cross_val_predict(model(), X, y, groups=by_host, cv=LeaveOneGroupOut())
    n_cve = len(set(by_cve))
    pred_cve = cross_val_predict(model(), X, y, groups=by_cve,
                                 cv=GroupKFold(n_splits=min(5, n_cve)))

    # Two baselines. The first is the trap this design is built to avoid: on a target where
    # 70% of values sit below 0.01, a constant is hard to beat on error and useless to rank.
    const = np.full_like(y, np.median(y))
    severity = np.array([float(r.get("severity") or 0) for r, _, _ in train])

    results = [("surrogate, host split", pred),
               ("surrogate, CVE split", pred_cve),
               ("predict the median", const),
               ("severity alone", severity)]
    print(f"  {'model':24s} {'Spearman':>9} {'MAE on EPSS':>13}")
    print("  " + "-" * 50)
    best = None
    for name, p in results:
        rho = spearmanr(y, p).statistic
        rho = 0.0 if np.isnan(rho) else rho
        mae = (np.mean(np.abs(np.clip(10 ** p, 0, 1) - y_raw))
               if name != "severity alone" else float("nan"))
        mae_text = f"{mae:12.4f}" if mae == mae else "           -"
        print(f"  {name:24s} {rho:8.3f} {mae_text}")
        if name == "surrogate, CVE split":
            best = rho
        if name == "severity alone":
            floor = rho
    print(f"\n  {n_cve} distinct CVEs supplied the targets, grouped into "
          f"{min(5, n_cve)} folds")

    # The registered condition has two parts and both bind. A threshold checked without the
    # baseline beside it is how this project once reported a failure as a success.
    print()
    if best < THRESHOLD:
        print(f"VERDICT: Spearman {best:.3f} is below the registered threshold of "
              f"{THRESHOLD}.")
        print("Report-level features do not predict EPSS well enough to stand behind.")
        print("Findings without a CVE are ranked on consequence alone, which is the fallback")
        print("stated in advance, and this is a result rather than a failure.")
    elif best <= floor:
        print(f"VERDICT: Spearman {best:.3f} clears the threshold of {THRESHOLD} but does "
              f"NOT beat")
        print(f"the severity column at {floor:.3f}. The registered condition was both, and")
        print("the second one is the one that matters: a gradient boosted model over the")
        print("title, the family and six numeric fields orders findings no better than the")
        print("one number the scanner already prints. On this evidence the surrogate is not")
        print("justified, and a finding with no CVE should take its likelihood from severity")
        print("until more hosts change the answer.")
    else:
        print(f"VERDICT: Spearman {best:.3f} clears the threshold of {THRESHOLD} and beats")
        print(f"severity alone at {floor:.3f}. The surrogate earns its place: report-level")
        print("features carry ordering information that the severity column does not.")
    return best


def write_scores(rows, epss, out):
    """L for every finding: the published score where one exists, the surrogate elsewhere.

    The surrogate is fitted on every scored finding here, because this is production of a
    score rather than measurement of one. The number that may be reported comes from
    evaluate(), which never lets a model see the host it is scoring.
    """
    labelled = [(r,) + target_for(r, epss) for r in rows]
    train = [(r, y) for r, y, _ in labelled if y is not None]
    fitted = model().fit(build_matrix([r for r, _ in train]),
                         np.log10(np.maximum([y for _, y in train], FLOOR)))

    rest = [r for r, y, _ in labelled if y is None]
    predicted = (np.clip(10 ** fitted.predict(build_matrix(rest)), 0.0, 1.0)
                 if rest else np.array([]))

    by_id = {id(r): v for r, v in zip(rest, predicted)}
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["host", "nvt_name", "cves", "likelihood", "source"])
        for r, y, _ in labelled:
            if y is None:
                w.writerow([r["host"], r["nvt_name"], r.get("cves", ""),
                            f"{by_id[id(r)]:.6f}", "surrogate"])
            else:
                w.writerow([r["host"], r["nvt_name"], r.get("cves", ""),
                            f"{y:.6f}", "epss"])
    print(f"\nwrote {out}: {len(labelled)} findings, "
          f"{len(train)} from EPSS and {len(rest)} from the surrogate")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--score", metavar="OUT",
                    help="also write L for every finding to this CSV")
    args = ap.parse_args()

    epss = epss_lookup()
    rows = findings()
    evaluate(rows, epss)
    if args.score:
        write_scores(rows, epss, args.score)


if __name__ == "__main__":
    main()
