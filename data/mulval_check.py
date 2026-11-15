#!/usr/bin/env python3
"""The impact classifier graded where its answers are used: inside the attack graph.

`impact.py` grades the classifier on labels, field by field, against the CVSS vectors NVD
publishes. That says how often it names the right impact. It does not say whether a wrong
answer matters, because the classifier's output is never read directly: it becomes the
`privEscalation` or `dos` a finding carries into MulVAL, and only what MulVAL derives from
that reaches a consequence score. A label error on a finding that reaches nothing either way
costs nothing; one that grants code execution on the database host costs everything.

THE PROTOCOL

On the hosts the topology declares, take every finding that has a published vector, so the
correct answer is known, and build three MulVAL inputs that differ only in the consequence
those findings carry:

    published   what NVD's vector says. The answer key.
    model       the classifier's estimate, from a model that never saw these hosts or any
                CVE whose vector it is being graded on
    constant    privEscalation for every finding, the value the classifier replaced

Findings with no published vector take the assumed constant in all three, so they cannot
move the comparison. Range is the published one in all three, because the classifier does
not predict it (see impact.py). Every input is written by findings_to_mulval.py, so the three
graphs cannot differ in anything but the consequence.

WHAT IS COMPARED

Per finding, the consequence C that consequence.py would score it with, read off each graph.
Per graph, the set of facts MulVAL derives and whether the goal is among them. The classifier
earns its place only if its graph is closer to the published one than the constant's is.

REGISTERED RULE, fixed before the first run: the model must leave strictly fewer findings
with a C different from the published graph than the constant does. Tying the constant means
the estimate changes nothing the graph can see, and is reported as a failure.

WHAT THIS IS NOT

MulVAL is not an answer key, and this does not verify the graph. The published graph is the
reference here only because its inputs are NIST's; whether its chain is walkable in the lab is
a separate question this script cannot answer.

    python3 mulval_check.py                      # generate, run MulVAL, compare
    python3 mulval_check.py --compare-only       # compare graphs produced elsewhere

MulVAL and XSB must be on PATH to run the graphs (see ../mulval/README.md). Without them the
three inputs are written and the commands to run them printed, so the graphs can be built
on a machine that has MulVAL and compared here with --compare-only.
"""

import argparse
import collections
import csv
import json
import os
import shutil
import subprocess
import sys

import consequence as C
import findings_to_mulval as F

HERE = os.path.dirname(os.path.abspath(__file__))
ARMS = ("published", "model", "constant")
# Impact values that findings_to_mulval.consequence_from_impact maps to each consequence.
# The estimate CSV carries impact metrics, not consequences, so each arm's consequence is
# written back in that form rather than teaching the adapter a second input format.
AS_IMPACT = {"privEscalation": ("HIGH", "NONE", "NONE"),
             "dos": ("NONE", "NONE", "HIGH")}


def in_scope(paths, topology, cvss_map):
    """Lab findings the adapter would emit and NVD describes, with the published consequence.

    The adapter's own filters are applied here so the graded set is exactly the set of
    findings whose published consequence the published graph carries.
    """
    hosts = topology["hosts"]
    rows, seen = [], set()
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("threat") == "Log" or r["host"] not in hosts:
                    continue
                port, _ = F.split_port(r.get("port", ""))
                if port is not None and r.get("port") not in hosts[r["host"]].get("services", {}):
                    continue
                key = F.row_key(r)
                if key in seen:
                    continue
                seen.add(key)
                _, cons = F.cvss_properties(r, cvss_map)
                if cons:
                    rows.append({**r, "published": cons})
    return rows


def estimate(scope, topology, nvd):
    """The classifier's consequence for each in-scope finding, trained without them.

    Training excludes every row on a topology host, and every row whose vector comes from a
    CVE an in-scope finding cites. The first keeps the evaluated machines out of training,
    the second stops the model recalling a vector it was shown under another host.
    """
    import numpy as np
    import impact as I
    import likelihood as L

    held_cves = {c.strip() for r in scope for c in (r.get("cves") or "").split(";")
                 if c.strip().startswith("CVE-")}
    train = []
    for r in I.load(["processed/findings_*2.csv"]):
        if r["host"] in topology["hosts"]:
            continue
        v, cve = I.vector_for(r, nvd)
        if v is None or cve in held_cves:
            continue
        train.append((r, v))
    print(f"model arm         : trained on {len(train)} findings, none on a lab host "
          f"and none citing a held-out CVE")
    if len(train) < 80:
        sys.exit("too few training rows left after holding out the lab; the model arm "
                 "would measure nothing.")

    X = L.build_matrix([r for r, _ in train])
    Xs = L.build_matrix(scope)
    pred = {}
    for field in I.FIELDS:
        y = np.array([v.get(field) or "NONE" for _, v in train])
        pred[field] = I.model().fit(X, y).predict(Xs)
    out = []
    for i, _ in enumerate(scope):
        cons = F.consequence_from_impact(*(pred[f][i] for f in I.FIELDS))
        # All three NONE has no MulVAL counterpart. The pipeline gives such a finding the
        # assumed constant, so the model arm does the same rather than dropping the fact.
        out.append(cons or F.ASSUMED[1])
    return out


def write_arm(directory, scope, consequences, args):
    os.makedirs(directory, exist_ok=True)
    for name in ("VERTICES.CSV", "ARCS.CSV"):
        # A graph left from an earlier run would be compared against a new input.
        if os.path.exists(os.path.join(directory, name)):
            os.remove(os.path.join(directory, name))
    cmd = [sys.executable, os.path.join(HERE, "findings_to_mulval.py"),
           "--topology", args.topology, "-o", os.path.join(directory, "input.P")]
    for path in args.findings:
        cmd += ["--findings", path]
    if consequences is not None:
        est = os.path.join(directory, "estimates.csv")
        with open(est, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["host", "port", "nvt_name", "confidentiality", "integrity",
                        "availability", "source"])
            for r, cons in zip(scope, consequences):
                w.writerow([r["host"], r.get("port", ""), r["nvt_name"],
                            *AS_IMPACT[cons], "estimated"])
        cmd += ["--predicted", est, "--override-published"]
    done = subprocess.run(cmd, capture_output=True, text=True)
    if done.returncode:
        sys.exit(f"findings_to_mulval.py failed for {directory}:\n{done.stderr}")


def run_mulval(directory):
    subprocess.run(["graph_gen.sh", "input.P", "-v", "-p"], cwd=directory,
                   capture_output=True, text=True)
    if not os.path.exists(os.path.join(directory, "VERTICES.CSV")):
        sys.exit(f"graph_gen.sh left no VERTICES.CSV in {directory}. If XSB is not on PATH "
                 f"it says `xsb: not found` and exits quietly; see ../mulval/README.md.")


def read_arm(directory, topology, findings):
    """Per-finding C and the derived facts, scored the way consequence.py scores them."""
    vertices, edges = C.read_graph(directory)
    goals = C.goal_vertex(vertices, topology["goal"])
    dist = C.distances_to(goals, edges, vertices)
    leaves = C.finding_leaves(vertices)
    emitted = C.emitted_facts(directory)
    scores = {}
    for r in C.load_findings(findings, topology):
        key = (r["atom"], r["vuln_id"])
        if key not in emitted:
            continue
        d = dist.get(leaves[key]) if key in leaves else None
        scores[(r["host"], r["nvt_name"])] = 0.0 if d is None else 1.0 / d
    facts = {vertices[v][0] for v in vertices if vertices[v][1] == "OR"}
    goal = any(vertices[g][0] in facts for g in goals)
    return scores, facts, goal, len(vertices)


def label_scores(truth, pred):
    labels = sorted(set(truth) | set(pred))
    f1s = []
    for lab in labels:
        tp = sum(t == lab and p == lab for t, p in zip(truth, pred))
        fp = sum(t != lab and p == lab for t, p in zip(truth, pred))
        fn = sum(t == lab and p != lab for t, p in zip(truth, pred))
        f1s.append(2 * tp / (2 * tp + fp + fn) if tp else 0.0)
    acc = sum(t == p for t, p in zip(truth, pred)) / len(truth)
    return acc, sum(f1s) / len(f1s)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", action="append", metavar="CSV")
    ap.add_argument("--topology", default=os.path.join(HERE, "topology_lab3.json"))
    ap.add_argument("--nvd", default=os.path.join(HERE, "cwe_map.json"))
    ap.add_argument("--work", default=os.path.join(HERE, "..", "mulval", "cases",
                                                   "lab3_check"), metavar="DIR",
                    help="one subdirectory per arm is written here")
    ap.add_argument("--compare-only", action="store_true",
                    help="skip generation and MulVAL; compare the graphs already in --work")
    ap.add_argument("-o", "--out", default=os.path.join(HERE, "figures",
                                                        "mulval_check.json"))
    args = ap.parse_args()
    args.findings = args.findings or [os.path.join(HERE, "processed",
                                                   "findings_openvas_b2.csv")]
    topology = json.load(open(args.topology, encoding="utf-8"))
    nvd = json.load(open(args.nvd, encoding="utf-8"))
    dirs = {arm: os.path.join(args.work, arm) for arm in ARMS}

    scope = in_scope(args.findings, topology, nvd)
    print(f"graded findings   : {len(scope)} on {len(topology['hosts'])} lab hosts, "
          f"each with a published consequence")
    truth = [r["published"] for r in scope]
    labels_path = os.path.join(args.work, "labels.json")

    if not args.compare_only:
        arms = {"published": None, "model": estimate(scope, topology, nvd),
                "constant": [F.ASSUMED[1]] * len(scope)}
        for arm, cons in arms.items():
            write_arm(dirs[arm], scope, cons, args)
        json.dump({arm: cons or truth for arm, cons in arms.items()},
                  open(labels_path, "w", encoding="utf-8"), indent=1)
        if not shutil.which("graph_gen.sh"):
            print(f"\ngraph_gen.sh is not on PATH. The three inputs are written; build the "
                  f"graphs with\n")
            for arm in ARMS:
                print(f"  (cd {dirs[arm]} && graph_gen.sh input.P -v -p)")
            print("\nthen rerun this script with --compare-only.")
            sys.exit(2)
        for arm in ARMS:
            print(f"running MulVAL    : {arm}")
            run_mulval(dirs[arm])

    try:
        labels = json.load(open(labels_path, encoding="utf-8"))
    except FileNotFoundError:
        sys.exit(f"no {labels_path}. Run once without --compare-only to write the inputs.")
    if len(labels["published"]) != len(scope) or labels["published"] != truth:
        sys.exit("the inputs in --work were written from different findings than these. "
                 "Regenerate them.")

    graphs = {arm: read_arm(dirs[arm], topology, args.findings) for arm in ARMS}
    ref_scores, ref_facts, ref_goal, _ = graphs["published"]

    print(f"\n  {'':10s} {'label acc':>9} {'macro-F1':>8} {'vertices':>8} {'goal':>5} "
          f"{'C wrong':>8} {'false reach':>11} {'lost reach':>10} {'facts +/-':>9}")
    results = {}
    for arm in ARMS:
        scores, facts, goal, n_vertices = graphs[arm]
        acc, f1 = label_scores(truth, labels[arm])
        common = set(scores) & set(ref_scores)
        wrong = [k for k in common if abs(scores[k] - ref_scores[k]) > 1e-9]
        false_reach = [k for k in common if scores[k] > 0 and ref_scores[k] == 0]
        lost_reach = [k for k in common if scores[k] == 0 and ref_scores[k] > 0]
        added, lost = facts - ref_facts, ref_facts - facts
        results[arm] = {"label_accuracy": round(acc, 4), "label_macro_f1": round(f1, 4),
                        "vertices": n_vertices, "goal_derived": goal,
                        "findings_compared": len(common), "c_wrong": len(wrong),
                        "false_reach": len(false_reach), "lost_reach": len(lost_reach),
                        "facts_added": sorted(added), "facts_lost": sorted(lost)}
        print(f"  {arm:10s} {acc:9.3f} {f1:8.3f} {n_vertices:8d} {'yes' if goal else 'NO':>5} "
              f"{len(wrong):8d} {len(false_reach):11d} {len(lost_reach):10d} "
              f"{'+' + str(len(added)) + '/-' + str(len(lost)):>9}")

    print(f"\n  compared over {results['published']['findings_compared']} findings, every "
          f"one the adapter emitted; C wrong counts any change from the published graph")
    for arm in ("model", "constant"):
        for kind in ("facts_added", "facts_lost"):
            for fact in results[arm][kind]:
                print(f"  {arm:8s} {'derives' if kind == 'facts_added' else 'loses  '} {fact}")

    m, c = results["model"]["c_wrong"], results["constant"]["c_wrong"]
    passed = m < c
    print(f"\n  registered rule   : model must leave fewer findings with a wrong C than the "
          f"constant")
    print(f"  model {m}, constant {c}: {'PASS' if passed else 'FAIL'}")
    if not passed:
        print("  The estimate changes nothing the graph can see, or changes it for the worse. "
              "The\n  label-level result in impact.py does not carry through to consequence.")

    results["passed"] = passed
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump(results, open(args.out, "w", encoding="utf-8"), indent=1)
    print(f"\n  wrote {args.out}")


if __name__ == "__main__":
    main()
