#!/usr/bin/env python3
"""Print what one pipeline stage produces, for the step-by-step demo in demo/.

Every live view calls the same functions the pipeline uses (prioritise.score), so the demo
cannot show a number the pipeline would not produce. Views marked RECORDED read results
committed in data/ because recomputing them takes minutes (model training) or needs XSB
(MulVAL); `./reproduce.sh` regenerates all of them.

    python3 demo/show.py parse | likelihood | impact | graph | risk
"""
import collections
import csv
import io
import json
import os
import sys
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
CALLER = os.getcwd()
sys.path.insert(0, DATA)
os.chdir(DATA)

GRAPH = "../mulval/cases/lab3/out"
TOPOLOGY = "topology_lab3.json"
FINDINGS = ["processed/findings_openvas_b2.csv"]


def recorded(what):
    print(f"[RECORDED] {what}\n")


def short(text, n):
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1] + "~"


def scored():
    """Findings with L, C and R, and the actions they group into (silences the model fit)."""
    import prioritise as P
    with redirect_stdout(io.StringIO()):
        kept, actions, _ = P.score(GRAPH, TOPOLOGY, FINDINGS)
    return kept, actions


def view_parse(path):
    rows = list(csv.DictReader(open(os.path.join(CALLER, path), encoding="utf-8")))
    print(f"{len(rows)} findings in the unified schema, {len(rows[0])} columns each")
    print("columns: " + ", ".join(list(rows[0])[:12]) + ", ...\n")
    print(f"{'host':14s} {"port":11s} {'sev':>4s}  {'CVE':16s} title")
    for r in rows[:8]:
        cve = (r.get("cves") or "-").split(";")[0] or "-"
        print(f"{r['host']:14s} {r["port"]:11s} {r['severity']:>4s}  {cve:16s} "
              f"{short(r['nvt_name'], 48)}")


def view_likelihood():
    kept, _ = scored()
    src = collections.Counter(r["l_source"] for r in kept)
    print(f"L = exploit likelihood for each of {len(kept)} findings")
    print(f"    {src['epss']:3d} have a CVE with an EPSS score -> L = EPSS (a lookup)")
    print(f"    {src['surrogate']:3d} have none            -> L = learned surrogate\n")
    print("findings scored by the surrogate:")
    for r in sorted((r for r in kept if r["l_source"] == "surrogate"),
                    key=lambda r: -r["likelihood"])[:8]:
        print(f"    L={r['likelihood']:.3f}  {r['host']:14s} {short(r['nvt_name'], 52)}")
    t = json.load(open("figures/transfer.json"))
    f = json.load(open("figures/feed_likelihood.json"))
    print()
    recorded("surrogate quality, from likelihood.py / transfer.py (minutes to retrain)")
    print(f"    Spearman vs published EPSS, CVE-grouped : {t['CVE-grouped split, the headline'][0]:.2f}")
    print(f"    scanner severity as a predictor         : {f['severity_baseline']:.2f}")
    print(f"    shifted hold-out (most CVE-less-like)   : {t['shifted hold-out, most CVE-like'][0]:.2f}"
          f"  vs random {t['random hold-out, same size'][0]:.2f}")


def view_impact():
    recorded("impact classifier quality, from impact.py (retrains in minutes)")
    d = json.load(open("figures/impact.json"))
    print(f"    {'axis':16s} {'ThreatRank':>10s} {'text clf':>9s} {'majority':>9s}   (macro-F1)")
    for axis in ("confidentiality", "integrity", "availability"):
        a = d[axis]
        print(f"    {axis:16s} {a['macro_f1']:10.2f} {a['macro_f1_text']:9.2f} "
              f"{a['macro_f1_majority']:9.2f}")
    text = open("../mulval/cases/lab3/input.P", encoding="utf-8").read()
    props = [l for l in text.splitlines() if l.startswith("vulProperty(")]
    est = sum("ESTIMATED" in l for l in props)
    ass = sum("ASSUMED" in l for l in props)
    print(f"\nwhere the impact of each of the {len(props)} vulnerability facts handed to the graph"
          f" comes from\n(mulval/cases/lab3/input.P):")
    print(f"    {len(props) - est - ass:3d} published NVD vector")
    print(f"    {est:3d} estimated by the classifier  (marked /* ESTIMATED */)")
    print(f"    {ass:3d} no vector, no estimate       (marked /* ASSUMED */)\n")
    print("example facts handed to the attack graph:")
    for l in [l for l in props if "ESTIMATED" in l][:2] + [l for l in props if "*/" not in l][:2]:
        print("    " + l.strip())


def view_graph():
    import consequence as C
    recorded("MulVAL attack graph (mulval/cases/lab3/out/), generated with XSB on the lab VM")
    vertices, edges = C.read_graph(GRAPH)
    n_edges = sum(len(v) for v in edges.values()) if isinstance(edges, dict) else len(edges)
    print(f"    {len(vertices)} vertices, {n_edges} arcs; goal: "
          f"{json.load(open(TOPOLOGY))['goal']}\n")
    kept, _ = scored()
    by_host = collections.defaultdict(lambda: [0, 0])
    for r in kept:
        by_host[r["host"]][0] += 1
        by_host[r["host"]][1] += int(r["consequence"])
    on = sum(int(r["consequence"]) for r in kept)
    print(f"C = 1 if the finding lies on a path to the goal:  {on} of {len(kept)} findings\n")
    print(f"    {'host':14s} {'findings':>8s} {'on a path':>10s}")
    for h, (n, c) in sorted(by_host.items()):
        print(f"    {h:14s} {n:8d} {c:10d}")
    print("\nfindings with C = 0 get no budget until everything relevant is fixed, e.g.:")
    for r in [r for r in kept if not r["consequence"]][:4]:
        print(f"    {r['host']:14s} {short(r['nvt_name'], 56)}")


def view_risk():
    kept, actions = scored()
    print(f"R = L x C for each finding, then summed per remediation action\n")
    print(f"{len(kept)} findings -> {len(actions)} actions "
          f"(one per host, port and product: one upgrade closes them all)\n")
    print(f"{'R':>7s}  {'tier':22s} {'size':>4s} {'KEV':>3s}  host / port / product")
    for a in sorted(actions, key=lambda a: -a["risk"])[:8]:
        host, port, product = a["key"]
        print(f"{a['risk']:7.3f}  {a['tier']:22s} {a['size']:4d} {a['kev']:3d}  "
              f"{host} {port} {product}")
    top = max(actions, key=lambda a: a["risk"])
    print(f"\ninside the top action ({top['key'][2]} on {top['key'][0]}), largest members:")
    for r in sorted(top["members"], key=lambda r: -r["risk"])[:5]:
        print(f"    L={r['likelihood']:.3f} C={r['consequence']:.0f} R={r['risk']:.3f}  "
              f"{short(r['nvt_name'], 50)}")


if __name__ == "__main__":
    views = {"likelihood": view_likelihood, "impact": view_impact,
             "graph": view_graph, "risk": view_risk}
    if len(sys.argv) >= 3 and sys.argv[1] == "parse":
        view_parse(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] in views:
        views[sys.argv[1]]()
    else:
        sys.exit(__doc__)
