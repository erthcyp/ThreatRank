#!/usr/bin/env python3
"""Attack consequence C for every finding, read off the attack graph.

The lower head of the two-head design, and the half that needs no labels. A finding's
consequence here is not how bad the vulnerability is in the abstract; it is how much closer
it takes an attacker to the asset that was declared as the goal. That is a property of the
network, so two identical findings on two hosts can score differently, which is the whole
reason a graph is used instead of a severity column.

WHAT IS COMPUTED

MulVAL emits a derivation graph: LEAF facts feed AND nodes (rules), which derive OR nodes
(facts), which feed further rules. For each finding that entered the graph as a `vulExists`
leaf, this script asks two questions:

    can the goal be derived from it at all?
    if so, how many derivation steps away is it?

    C = 1 / d   for a finding on some derivation of the goal, d being the shortest such
    C = 0       for a finding from which the goal cannot be derived

d is a count of derivation steps, not network hops. A finding one step from the goal scores
1.0, and a finding that only matters after several further exploits scores proportionally
less. The measure needs no training and is defined for every finding in the graph, including
the ones with no CVE, which is what lets this head cover the findings the likelihood head
cannot.

WHAT C = 0 MEANS, AND WHY IT IS NOT A BUG

A finding that reaches nothing scores zero and therefore takes R = L x C to zero as well.
That is deliberate: under a fixed remediation budget, work that does not move an attacker
toward anything declared valuable is work that waits. It is also the sharpest claim this
head makes, so the distribution of zeros is printed rather than hidden. If almost everything
scores zero the goal is too narrow; if almost nothing does, the topology is too permissive.
Both are readable from the output.

WHAT THIS DEPENDS ON THAT NO SCANNER REPORTS

Reachability, service accounts and the attacker's starting position all come from the
topology file, and so does the goal. Change the goal and every C changes. That is a property
of the question being asked, not a defect, but it means a consequence score is only as
honest as the topology it was computed under, and the topology has to be reported next to
it.

    python3 consequence.py --graph ~/mulval/testcases/lab3 \\
                           --topology topology_lab3.json \\
                           --findings processed/findings_openvas_b2.csv
"""

import argparse
import collections
import csv
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# vulExists(host, vulnId, software, range, consequence) as MulVAL prints it back
VULEXISTS = re.compile(r"^vulExists\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^)]+)\)$")


def unquote(atom):
    atom = atom.strip()
    return atom[1:-1].replace("''", "'") if atom.startswith("'") and atom.endswith("'") else atom


def read_graph(directory):
    """Vertices as {id: (fact, type)} and edges as source -> {destinations}.

    ARCS.CSV is written destination-first: a row `4,5,-1` means vertex 5 feeds vertex 4.
    Reading it the other way round silently reverses every distance in this file, so the
    direction is asserted here rather than assumed at the call site.
    """
    vpath = os.path.join(directory, "VERTICES.CSV")
    apath = os.path.join(directory, "ARCS.CSV")
    for path in (vpath, apath):
        if not os.path.exists(path):
            sys.exit(f"missing {path}. Run graph_gen.sh in that directory first.")

    vertices = {}
    with open(vpath, encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if len(row) < 3:
                continue
            vertices[int(row[0])] = (row[1], row[2])

    edges = collections.defaultdict(set)
    with open(apath, encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if len(row) < 2:
                continue
            dst, src = int(row[0]), int(row[1])
            edges[src].add(dst)
    return vertices, edges


def goal_vertex(vertices, goal_text):
    """The vertex the topology named as the goal.

    MulVAL conventionally numbers the goal 1, but relying on that would break silently the
    day it does not, so the goal is matched on its text and the convention is only a
    fallback.
    """
    head = goal_text.split("(")[0].strip()
    args = goal_text[goal_text.find("(") + 1:goal_text.rfind(")")].split(",")
    host = args[0].strip()
    best = [vid for vid, (fact, kind) in vertices.items()
            if kind == "OR" and fact.startswith(f"{head}({host}")]
    if best:
        return sorted(best)
    if 1 in vertices:
        print("  note: no vertex matched the goal text; falling back to vertex 1")
        return [1]
    sys.exit("no goal vertex found in the graph")


def distances_to(goals, edges, vertices):
    """Shortest step count from every vertex to the nearest goal, over reversed edges."""
    reverse = collections.defaultdict(set)
    for src, dsts in edges.items():
        for dst in dsts:
            reverse[dst].add(src)

    dist = {g: 0 for g in goals}
    queue = collections.deque(goals)
    while queue:
        node = queue.popleft()
        for prev in reverse.get(node, ()):
            if prev not in dist:
                dist[prev] = dist[node] + 1
                queue.append(prev)
    return dist


def assumed_keys(rows, cvss_path):
    """Findings whose range and consequence were assumed, because nothing published them.

    A learned classifier was tried for this job and measured: on 29 such findings it
    predicted privilege escalation for 28, `TCP Timestamps Information Disclosure` among
    them, and class weighting moved exactly one. The text of an uncatalogued finding lies
    outside the distribution of CVE titles the labels come from, so the model falls back to
    the majority class and returns the same answer as the constant it was meant to replace,
    while looking like a measurement. The constant is kept and its influence is measured
    instead, which is the difference between guessing quietly and saying what the guess
    holds up.
    """
    try:
        with open(cvss_path, encoding="utf-8") as fh:
            cvss = json.load(fh)
    except FileNotFoundError:
        return set()
    out = set()
    for r in rows:
        published = False
        for cve in [c.strip() for c in (r.get("cves") or "").split(";")
                    if c.strip().startswith("CVE-")]:
            if ((cvss.get(cve) or {}).get("cvss") or {}).get("attackVector"):
                published = True
                break
        if not published:
            out.add((r["atom"], r["vuln_id"]))
    return out


def derivable(vertices, incoming, removed):
    """Least fixed point over the AND/OR graph once `removed` is gone."""
    holds = {v for v, (_, kind) in vertices.items()
             if kind == "LEAF" and v not in removed}
    changed = True
    while changed:
        changed = False
        for v, (_, kind) in vertices.items():
            if v in holds or kind == "LEAF":
                continue
            inputs = incoming.get(v, ())
            if not inputs:
                continue
            ok = (all(i in holds for i in inputs) if kind == "AND"
                  else any(i in holds for i in inputs))
            if ok:
                holds.add(v)
                changed = True
    return holds


def report_dependence(vertices, edges, goals, leaves, assumed):
    """How much of the reported result rests on facts nothing published."""
    incoming = collections.defaultdict(set)
    for src, dsts in edges.items():
        for dst in dsts:
            incoming[dst].add(src)
    removed = {leaves[k] for k in assumed if k in leaves}
    if not removed:
        return
    facts = {v for v in derivable(vertices, incoming, set())
             if vertices[v][1] == "OR"}
    without = derivable(vertices, incoming, removed)
    lost = facts - without
    still = bool(goals & without)
    print("\ndependence on assumed properties")
    print(f"  {len(removed)} of {len(leaves)} findings in the graph carry a range and "
          f"consequence")
    print(f"  that no published vector supplied")
    print(f"  removing all of them: the goal is "
          f"{'still derivable' if still else 'NO LONGER derivable'}, "
          f"{len(lost)} of {len(facts)} derived facts lost")
    print("  the reported result does not rest on those assumptions"
          if still and not lost else
          "  the reported result rests on those assumptions and must say so")


EMITTED = re.compile(r"^vulExists\(([^,]+),\s*([^,]+),")


def emitted_facts(directory):
    """(host_atom, vuln_id) for every finding the adapter put into input.P.

    MulVAL prunes any fact that derives nothing, so a finding can be absent from
    VERTICES.CSV for two quite different reasons: it never entered the model, or it
    entered and leads nowhere. Only the second is a consequence of zero, and telling them
    apart is the difference between reporting that every finding reaches the goal and
    reporting that a fifth of them reach nothing.
    """
    path = os.path.join(directory, "input.P")
    if not os.path.exists(path):
        return None
    out = set()
    for line in open(path, encoding="utf-8"):
        m = EMITTED.match(line.strip())
        if m:
            out.add((unquote(m.group(1)), unquote(m.group(2))))
    return out


def finding_leaves(vertices):
    """Every vulExists leaf, as {(host_atom, vuln_id): vertex id}."""
    out = {}
    for vid, (fact, kind) in vertices.items():
        if kind != "LEAF":
            continue
        m = VULEXISTS.match(fact)
        if m:
            out[(unquote(m.group(1)), unquote(m.group(2)))] = vid
    return out


def load_findings(paths, topology):
    """Findings for the hosts this topology declares, keyed the way the adapter keyed them."""
    atom_of = {ip: h.get("atom") or ip for ip, h in topology["hosts"].items()}
    rows, seen = [], set()
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r.get("threat") == "Log" or r["host"] not in atom_of:
                    continue
                key = (r["host"], r["nvt_name"])
                if key in seen:
                    continue
                seen.add(key)
                cves = [c.strip() for c in (r.get("cves") or "").split(";")
                        if c.strip().startswith("CVE-")]
                vuln_id = cves[0] if cves else f"oid_{r.get('nvt_oid') or 'unknown'}"
                rows.append({**r, "atom": atom_of[r["host"]], "vuln_id": vuln_id,
                             "has_cve": bool(cves)})
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--graph", required=True, metavar="DIR",
                    help="directory holding VERTICES.CSV and ARCS.CSV")
    ap.add_argument("--topology", required=True, metavar="JSON")
    ap.add_argument("--findings", required=True, action="append", metavar="CSV")
    ap.add_argument("-o", "--out", metavar="CSV", help="write C per finding here")
    args = ap.parse_args()

    topology = json.load(open(args.topology, encoding="utf-8"))
    vertices, edges = read_graph(args.graph)
    goals = goal_vertex(vertices, topology["goal"])
    dist = distances_to(goals, edges, vertices)
    leaves = finding_leaves(vertices)
    emitted = emitted_facts(args.graph)
    rows = load_findings(args.findings, topology)

    print(f"graph             : {len(vertices)} vertices, "
          f"{sum(len(v) for v in edges.values())} arcs")
    print(f"goal              : {topology['goal']}, matched {len(goals)} vertices")
    print(f"findings declared : {len(rows)} on {len(topology['hosts'])} hosts")
    print(f"  of those, in the graph as a vulExists leaf: {len(leaves)} distinct keys")

    report_dependence(vertices, edges, set(goals), leaves,
                      assumed_keys(rows, os.path.join(HERE, "cwe_map.json")))
    print()

    scored, not_modelled, pruned = [], 0, 0
    for r in rows:
        key = (r["atom"], r["vuln_id"])
        vid = leaves.get(key)
        if vid is None:
            # Absent from the graph. If the adapter emitted it, MulVAL pruned it because
            # nothing follows from it, and that is a consequence of zero. If the adapter
            # never emitted it, it is outside the model and must not be scored at all.
            if emitted is not None and key not in emitted:
                not_modelled += 1
                continue
            pruned += 1
            r["distance"] = None
            r["consequence"] = 0.0
            scored.append(r)
            continue
        d = dist.get(vid)
        r["distance"] = d
        r["consequence"] = 0.0 if d is None else 1.0 / d
        scored.append(r)

    if not scored:
        sys.exit("no finding could be matched to a graph vertex. Check that --findings and "
                 "--topology are the same pair the graph was generated from.")

    reaching = [r for r in scored if r["consequence"] > 0]
    print(f"scored            : {len(scored)} findings")
    print(f"  reach the goal    : {len(reaching)} ({100*len(reaching)/len(scored):.1f}%)")
    print(f"  reach nothing     : {len(scored)-len(reaching)} ("
          f"{100*(len(scored)-len(reaching))/len(scored):.1f}%), C = 0")
    if pruned:
        print(f"    of those, {pruned} were modelled but pruned by MulVAL because nothing")
        print(f"    follows from them, which is what a consequence of zero means")
    if not_modelled:
        print(f"  outside the model : {not_modelled}, not scored")
    print()

    by_host = collections.defaultdict(lambda: [0, 0])
    for r in scored:
        by_host[r["host"]][0] += 1
        by_host[r["host"]][1] += 1 if r["consequence"] > 0 else 0
    print(f"  {'host':16s} {'scored':>7} {'reaching':>9}")
    for host, (total, reach) in sorted(by_host.items()):
        print(f"  {host:16s} {total:7d} {reach:9d}")

    # The claim this head exists to support: coverage does not depend on having a CVE.
    cveless = [r for r in scored if not r["has_cve"]]
    cveless_reach = [r for r in cveless if r["consequence"] > 0]
    print(f"\n  findings with no CVE: {len(cveless)} scored, "
          f"{len(cveless_reach)} of them on a derivation of the goal")

    spread = collections.Counter(r["distance"] for r in reaching)
    print(f"\n  shortest distance to the goal, over the {len(reaching)} that reach it:")
    for d, n in sorted(spread.items()):
        print(f"    d = {d:<3} C = {1/d:.3f}   {n} findings")
    if len(spread) == 1:
        print("\n  WARNING: every reaching finding has the same distance, so C is a constant")
        print("  and R = L x C collapses to a rescaling of L. The graph is not separating")
        print("  these findings, and a consequence head that separates nothing is not one.")

    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["host", "nvt_name", "vuln_id", "has_cve", "distance", "consequence"])
            for r in scored:
                w.writerow([r["host"], r["nvt_name"], r["vuln_id"], int(r["has_cve"]),
                            r["distance"] if r["distance"] is not None else "",
                            f"{r['consequence']:.6f}"])
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
