#!/usr/bin/env python3
"""Render the recorded attack graph as an interactive HTML page.

The full MulVAL graph is 357 vertices and unreadable drawn in full. This condenses it without
inventing anything: every conclusion (OR vertex) is kept; rule applications (AND vertices) that
derive the same conclusion by the same rule from the same premises are merged into one node with
a count; and the vulnerability facts feeding them are grouped by the remediation action that would
remove them, so the graph and the remediation plan share one vocabulary. Network facts and the
attacker's position are kept as they are.

On the page:
  - choose the declared goal (database, application or web server); vertices that cannot help
    derive it fade out, and the work that cannot reach it is counted;
  - set a budget; the actions the plan selects within it are highlighted in the graph;
  - click any node for its MulVAL facts, its findings, and its place in the plan.

    python3 render_graph.py --graph ../mulval/cases/lab3/out --topology topology_lab3.json \\
        --findings processed/findings_openvas_b2.csv --plan processed/plan_lab3.csv \\
        -o figures/attack_graph.html
"""

import argparse
import collections
import csv
import html
import json
import os
import re
import subprocess
import sys

import consequence as C
import prioritise as P
from render_plan import product as pretty_product

HERE = os.path.dirname(os.path.abspath(__file__))
# Actions drawn on their own: the top of the plan and anything holding a KEV-listed finding.
MAJOR_RANK = 10
ROLE = {"vmWeb": "Web server", "vmApp": "App server", "vmDb": "Database"}


def host_label(atom, topology):
    ip = next((ip for ip, h in topology["hosts"].items() if h.get("atom") == atom), "")
    return f"{ROLE.get(atom, atom)} ({ip})" if ip else ROLE.get(atom, atom)


def or_label(fact, topology):
    m = re.match(r"(\w+)\((.*)\)", fact)
    head, args = m.group(1), [a.strip().strip("'") for a in m.group(2).split(",")]
    if head == "execCode":
        return f"Code execution on {ROLE.get(args[0], args[0])}\\nas {args[1]}"
    if head == "netAccess":
        return f"Network access to {ROLE.get(args[0], args[0])}\\n{args[1]}/{args[2]}"
    return fact


def leaf_label(fact):
    m = re.match(r"(\w+)\((.*)\)", fact)
    head, args = m.group(1), [a.strip().strip("'") for a in m.group(2).split(",")]
    if head == "attackerLocated":
        return f"Attacker\\n({args[0]})"
    if head == "hacl":
        return f"Firewall allows\\n{ROLE.get(args[0], args[0])} → {ROLE.get(args[1], args[1])}\\n{args[2]}/{args[3]}"
    if head == "networkServiceInfo":
        return f"Service on {ROLE.get(args[0], args[0])}\\n{args[1]} {args[2]}/{args[3]}, as {args[4]}"
    return fact


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--graph", required=True, metavar="DIR")
    ap.add_argument("--topology", required=True, metavar="JSON")
    ap.add_argument("--findings", required=True, action="append", metavar="CSV")
    ap.add_argument("--plan", required=True, metavar="CSV", help="plan written by prioritise.py")
    ap.add_argument("--budget", type=float, default=0.05)
    ap.add_argument("-o", "--out", default=os.path.join(HERE, "figures", "attack_graph.html"))
    args = ap.parse_args()

    topology = json.load(open(args.topology, encoding="utf-8"))
    vertices, edges = C.read_graph(args.graph)           # edges: premise -> {conclusions}
    premises = collections.defaultdict(set)
    for src, dsts in edges.items():
        for dst in dsts:
            premises[dst].add(src)

    # Findings, their graph leaves and their actions, exactly as the plan was built.
    kept, actions, _ = P.score(args.graph, args.topology, args.findings)
    leaf_of = C.finding_leaves(vertices)                  # (atom, vuln_id) -> vertex
    action_of_leaf = collections.defaultdict(set)
    members_of = {}
    for a in actions:
        members_of[a["key"]] = a["members"]
        for r in a["members"]:
            v = leaf_of.get((r["atom"], r["vuln_id"]))
            if v is not None:
                action_of_leaf[v].add(a["key"])

    plan_rows = list(csv.DictReader(open(args.plan, encoding="utf-8")))
    plan_by_key = {(r["host"], r["port"], r["product"]): r for r in plan_rows}

    # ---- condense ------------------------------------------------------------------------
    nodes, links = {}, collections.Counter()
    vmap = collections.defaultdict(set)                   # MulVAL vertex -> condensed node ids

    def add(nid, **kw):
        nodes.setdefault(nid, kw)
        return nid

    for v, (fact, kind) in vertices.items():
        if kind == "OR":
            vmap[v].add(add(f"o{v}", kind="or", label=or_label(fact, topology), facts=[fact]))
        elif kind == "LEAF" and not fact.startswith("vulExists"):
            vmap[v].add(add(f"l{v}", kind="leaf", label=leaf_label(fact), facts=[fact]))

    action_ids = {}
    atom_of_ip = {ip: h.get('atom') for ip, h in topology['hosts'].items()}
    groups = collections.defaultdict(list)
    for v, (fact, kind) in vertices.items():
        if kind != "AND":
            continue
        concl = sorted(edges.get(v, ()))
        or_prem = tuple(sorted(p for p in premises[v] if vertices[p][1] == "OR"))
        other = tuple(sorted(p for p in premises[v] if vertices[p][1] == "LEAF"
                             and not vertices[p][0].startswith("vulExists")))
        groups[(tuple(concl), fact, or_prem, other)].append(v)

    for gi, ((concl, rule, or_prem, other), members) in enumerate(groups.items()):
        rid = f"r{gi}"
        num, _, desc = rule.partition(" (")
        add(rid, kind="rule", label=f"{desc.rstrip(')')}\\n×{len(members)}", facts=[rule],
            count=len(members))
        for v in members:
            vmap[v].add(rid)
        for c in concl:
            links[(rid, f"o{c}")] += len(members)
        for p in or_prem:
            links[(f"o{p}", rid)] += len(members)
        for p in other:
            links[(f"l{p}", rid)] += len(members)
        for v in members:
            for p in premises[v]:
                if vertices[p][0].startswith("vulExists"):
                    keys = action_of_leaf.get(p) or {("?", "", "unmapped finding")}
                    for k in keys:
                        pr = plan_by_key.get(k, {})
                        members_k = members_of.get(k, [])
                        major = pr and (int(pr["rank"]) <= MAJOR_RANK
                                        or int(pr["known_exploited"]) > 0)
                        if major:
                            aid = action_ids.setdefault(k, f"a{len(action_ids)}")
                            add(aid, kind="action",
                                label=f"{pretty_product(k[2])}\\n{ROLE.get(atom_of_ip.get(k[0], k[0]), k[0])}",
                                facts=[], key=list(k), rank=int(pr["rank"]),
                                cost=float(pr["cost"]), kev=int(pr["known_exploited"]),
                                findings=len(members_k),
                                examples=sorted({m["nvt_name"] for m in members_k})[:8])
                        else:
                            # Small actions outside the top of the plan are pooled per rule, so
                            # the drawing stays readable; the panel still lists every one.
                            aid = f"m{gi}"
                            add(aid, kind="action", label="", facts=[], key=None, rank=None,
                                cost=None, kev=0, findings=0, examples=[], pooled={})
                            nodes[aid]["pooled"][pretty_product(k[2])] = len(members_k)
                        nodes[aid]["facts"].append(vertices[p][0])
                        vmap[p].add(aid)
                        links[(aid, rid)] += 1
        if f"m{gi}" in nodes:
            pool = nodes[f"m{gi}"]
            pool["findings"] = sum(pool["pooled"].values())
            pool["examples"] = [f"{k} ({v} findings)" for k, v in sorted(pool["pooled"].items())]
            na, nf = len(pool["pooled"]), pool["findings"]
            pool["label"] = (f"{na} smaller action{'s' if na != 1 else ''}\\n"
                             f"({nf} finding{'s' if nf != 1 else ''})")

    # ---- goals: what each declared goal can be derived from ------------------------------
    goals = {}
    for atom in ("vmDb", "vmApp", "vmWeb"):
        gv = C.goal_vertex(vertices, f"execCode({atom}, _)")
        dist = C.distances_to(gv, edges, vertices)
        active = sorted({n for v in dist for n in vmap.get(v, ())})
        reach = {k for k in members_of if any(leaf_of.get((r["atom"], r["vuln_id"])) in dist
                                              for r in members_of[k])}
        cost = {P.PATCH: 1.0, P.CONFIG: 2.0, P.REPLACE: 5.0}
        unreach = [a for a in actions if a["key"] not in reach]
        goals[atom] = {"label": ROLE[atom], "active": active,
                       "goal_nodes": [f"o{g}" for g in gv],
                       "unreachable_actions": len(unreach), "actions": len(actions),
                       "unreachable_cost": sum(cost[a["tier"]] for a in unreach),
                       "total_cost": sum(cost[a["tier"]] for a in actions)}
        print(f"  goal {atom}: {len(unreach)}/{len(actions)} actions, "
              f"{goals[atom]['unreachable_cost']:g}/{goals[atom]['total_cost']:g} cost units "
              f"cannot reach it")

    # ---- draw with Graphviz ---------------------------------------------------------------
    style = {"or": 'shape=box, style="rounded,filled", fillcolor="#e8f0fb", color="#2b6cb0", penwidth=1.4',
             "rule": 'shape=ellipse, style=filled, fillcolor="#ffffff", color="#7a8597", fontsize=10',
             "leaf": 'shape=note, style=filled, fillcolor="#f3f4f6", color="#9aa0a8", fontsize=10',
             "action": 'shape=box, style="filled", fillcolor="#fff7e6", color="#c27c0e"'}
    lines = ["digraph G {", '  rankdir=LR; nodesep=0.25; ranksep=0.55; bgcolor="transparent";',
             '  node [fontname="Helvetica", fontsize=11, margin="0.12,0.06"];',
             '  edge [color="#9aa3b2", arrowsize=0.6];']
    for nid, n in nodes.items():
        label = n["label"].replace('"', "'")
        lines.append(f'  {nid} [id="{nid}", label="{label}", {style[n["kind"]]}];')
    for (a, b), w in links.items():
        if a in nodes and b in nodes:
            lines.append(f'  {a} -> {b} [id="{a}__{b}"{", penwidth=1.6" if w > 5 else ""}];')
    lines.append("}")
    svg = subprocess.run(["dot", "-Tsvg"], input="\n".join(lines), capture_output=True,
                         text=True)
    if svg.returncode:
        sys.exit(f"dot failed: {svg.stderr}")
    svg_text = svg.stdout[svg.stdout.find("<svg"):]

    plan_data = [{"key": [r["host"], r["port"], r["product"]], "cost": float(r["cost"])}
                 for r in plan_rows]
    total_cost = sum(p["cost"] for p in plan_data)
    for n in nodes.values():
        n["facts"] = n["facts"][:12]
    page = PAGE.format(svg=svg_text, nodes=json.dumps(nodes), goals=json.dumps(goals),
                       plan=json.dumps(plan_data), total=total_cost,
                       pct=max(1, min(100, round(args.budget * 100))),
                       nv=len(vertices), ne=sum(len(d) for d in edges.values()),
                       nn=len(nodes), src=html.escape(os.path.basename(args.plan)))
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    open(args.out, "w", encoding="utf-8").write(page)
    print(f"wrote {args.out}: {len(vertices)} MulVAL vertices condensed to {len(nodes)} nodes")


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ThreatRank Attack Graph</title>
<style>
:root {{ --bg:#f6f7f9; --panel:#fff; --ink:#1d2433; --muted:#5b6475; --line:#e3e6ec;
        --accent:#2b6cb0; --goal:#d24a1f; --ok:#1f7a4d; --okbg:#e3f4ea; --kev:#b42318; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#14171d; --panel:#1c2029; --ink:#e7eaf0;
        --muted:#a3abba; --line:#2c3240; --accent:#7fb2f0; --goal:#ff8a65; --ok:#7ed3a4;
        --okbg:#1d3328; --kev:#ff8a80; }} }}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--bg); color:var(--ink);
       font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif }}
main {{ max-width:1400px; margin:0 auto; padding:24px 16px 40px }}
h1 {{ margin:0; font-size:26px }}
.sub {{ color:var(--muted); margin:4px 0 16px }}
.bar {{ display:flex; gap:12px; flex-wrap:wrap; align-items:center; background:var(--panel);
       border:1px solid var(--line); border-radius:10px; padding:12px 14px }}
.bar label {{ font-weight:600 }}
.seg button {{ border:1px solid var(--line); background:var(--bg); color:var(--ink); padding:5px 12px;
              font:inherit; font-size:14px; cursor:pointer }}
.seg button:first-child {{ border-radius:6px 0 0 6px }} .seg button:last-child {{ border-radius:0 6px 6px 0 }}
.seg button.on {{ background:var(--accent); border-color:var(--accent); color:#fff }}
input[type=range] {{ width:180px; accent-color:var(--accent) }}
.stats {{ display:flex; gap:18px; flex-wrap:wrap; color:var(--muted); font-size:14px; margin:10px 2px }}
.stats b {{ color:var(--ink) }}
.wrap {{ display:grid; grid-template-columns:minmax(0,1fr) 320px; gap:14px; margin-top:6px }}
@media (max-width:900px) {{ .wrap {{ grid-template-columns:1fr }} }}
.canvas {{ position:relative; background:var(--panel); border:1px solid var(--line); border-radius:10px;
          overflow:hidden; height:72vh; min-height:420px; cursor:grab; touch-action:none }}
.canvas.dragging {{ cursor:grabbing }}
.canvas svg {{ width:100%; height:100%; display:block; user-select:none }}
.zoom {{ position:absolute; right:10px; top:10px; display:flex; flex-direction:column; gap:4px; z-index:2 }}
.zoom button {{ width:34px; height:34px; border:1px solid var(--line); background:var(--panel); color:var(--ink);
               border-radius:6px; font:600 18px/1 system-ui,sans-serif; cursor:pointer }}
.zoom button.fit {{ font-size:11px }}
.hint {{ position:absolute; left:10px; bottom:8px; font-size:12px; color:var(--muted); background:var(--panel);
        padding:2px 6px; border-radius:4px; z-index:2 }}
.panel {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px;
         align-self:start; position:sticky; top:12px; font-size:14px }}
.panel h3 {{ margin:0 0 6px; font-size:16px }}
.panel .muted {{ color:var(--muted) }}
.panel code {{ font-size:12px; word-break:break-all }}
.legend {{ display:flex; gap:14px; flex-wrap:wrap; font-size:13px; color:var(--muted); margin-top:10px }}
.sw {{ display:inline-block; width:12px; height:12px; border-radius:3px; vertical-align:-1px; margin-right:4px; border:1px solid }}
g.node {{ cursor:pointer; transition:opacity .2s }}
g.node.off, g.edge.off {{ opacity:.12 }}
g.node.goal polygon, g.node.goal path {{ stroke:var(--goal); stroke-width:3 }}
g.node.inbudget polygon, g.node.inbudget path {{ stroke:var(--ok); stroke-width:3.5 }}
g.node.sel polygon, g.node.sel path, g.node.sel ellipse {{ stroke-dasharray:4 2; stroke-width:3 }}
</style></head>
<body><main>
<h1>ThreatRank Attack Graph</h1>
<p class="sub">The recorded MulVAL graph ({nv} vertices, {ne} arcs) condensed to {nn} nodes: rule
applications with the same conclusion and premises are merged, and vulnerability facts are grouped by
the remediation action that removes them. Click a node for details.</p>
<div class="bar">
  <label>Declared goal</label>
  <span class="seg" id="goals"></span>
  <label for="budget" style="margin-left:12px">Plan budget</label>
  <input type="range" id="budget" min="1" max="100" value="{pct}">
  <b id="budgetOut"></b>
</div>
<div class="stats" id="stats"></div>
<div class="wrap">
  <div class="canvas" id="canvas">
    <div class="zoom"><button id="zin" title="Zoom in">+</button><button id="zout" title="Zoom out">&minus;</button><button id="zfit" class="fit" title="Fit to view">Fit</button></div>
    <div class="hint">Scroll or pinch to zoom &middot; drag to move &middot; click a node for details</div>
    {svg}
  </div>
  <aside class="panel" id="panel"><h3>Details</h3><p class="muted">Click a node in the graph.</p>
    <div class="legend">
      <span><i class="sw" style="background:#e8f0fb;border-color:#2b6cb0"></i>Conclusion</span>
      <span><i class="sw" style="background:#fff;border-color:#7a8597;border-radius:50%"></i>Rule (×count)</span>
      <span><i class="sw" style="background:#fff7e6;border-color:#c27c0e"></i>Remediation action</span>
      <span><i class="sw" style="background:#f3f4f6;border-color:#9aa0a8"></i>Network fact</span>
      <span><i class="sw" style="border-color:var(--goal);border-width:2px"></i>Goal</span>
      <span><i class="sw" style="border-color:var(--ok);border-width:2px"></i>Fixed within budget</span>
    </div>
  </aside>
</div>
<p class="sub" style="margin-top:14px">Generated by render_graph.py from the recorded graph and {src}.
Goals and reachability are MulVAL's derivation from the declared topology; the plan is the same
greedy selection prioritise.py makes.</p>
</main>
<script>
const NODES = {nodes}, GOALS = {goals}, PLAN = {plan}, TOTAL = {total};
const svg = document.querySelector("#canvas svg");
let goal = "vmDb", sel = null;
const esc = s => String(s).replace(/[&<>"]/g, c => ({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}}[c]));
const keyStr = k => k ? k.join("|") : "";

function inBudget() {{
  const b = TOTAL * (+document.getElementById("budget").value) / 100, chosen = new Map();
  let spent = 0;
  PLAN.forEach((p, i) => {{ if (spent + p.cost <= b + 1e-9) {{ spent += p.cost; chosen.set(keyStr(p.key), i + 1); }} }});
  return chosen;
}}
function render() {{
  const g = GOALS[goal], act = new Set(g.active), chosen = inBudget();
  svg.querySelectorAll("g.node").forEach(el => {{
    const n = NODES[el.id]; if (!n) return;
    el.classList.toggle("off", !act.has(el.id));
    el.classList.toggle("goal", g.goal_nodes.includes(el.id));
    el.classList.toggle("inbudget", n.kind === "action" && chosen.has(keyStr(n.key)));
    el.classList.toggle("sel", el.id === sel);
  }});
  svg.querySelectorAll("g.edge").forEach(el => {{
    const [a, b] = el.id.split("__"); el.classList.toggle("off", !(act.has(a) && act.has(b)));
  }});
  const pct = document.getElementById("budget").value;
  document.getElementById("budgetOut").textContent = pct + "%";
  let kev = 0; Object.values(NODES).forEach(n => {{ if (n.kind === "action" && chosen.has(keyStr(n.key))) kev += n.kev; }});
  document.getElementById("stats").innerHTML =
    `<span>Goal: <b>code execution on the ${{esc(g.label)}}</b></span>` +
    `<span>Work that cannot reach it: <b>${{g.unreachable_actions}} / ${{g.actions}}</b> actions, ` +
    `<b>${{g.unreachable_cost}} / ${{g.total_cost}}</b> cost units</span>` +
    `<span>Plan at ${{pct}}%: <b>${{chosen.size}}</b> actions selected</span>`;
  document.querySelectorAll("#goals button").forEach(b => b.classList.toggle("on", b.dataset.g === goal));
}}
function show(id) {{
  const n = NODES[id]; if (!n) return; sel = id; const p = document.getElementById("panel");
  const kindName = {{or:"Conclusion", rule:"Rule application", action:"Remediation action", leaf:"Network fact"}}[n.kind];
  let h = `<h3>${{esc(n.label.replace(/\\\\n/g, " "))}}</h3><p class="muted">${{kindName}}</p>`;
  if (n.kind === "action" && !n.key) {{
    h += `<p>${{n.examples.length}} smaller actions outside the top ${{10}} of the plan, with no KEV-listed finding, pooled to keep the graph readable.</p><ul>` +
         n.examples.map(e => `<li>${{esc(e)}}</li>`).join("") + "</ul>";
  }} else if (n.kind === "action") {{
    const chosen = inBudget().has(keyStr(n.key));
    h += `<p>Plan rank <b>${{n.rank ?? "–"}}</b> · cost <b>${{n.cost ?? "–"}}</b> · ` +
         `<b>${{n.findings}}</b> findings · <b style="color:var(--kev)">${{n.kev}} KEV</b><br>` +
         `${{chosen ? '<b style="color:var(--ok)">Fixed within the selected budget</b>' : "Not within the selected budget"}}</p>` +
         `<p class="muted">Host ${{esc(n.key[0])}} ${{esc(n.key[1])}}</p><p><b>Example findings</b></p><ul>` +
         n.examples.map(e => `<li>${{esc(e)}}</li>`).join("") + "</ul>";
  }}
  if (n.kind === "rule") h += `<p>${{n.count}} rule applications merged into this node.</p>`;
  h += `<p><b>MulVAL facts</b></p>` + n.facts.map(f => `<code>${{esc(f)}}</code><br>`).join("");
  p.innerHTML = h; render();
}}
Object.entries(GOALS).forEach(([k, g]) => {{
  const b = document.createElement("button"); b.textContent = g.label; b.dataset.g = k;
  b.onclick = () => {{ goal = k; render(); }}; document.getElementById("goals").appendChild(b);
}});
// ---- pan and zoom, by moving the SVG viewBox ----------------------------------------
const canvas = document.getElementById("canvas");
svg.removeAttribute("width"); svg.removeAttribute("height");
svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
const vb0 = svg.viewBox.baseVal, home = {{x: vb0.x, y: vb0.y, w: vb0.width, h: vb0.height}};
let vb = {{...home}};
const setVB = () => svg.setAttribute("viewBox", `${{vb.x}} ${{vb.y}} ${{vb.w}} ${{vb.h}}`);
function toUser(cx, cy) {{
  const pt = svg.createSVGPoint(); pt.x = cx; pt.y = cy;
  return pt.matrixTransform(svg.getScreenCTM().inverse());
}}
function zoomAt(cx, cy, f) {{
  const nw = vb.w * f;
  if (nw < home.w * 0.04 || nw > home.w * 1.5) return;
  const p = toUser(cx, cy);
  vb = {{x: p.x - (p.x - vb.x) * f, y: p.y - (p.y - vb.y) * f, w: nw, h: vb.h * f}};
  setVB();
}}
function zoomCenter(f) {{ const r = svg.getBoundingClientRect(); zoomAt(r.left + r.width / 2, r.top + r.height / 2, f); }}
canvas.addEventListener("wheel", e => {{
  e.preventDefault();
  zoomAt(e.clientX, e.clientY, Math.exp(e.deltaY * (e.ctrlKey ? 0.01 : 0.0015)));
}}, {{passive: false}});
let drag = null, moved = false;
canvas.addEventListener("pointerdown", e => {{
  if (e.target.closest(".zoom")) return;
  drag = {{x: e.clientX, y: e.clientY, vb: {{...vb}}, s: svg.getScreenCTM().a}}; moved = false;
  canvas.setPointerCapture(e.pointerId);
}});
canvas.addEventListener("pointermove", e => {{
  if (!drag) return;
  const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
  if (Math.abs(dx) + Math.abs(dy) > 4) {{ moved = true; canvas.classList.add("dragging"); }}
  if (moved) {{ vb.x = drag.vb.x - dx / drag.s; vb.y = drag.vb.y - dy / drag.s; setVB(); }}
}});
canvas.addEventListener("pointerup", e => {{
  canvas.classList.remove("dragging");
  if (drag && !moved) {{
    const hit = document.elementFromPoint(e.clientX, e.clientY);
    const node = hit && hit.closest("g.node");
    if (node) show(node.id);
  }}
  drag = null;
}});
document.getElementById("zin").onclick = () => zoomCenter(0.7);
document.getElementById("zout").onclick = () => zoomCenter(1 / 0.7);
document.getElementById("zfit").onclick = () => {{ vb = {{...home}}; setVB(); }};
canvas.addEventListener("dblclick", e => zoomAt(e.clientX, e.clientY, 0.5));
document.getElementById("budget").addEventListener("input", render);
render();
</script>
</body></html>
"""


if __name__ == "__main__":
    main()
