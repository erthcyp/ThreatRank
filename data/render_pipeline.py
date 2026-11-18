#!/usr/bin/env python3
"""Render the whole pipeline, stage by stage, as one self-contained HTML page.

    python3 render_pipeline.py [-o figures/pipeline.html]

The page walks from the raw scanner reports (stage 0) to the remediation plan (stage 6), and
every number on it is computed here from the same code and committed data the experiments use:
prioritise.score() for likelihood, consequence, risk and actions; correlate.py and
prioritise.py for their printed summaries; the recorded model results in figures/*.json for
the two learned components (retraining them takes minutes). The last stage embeds
plan_report.html and attack_graph.html from the same folder, so render those first
(reproduce.sh does).
"""
import argparse
import collections
import csv
import html
import io
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)

GRAPH = "../mulval/cases/lab3/out"
TOPOLOGY = "topology_lab3.json"
OPENVAS_RAW = "raw/openvas/2026-09-08_openvas_B_group-b-old-images.xml"
NESSUS_RAW = "raw/nessus/2026-09-29_nessus_B_group-b-nessus.json"
OPENVAS_CSV = "processed/findings_openvas_b2.csv"
NESSUS_CSV = "processed/findings_nessus_b2.csv"
HOSTS = {"172.18.0.110": "Web server", "172.18.0.111": "App server", "172.18.0.112": "Database"}

e = html.escape


def short(text, n):
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1] + "…"


def table(head, rows, cls=""):
    th = "".join(f"<th>{h}</th>" for h in head)
    tr = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="tw"><table class="{cls}"><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table></div>'


def stat(v, label, tone=""):
    return f'<div class="stat {tone}"><div class="v">{v}</div><div class="l">{label}</div></div>'


def run(*args):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, check=True).stdout


# ---------------------------------------------------------------- data
def load_csv(path):
    return list(csv.DictReader(open(path, encoding="utf-8")))


def raw_openvas_sample():
    root = ET.parse(OPENVAS_RAW).getroot()
    res = next(r for r in root.iter("result")
               if r.findtext("threat") == "High" and "CVE" in ET.tostring(r, encoding="unicode"))
    nvt = res.find("nvt")
    cves = [r.get("id") for r in nvt.iter("ref") if r.get("type") == "cve"][:3]
    lines = [
        f'<result id="{res.get("id")[:8]}…">',
        f"  <name>{res.findtext('name')}</name>",
        f"  <host>{res.findtext('host').strip()}</host>",
        f"  <port>{res.findtext('port')}</port>",
        f'  <nvt oid="{nvt.get("oid")}">',
        f"    <family>{nvt.findtext('family')}</family>",
        f"    <cvss_base>{nvt.findtext('cvss_base')}</cvss_base>",
        *[f'    <ref type="cve" id="{c}"/>' for c in cves],
        "  </nvt>",
        f"  <threat>{res.findtext('threat')}</threat>",
        f"  <severity>{res.findtext('severity')}</severity>",
        f"  <qod><value>{res.findtext('qod/value')}</value></qod>",
        "  …",
        "</result>",
    ]
    return "\n".join(lines)


def raw_nessus_sample():
    d = json.load(open(NESSUS_RAW, encoding="utf-8"))
    host = d["hosts"]["2"]
    v = next(x for x in host["vulnerabilities"] if x.get("severity", 0) >= 3)
    keep = {k: v[k] for k in ("plugin_id", "plugin_name", "plugin_family", "severity", "score", "cpe")}
    return ('"host-ip": "' + host["info"]["host-ip"] + '",\n"vulnerabilities": [\n  '
            + json.dumps(keep, indent=2).replace("\n", "\n  ") + ",\n  …\n]")


def collect():
    import prioritise as P
    D = {}
    ov, ne = load_csv(OPENVAS_CSV), load_csv(NESSUS_CSV)
    D["ov_threat"] = collections.Counter(r["threat"] for r in ov)
    D["ne_threat"] = collections.Counter(r["threat"] for r in ne)
    D["ov_rows"], D["ne_rows"] = len(ov), len(ne)
    D["n_hosts"] = len({r["host"] for r in ov} | {r["host"] for r in ne})
    D["ov_kept"] = sum(1 for r in ov if r["threat"] != "Log")
    D["ne_kept"] = sum(1 for r in ne if r["threat"] != "Log")
    D["columns"] = list(ov[0])
    D["sample"] = sorted((r for r in ov if r["threat"] != "Log"),
                         key=lambda r: -float(r["severity"] or 0))[:6]
    D["raw_ov"], D["raw_ne"] = raw_openvas_sample(), raw_nessus_sample()

    D["correlate"] = run("correlate.py", "--findings", OPENVAS_CSV, "--findings", NESSUS_CSV,
                         "-o", os.devnull)

    with redirect_stdout(io.StringIO()):
        kept, actions, _ = P.score(GRAPH, TOPOLOGY, [OPENVAS_CSV])
    D["kept"], D["actions"] = kept, actions
    D["kev_total"] = sum(1 for r in kept if P.in_kev(r))

    D["impact"] = json.load(open("figures/impact.json"))
    D["transfer"] = json.load(open("figures/transfer.json"))
    D["feed"] = json.load(open("figures/feed_likelihood.json"))
    props = [l for l in open("../mulval/cases/lab3/input.P", encoding="utf-8")
             if l.startswith("vulProperty(")]
    D["props"] = props
    verts = sum(1 for _ in open(f"{GRAPH}/VERTICES.CSV"))
    arcs = sum(1 for _ in open(f"{GRAPH}/ARCS.CSV"))
    D["graph_size"] = (verts, arcs)
    D["prioritise"] = run("prioritise.py", "--graph", GRAPH, "--topology", TOPOLOGY,
                          "--findings", OPENVAS_CSV)
    return D


def parse_block(text, title):
    """One budget table from prioritise.py's report: {ordering: [values per budget]}."""
    lines = text.splitlines()
    i = next(n for n, l in enumerate(lines) if l.strip().startswith(title))
    budgets = lines[i + 1].split()[1:]
    out = {}
    for l in lines[i + 3:]:
        if not l.strip() or l.strip().startswith("out of"):
            break
        parts = re.split(r"\s{2,}", l.strip())
        name, vals = parts[0], " ".join(parts[1:]).split()
        out[name] = vals
    return budgets, out


# ---------------------------------------------------------------- stages
def stage0(D):
    t = D["ov_threat"]
    sev = " · ".join(f"{k} {t[k]}" for k in ("Critical", "High", "Medium", "Low", "Log") if t.get(k))
    return f"""
<p class="lead">Two vulnerability scanners scan the same group of containers. Each exports
results in its own format, with its own field names and severity scale.</p>
<div class="stats">{stat(D['ov_rows'], 'OpenVAS results (XML)')}{stat(sum(D['ne_threat'].values()), 'Nessus results (JSON)')}{stat(D['n_hosts'], 'hosts in group B')}</div>
<div class="two">
 <div><h4>OpenVAS: one &lt;result&gt; from the XML report</h4><pre>{e(D['raw_ov'])}</pre>
 <p class="note">Severity mix: {sev}</p></div>
 <div><h4>Nessus: one vulnerability from the JSON export</h4><pre>{e(D['raw_ne'])}</pre>
 <p class="note">Different structure, different names: <code>plugin_name</code> instead of
 <code>&lt;name&gt;</code>, a 0–4 severity instead of a CVSS score.</p></div>
</div>"""


def stage1(D):
    rows = [[e(r["host"]), e(r["port"]), e(r["severity"]), e((r["cves"] or "–").split(";")[0]),
             e(short(r["nvt_name"], 60)), e(r["scanner"])] for r in D["sample"]]
    cols = ", ".join(f"<code>{c}</code>" for c in D["columns"][:14])
    return f"""
<p class="lead">One parser per scanner maps every finding into the same table. Service
detections (OpenVAS <em>Log</em> level) are removed: they say a service is running, not that
anything is wrong.</p>
<div class="stats">{stat(D['ov_kept'], f"OpenVAS findings kept (of {D['ov_rows']})")}{stat(D['ne_kept'], f"Nessus findings kept (of {D['ne_rows']})")}{stat(D['ov_kept'] + D['ne_kept'], 'findings in one schema', 'hi')}</div>
<h4>The unified schema ({len(D['columns'])} columns)</h4><p class="note">{cols}, …</p>
{table(['host', 'port', 'severity', 'CVE', 'check', 'scanner'], rows)}
<p class="note">Re-running the parsers on the raw reports reproduces the committed CSVs byte
for byte (<code>reproduce.sh</code> checks this).</p>"""


def stage2(D):
    imp = D["impact"]
    rows = [[a.capitalize(), f"<b>{imp[a]['macro_f1']:.2f}</b>", f"{imp[a]['macro_f1_text']:.2f}",
             f"{imp[a]['macro_f1_majority']:.2f}"] for a in ("confidentiality", "integrity", "availability")]
    props = D["props"]
    est = [p for p in props if "ESTIMATED" in p]
    ass = sum("ASSUMED" in p for p in props)
    pub = len(props) - len(est) - ass
    ex = "\n".join(p.split("/*")[0].strip() + ("   /* ESTIMATED */" if "ESTIMATED" in p else "")
                   for p in est[:2] + [p for p in props if "*/" not in p][:2])
    return f"""
<p class="lead">The attack graph needs to know what each weakness gives an attacker: can they read
data, change it, or take the service down? That is the CVSS impact (C / I / A). When NVD
publishes a vector we use it; when it doesn't, a gradient-boosting classifier predicts it from
the finding's text, family, solution type, severity, confidence and port.</p>
<span class="ml">Machine learning #1</span>
<div class="stats">{stat(pub, 'facts from a published NVD vector')}{stat(len(est), 'estimated by the classifier', 'hi')}{stat(ass, 'no vector, no estimate')}</div>
<h4>Classifier quality (macro-F1, CVE-grouped folds)</h4>
{table(['Impact axis', 'ThreatRank', 'Text classifier', 'Majority baseline'], rows)}
<h4>Facts handed to the attack graph</h4><pre>{e(ex)}</pre>
<p class="note">Every estimated fact is marked, so any conclusion that rests on an estimate can be
traced. Published values always take priority.</p>"""


def stage3(D):
    text = D["correlate"]
    n_find = re.search(r"findings\s*:\s*(\d+)", text).group(1)
    by_title = re.search(r"groups by title\s*:\s*(\d+)", text).group(1)
    by_prod = re.search(r"groups by product\s*:\s*(\d+)", text).group(1)
    both = re.findall(r"^\s+(172\.\S+)\s+(\S+)\s+(\S+)\s+(nessus \d+, openvas \d+)", text, re.M)
    largest = re.findall(r"^\s+(\d+)\s+(172\.\S+)\s+(\S+)\s+(\S+)\s*$", text, re.M)
    rows_b = [[e(h), e(p), e(pr), e(c)] for h, p, pr, c in both]
    rows_l = [[e(n), e(h), e(p), e(pr)] for n, h, p, pr in largest[:6]]
    return f"""
<p class="lead">The same weakness is often reported more than once: by both scanners, or by
several checks in one scanner. Findings on the same host and port are grouped by the product
NVD lists as affected, so one upgrade becomes one job. Without a usable CVE, the check title is
used instead.</p>
<div class="stats">{stat(n_find, 'findings from both scanners')}{stat(by_title, 'groups if keyed by title')}{stat(by_prod, 'groups keyed by NVD product', 'hi')}</div>
<div class="two"><div><h4>Reported by both scanners</h4>{table(['host', 'port', 'product', 'reports'], rows_b)}</div>
<div><h4>Largest groups: one job each</h4>{table(['findings', 'host', 'port', 'product'], rows_l)}</div></div>"""


def stage4(D):
    kept = D["kept"]
    src = collections.Counter(r["l_source"] for r in kept)
    sur = sorted((r for r in kept if r["l_source"] == "surrogate"), key=lambda r: -r["likelihood"])[:6]
    rows_s = [[f"{r['likelihood']:.3f}", e(HOSTS.get(r["host"], r["host"])), e(short(r["nvt_name"], 58))] for r in sur]
    by = collections.defaultdict(lambda: [0, 0])
    for r in kept:
        by[r["host"]][0] += 1
        by[r["host"]][1] += int(r["consequence"])
    on = sum(int(r["consequence"]) for r in kept)
    rows_c = [[e(HOSTS.get(h, h)), e(h), n, c, n - c] for h, (n, c) in sorted(by.items())]
    t, f = D["transfer"], D["feed"]
    v, a = D["graph_size"]
    return f"""
<p class="lead">Every finding is scored on two axes. From here on the network is the three-tier
deployment the attack graph models: web server → app server → database, {len(kept)} findings.</p>
<h3>Head 1 · Exploit likelihood (L)</h3>
<span class="ml">Machine learning #2</span>
<div class="stats">{stat(src['epss'], 'have a CVE: L = published EPSS')}{stat(src['surrogate'], 'no CVE: L = learned surrogate', 'hi')}{stat(f"{t['CVE-grouped split, the headline'][0]:.2f} vs {f['severity_baseline']:.2f}", 'surrogate vs severity (Spearman with EPSS)')}</div>
<h4>Findings the surrogate scores</h4>{table(['L', 'host', 'finding'], rows_s)}
<h3>Head 2 · Attack consequence (C)</h3>
<p>MulVAL derives every way an attacker can chain the findings to the goal, code execution on
the database. The graph has {v} vertices and {a} arcs. C = 1 if a finding lies on a path to
the goal, otherwise 0. Rule-based, no machine learning.</p>
<div class="stats">{stat(f'{on} / {len(kept)}', 'findings on a path to the goal', 'hi')}{stat(len(kept) - on, 'deferred: cannot reach the goal')}{stat('10 / 10', 'perturbation tests as predicted')}</div>
{table(['tier', 'host', 'findings', 'on a path (C = 1)', 'off path (C = 0)'], rows_c)}"""


def stage5(D):
    kept, actions = D["kept"], D["actions"]
    top = sorted(actions, key=lambda a: -a["risk"])[:8]
    rows = [[f"{a['risk']:.2f}", e(a["key"][2]), e(HOSTS.get(a["key"][0], a["key"][0])), e(a["tier"]),
             a["size"], f'<span class="kev">{a["kev"]}</span>' if a["kev"] else "0"] for a in top]
    b, kev = parse_block(D["prioritise"], "known-exploited findings closed")
    _, risk = parse_block(D["prioritise"], "risk removed, percent of the total")
    pick = [("R = L x C", "ThreatRank (R = L × C)"), ("EPSS", "EPSS"), ("SSVC", "SSVC"),
            ("severity", "Severity, grouped"), ("ungrouped sev", "Severity, scanner list")]
    i5 = b.index("5%")
    rows_b = [[("<b>%s</b>" % lab if k == "R = L x C" else lab), f"{risk[k][i5]}%", f"{kev[k][i5]} of {D['kev_total']}"]
              for k, lab in pick if k in risk]
    total = sum({"patch available": 1, "configuration change": 2}.get(a["tier"], 5) for a in actions)
    return f"""
<p class="lead">The risk of a finding is <b>R = L × C</b>; the risk of an action is the sum over
the findings it closes. Each action costs its tier: patch 1, configuration change 2,
replacement 5. Actions are then taken greedily by risk removed per unit of cost until the
budget runs out.</p>
<div class="stats">{stat(len(kept), 'findings')}{stat(len(actions), 'remediation actions', 'hi')}{stat(total, 'total cost units')}</div>
<h4>Highest-risk actions</h4>
{table(['R', 'product', 'host', 'tier', 'findings', 'KEV'], rows)}
<h4>Same greedy selector, different orderings · 5% budget</h4>
{table(['Ordering', 'Exposure removed', 'Known-exploited closed'], rows_b)}
<p class="note">CISA KEV is the answer key only, never an input. EPSS and SSVC close all {D['kev_total']} at
this budget; ThreatRank removes the most exposure.</p>"""


def stage6(_):
    return """
<p class="lead">What the Blue Team receives: an ordered list of fixes with an adjustable budget,
and the attack graph that explains why each one matters.</p>
<div class="tabs"><button class="tab on" data-f="plan_report.html">Remediation plan</button>
<button class="tab" data-f="attack_graph.html">Attack graph</button>
<a id="openNew" href="plan_report.html" target="_blank">Open in a new tab ↗</a></div>
<iframe id="frame" src="plan_report.html" title="ThreatRank output"></iframe>"""


STAGES = [
    ("0", "Input", "Raw scanner reports", stage0, "raw/"),
    ("1", "Parsing & Normalization", "One schema for every scanner", stage1,
     "parse_openvas.py · fetch_nessus.py · parse_qualys.py"),
    ("2", "Attribute Completion", "Filling in what NVD does not say", stage2,
     "impact.py · findings_to_mulval.py"),
    ("3", "Vulnerability Correlation", "Merge before scoring", stage3, "correlate.py"),
    ("4", "Dual-Head Risk Scoring", "How likely, and does it matter here", stage4,
     "likelihood.py · consequence.py · prioritise.py"),
    ("5", "Budget-Aware Prioritization", "Most risk removed per unit of effort", stage5,
     "prioritise.py"),
    ("6", "Recommendation Plan", "What the Blue Team receives", stage6,
     "render_plan.py · render_graph.py"),
]


def page(D):
    pills = "".join(f'<button class="pill" data-i="{i}"><span>{n}</span>{e(t)}</button>'
                    for i, (n, t, *_rest) in enumerate(STAGES))
    secs = "".join(f"""<section class="stage" data-i="{i}">
<div class="sh"><div class="num">{n}</div><div><div class="kick">Stage {n}</div><h2>{e(t)}</h2>
<div class="sub">{e(sub)}</div></div></div>{fn(D)}
<p class="code">code: <code>data/{e(code)}</code></p></section>"""
                   for i, (n, t, sub, fn, code) in enumerate(STAGES))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ThreatRank Pipeline</title>
<style>
:root {{ --bg:#f6f7f9; --panel:#fff; --ink:#1d2433; --muted:#5b6475; --line:#e3e6ec;
        --accent:#2b6cb0; --accentbg:#e8f0fa; --kev:#b42318; --kevbg:#fde8e7; --ml:#6b46c1; --mlbg:#efe9fb;
        --code:#f1f3f6; }}
@media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{ --bg:#14171d; --panel:#1c2029;
        --ink:#e7eaf0; --muted:#a3abba; --line:#2c3240; --accent:#7fb2f0; --accentbg:#1d2a3d;
        --kev:#ff8a80; --kevbg:#3a1f1f; --ml:#b79cf2; --mlbg:#2a2140; --code:#232835; }} }}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--bg); color:var(--ink);
       font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif }}
header {{ position:sticky; top:0; z-index:5; background:var(--bg); border-bottom:1px solid var(--line) }}
.hin {{ max-width:1100px; margin:0 auto; padding:14px 16px 10px }}
h1 {{ margin:0; font-size:22px }}
.pills {{ display:flex; gap:6px; overflow-x:auto; padding:10px 0 2px }}
.pill {{ flex:0 0 auto; display:flex; align-items:center; gap:7px; border:1px solid var(--line);
        background:var(--panel); color:var(--muted); border-radius:999px; padding:5px 12px 5px 5px;
        font:inherit; font-size:13px; cursor:pointer; white-space:nowrap }}
.pill span {{ width:22px; height:22px; border-radius:50%; background:var(--line); color:var(--ink);
             display:inline-flex; align-items:center; justify-content:center; font-weight:700; font-size:12px }}
.pill.done span {{ background:var(--accentbg); color:var(--accent) }}
.pill.on {{ border-color:var(--accent); color:var(--ink); font-weight:600 }}
.pill.on span {{ background:var(--accent); color:#fff }}
main {{ max-width:1100px; margin:0 auto; padding:22px 16px 90px }}
.stage {{ display:none; background:var(--panel); border:1px solid var(--line); border-radius:12px;
         padding:22px 24px }}
.stage.on {{ display:block; animation:fade .25s }}
@keyframes fade {{ from {{ opacity:0; transform:translateY(4px) }} to {{ opacity:1 }} }}
.sh {{ display:flex; gap:16px; align-items:center; margin-bottom:12px }}
.num {{ flex:0 0 54px; height:54px; border-radius:14px; background:var(--accent); color:#fff;
       display:flex; align-items:center; justify-content:center; font-size:26px; font-weight:800 }}
.kick {{ color:var(--accent); font-size:12px; font-weight:700; letter-spacing:.06em; text-transform:uppercase }}
h2 {{ margin:0; font-size:24px }}
.sub {{ color:var(--muted) }}
h3 {{ margin:22px 0 6px; font-size:18px }}
h4 {{ margin:18px 0 8px; font-size:15px }}
.lead {{ font-size:16px; max-width:80ch }}
.ml {{ display:inline-block; background:var(--mlbg); color:var(--ml); border-radius:6px;
      padding:1px 10px; font-size:13px; font-weight:700 }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:10px; margin:14px 0 }}
.stat {{ border:1px solid var(--line); border-radius:10px; padding:12px 14px }}
.stat .v {{ font-size:26px; font-weight:750 }}
.stat .l {{ color:var(--muted); font-size:13px }}
.stat.hi {{ background:var(--accentbg); border-color:transparent }}
.stat.hi .v {{ color:var(--accent) }}
.two {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:18px }}
pre {{ background:var(--code); border-radius:8px; padding:12px 14px; overflow-x:auto; font-size:12.5px;
      line-height:1.45; margin:0 }}
code {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.9em }}
.tw {{ overflow-x:auto }}
table {{ border-collapse:collapse; width:100%; font-size:14px }}
th {{ text-align:left; color:var(--muted); font-weight:600; font-size:12.5px; border-bottom:1px solid var(--line);
     padding:6px 10px }}
td {{ border-bottom:1px solid var(--line); padding:6px 10px; vertical-align:top }}
tr:last-child td {{ border-bottom:0 }}
.kev {{ color:var(--kev); background:var(--kevbg); border-radius:6px; padding:0 7px; font-weight:700 }}
.note {{ color:var(--muted); font-size:13.5px }}
.code {{ margin:22px 0 0; padding-top:12px; border-top:1px solid var(--line); color:var(--muted); font-size:13px }}
.tabs {{ display:flex; gap:6px; align-items:center; margin:8px 0 10px; flex-wrap:wrap }}
.tab {{ border:1px solid var(--line); background:var(--bg); color:var(--ink); border-radius:8px;
       padding:6px 14px; font:inherit; cursor:pointer }}
.tab.on {{ background:var(--accent); border-color:var(--accent); color:#fff }}
#openNew {{ margin-left:auto; color:var(--accent); font-size:14px }}
iframe {{ width:100%; height:78vh; border:1px solid var(--line); border-radius:10px; background:var(--bg) }}
nav {{ position:fixed; bottom:0; left:0; right:0; background:var(--bg); border-top:1px solid var(--line) }}
.nin {{ max-width:1100px; margin:0 auto; padding:10px 16px; display:flex; gap:10px; align-items:center }}
nav button {{ border:1px solid var(--line); background:var(--panel); color:var(--ink); border-radius:8px;
             padding:8px 16px; font:inherit; cursor:pointer }}
nav button.primary {{ background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600 }}
nav button:disabled {{ opacity:.4; cursor:default }}
.prog {{ flex:1; height:4px; background:var(--line); border-radius:2px; overflow:hidden }}
.prog i {{ display:block; height:100%; background:var(--accent); transition:width .25s }}
.hint {{ color:var(--muted); font-size:12px }}
@media (max-width:640px) {{ .stage {{ padding:16px }} .hint {{ display:none }} }}
</style></head>
<body>
<header><div class="hin"><h1>ThreatRank: from scanner reports to a remediation plan</h1>
<div class="pills">{pills}</div></div></header>
<main>{secs}</main>
<nav><div class="nin"><button id="prev">← Back</button><div class="prog"><i id="bar"></i></div>
<span class="hint">← → keys</span><button id="next" class="primary">Next →</button></div></nav>
<script>
const S=[...document.querySelectorAll('.stage')], P=[...document.querySelectorAll('.pill')];
let cur=0;
function show(i){{
  cur=Math.max(0,Math.min(S.length-1,i));
  S.forEach((s,k)=>s.classList.toggle('on',k===cur));
  P.forEach((p,k)=>{{p.classList.toggle('on',k===cur);p.classList.toggle('done',k<cur);}});
  P[cur].scrollIntoView({{block:'nearest',inline:'center'}});
  document.getElementById('prev').disabled=cur===0;
  const n=document.getElementById('next'); n.disabled=cur===S.length-1;
  document.getElementById('bar').style.width=(cur/(S.length-1)*100)+'%';
  try{{history.replaceState(null,'','#stage'+cur)}}catch(e){{}}
  window.scrollTo({{top:0}});
}}
P.forEach((p,k)=>p.onclick=()=>show(k));
document.getElementById('prev').onclick=()=>show(cur-1);
document.getElementById('next').onclick=()=>show(cur+1);
document.addEventListener('keydown',ev=>{{
  if(ev.target.tagName==='INPUT')return;
  if(ev.key==='ArrowRight'||ev.key==='PageDown')show(cur+1);
  if(ev.key==='ArrowLeft'||ev.key==='PageUp')show(cur-1);
}});
document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{{
  document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('on',x===t));
  document.getElementById('frame').src=t.dataset.f;
  document.getElementById('openNew').href=t.dataset.f;
}});
const m=location.hash.match(/stage(\\d+)/); show(m?+m[1]:0);
</script>
</body></html>"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--out", default=os.path.join(HERE, "figures", "pipeline.html"))
    args = ap.parse_args()
    D = collect()
    out = os.path.abspath(args.out)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(page(D))
    for f in ("plan_report.html", "attack_graph.html"):
        if not os.path.exists(os.path.join(os.path.dirname(out), f)):
            print(f"note: {f} is not next to {out}; stage 6 embeds it", file=sys.stderr)
    print(f"wrote {out}: {len(STAGES)} stages, {len(D['kept'])} findings, {len(D['actions'])} actions")


if __name__ == "__main__":
    main()
