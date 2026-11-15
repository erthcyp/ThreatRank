#!/usr/bin/env python3
"""Render a remediation plan written by prioritise.py as a one-page, interactive HTML report.

prioritise.py writes the plan as a CSV, one row per action in the order it should be done. That
is the pipeline's output and what a ticketing system would import. This turns it into a page a
person can read: a summary of what a budget buys, then one card per action saying what to fix,
what it costs, what it closes and why it sits where it does. A slider changes the budget in the
browser, re-running the same greedy rule as prioritise.plan over the same rows. The page adds no
number of its own; every value comes from the CSV.

    python3 prioritise.py --graph ... --findings ... -o processed/plan_lab3.csv
    python3 render_plan.py processed/plan_lab3.csv --budget 0.05 -o figures/plan_report.html
"""

import argparse
import csv
import datetime
import html
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))

TIER_LABEL = {"patch available": "Patch", "configuration change": "Configuration change",
              "no fix available": "Replace or remove"}
SCANNER_LABEL = {"openvas": "OpenVAS", "nessus": "Nessus", "qualys": "Qualys"}
# Product names arrive lower-cased: from NVD as vendor:product, or parsed from a check title.
WORD = {"apache": "Apache", "http": "HTTP", "http/2": "HTTP/2", "php": "PHP",
        "wordpress": "WordPress", "mysql": "MySQL", "oracle": "Oracle", "openssl": "OpenSSL",
        "openssh": "OpenSSH", "jquery": "jQuery", "curl": "curl", "weblogic": "WebLogic",
        "debian": "Debian", "linux": "Linux", "os": "OS", "eol": "EOL", "seol": "SEoL",
        "dos": "DoS", "xss": "XSS", "rce": "RCE", "sql": "SQL", "tcp": "TCP", "icmp": "ICMP",
        "ip": "IP", "crlf": "CRLF", "mu": "MU", "server": "Server"}


def product(raw):
    name = raw.split(":", 1)[1].replace("_", " ") if ":" in raw and " " not in raw else raw
    words = []
    for w in name.split(" "):
        key = w.strip("()',").lower()
        if key in WORD:
            w = w.lower().replace(key, WORD[key])
        elif re.match(r"\(?cve-", w, re.I):
            w = w.upper()
        words.append(w)
    out = " ".join(words)
    return out[:1].upper() + out[1:]


def likelihood_text(raw):
    parts = []
    for item in (raw or "").split("+"):
        m = re.match(r"\s*(epss|surrogate)\s+(\d+)", item)
        if m:
            src = "EPSS" if m.group(1) == "epss" else "learned surrogate"
            parts.append(f"{src} for {m.group(2)} finding{'s' if m.group(2) != '1' else ''}")
    return "Exploit likelihood: " + (", ".join(parts) if parts else "n/a")


def num(row, key, cast=float):
    try:
        return cast(row.get(key) or 0)
    except ValueError:
        return cast(0)


def card(r, index):
    e = html.escape
    closed = num(r, "findings_closed", int)
    kev = num(r, "known_exploited", int)
    goal = r.get("reaches_goal", "")
    reached = goal.split("/")[0] if "/" in goal else goal
    reasons = [f"<b>{e(reached)}</b> of {closed} findings lie on a path to the security goal"]
    # Written only when prioritise.py ran with --correlate; blank otherwise, and a blank must not
    # be shown as zero.
    if (r.get("remote_exploit") or "").strip() and (r.get("priv_escalation") or "").strip():
        reasons.append(f"<b>{num(r, 'remote_exploit', int)}</b> can be exploited remotely, "
                       f"<b>{num(r, 'priv_escalation', int)}</b> lead to privilege escalation")
    scanners = " and ".join(SCANNER_LABEL.get(s, s) for s in r.get("scanners", "").split("+") if s)
    reasons += [e(likelihood_text(r.get("likelihood_from"))), f"Reported by {e(scanners)}"]
    badge = (f'<span class="kev">{kev} known-exploited</span>' if kev
             else '<span class="nokev">no known-exploited</span>')
    return f"""
<article class="card" data-i="{index}">
  <div class="rank">{e(r['rank'])}</div>
  <div class="body">
    <div class="head">
      <h3>{e(product(r.get('product', '')))} <span class="where">{e(r.get('host', ''))}:{e(r.get('port', ''))}</span></h3>
      <span class="state"></span>
    </div>
    <div class="facts">
      <span><b>{e(TIER_LABEL.get(r.get('tier', ''), r.get('tier', '')))}</b></span>
      <span>cost <b>{num(r, 'cost'):g}</b></span>
      <span>closes <b>{closed}</b> findings</span>
      {badge}
      <span>risk removed <b>{num(r, 'risk_removed'):.2f}</b></span>
    </div>
    <ul>{''.join(f'<li>{x}</li>' for x in reasons)}</ul>
    <p class="example">e.g. {e(r.get('top_finding', ''))}</p>
  </div>
</article>"""


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("plan", help="plan CSV written by prioritise.py --out")
    ap.add_argument("--budget", type=float, default=0.05,
                    help="initial fraction of the total cost (default 0.05); adjustable on the page")
    ap.add_argument("--top", type=int, default=12,
                    help="actions shown before 'show all' (default 12)")
    ap.add_argument("-o", "--out", default=os.path.join(HERE, "figures", "plan_report.html"))
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.plan, encoding="utf-8")))
    data = [{"cost": num(r, "cost"), "risk": num(r, "risk_removed"),
             "kev": num(r, "known_exploited", int), "found": num(r, "findings_closed", int)}
            for r in rows]
    hosts = sorted({r.get("host", "") for r in rows})
    total_cost = sum(d["cost"] for d in data)
    cards = "".join(card(r, i) for i, r in enumerate(rows))
    pct0 = max(1, min(100, round(args.budget * 100)))

    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ThreatRank Remediation Plan</title>
<style>
:root {{ --bg:#f6f7f9; --panel:#fff; --ink:#1d2433; --muted:#5b6475; --line:#e3e6ec;
        --accent:#2b6cb0; --kev:#b42318; --kevbg:#fde8e7; --ok:#1f7a4d; --okbg:#e3f4ea; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#14171d; --panel:#1c2029; --ink:#e7eaf0;
        --muted:#a3abba; --line:#2c3240; --accent:#7fb2f0; --kev:#ff8a80; --kevbg:#3a1f1f;
        --ok:#7ed3a4; --okbg:#1d3328; }} }}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--bg); color:var(--ink);
       font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif }}
main {{ max-width:960px; margin:0 auto; padding:28px 16px 48px }}
header h1 {{ margin:0; font-size:26px }}
header p {{ margin:4px 0 0; color:var(--muted) }}
.control {{ background:var(--panel); border:1px solid var(--line); border-radius:10px;
           padding:14px 16px; margin:20px 0 0 }}
.control .row {{ display:flex; align-items:center; gap:14px; flex-wrap:wrap }}
.control label {{ font-weight:600 }}
.control input[type=range] {{ flex:1; min-width:180px; accent-color:var(--accent) }}
.control output {{ font-weight:700; font-size:20px; min-width:70px; text-align:right }}
.presets {{ display:flex; gap:6px; flex-wrap:wrap; margin-top:10px }}
.presets button {{ border:1px solid var(--line); background:var(--bg); color:var(--ink);
                  border-radius:6px; padding:4px 10px; font:inherit; font-size:13px; cursor:pointer }}
.presets button.on {{ background:var(--accent); border-color:var(--accent); color:#fff }}
.summary {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px;
           margin:14px 0 26px }}
.stat {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px }}
.stat .v {{ font-size:26px; font-weight:700 }}
.stat .l {{ color:var(--muted); font-size:13px }}
h2 {{ font-size:18px; margin:0 0 12px }}
.card {{ display:flex; gap:14px; background:var(--panel); border:1px solid var(--line);
        border-radius:10px; padding:14px 16px; margin-bottom:10px; transition:opacity .2s }}
.card.dim {{ opacity:.6 }}
.card.hide {{ display:none }}
.rank {{ flex:0 0 36px; height:36px; border-radius:50%; background:var(--accent); color:#fff;
        display:flex; align-items:center; justify-content:center; font-weight:700 }}
.body {{ flex:1; min-width:0 }}
.head {{ display:flex; justify-content:space-between; gap:10px; align-items:baseline; flex-wrap:wrap }}
h3 {{ margin:0; font-size:17px }}
.where {{ color:var(--muted); font-weight:400; font-size:14px }}
.facts {{ display:flex; flex-wrap:wrap; gap:6px 14px; margin:6px 0; color:var(--muted); font-size:14px }}
.facts b {{ color:var(--ink) }}
.kev {{ color:var(--kev); background:var(--kevbg); border-radius:6px; padding:0 8px; font-weight:600 }}
.nokev {{ color:var(--muted) }}
.state .in {{ color:var(--ok); background:var(--okbg); border-radius:6px; padding:1px 8px; font-size:13px; font-weight:600 }}
.state .out {{ color:var(--muted); border:1px solid var(--line); border-radius:6px; padding:0 8px; font-size:13px }}
ul {{ margin:6px 0 4px; padding-left:18px; font-size:14px }}
.example {{ margin:4px 0 0; color:var(--muted); font-size:13px; overflow-wrap:anywhere }}
#more {{ border:1px solid var(--line); background:var(--panel); color:var(--ink); border-radius:8px;
        padding:8px 14px; font:inherit; cursor:pointer }}
footer {{ margin-top:22px; color:var(--muted); font-size:13px }}
</style></head>
<body><main>
<header>
  <h1>ThreatRank Remediation Plan</h1>
  <p>{len(rows)} remediation actions over {len(hosts)} hosts, ordered by risk removed per unit of
     cost. <span id="budgetText"></span></p>
</header>
<section class="control">
  <div class="row">
    <label for="budget">Remediation budget</label>
    <input type="range" id="budget" min="1" max="100" step="1" value="{pct0}">
    <output id="budgetOut" for="budget"></output>
  </div>
  <div class="presets">{''.join(f'<button data-p="{p}">{p}%</button>' for p in (1, 2, 3, 5, 10, 25, 50, 100))}</div>
</section>
<section class="summary">
  <div class="stat"><div class="v" id="sActions"></div><div class="l">actions within budget</div></div>
  <div class="stat"><div class="v" id="sExposure"></div><div class="l">of exposure removed (L &times; C)</div></div>
  <div class="stat"><div class="v" id="sKev"></div><div class="l">known-exploited (CISA KEV) findings closed</div></div>
  <div class="stat"><div class="v" id="sFound"></div><div class="l">findings closed</div></div>
</section>
<h2>Actions, in the order to do them</h2>
<div id="cards">{cards}</div>
<button id="more" type="button"></button>
<footer>Generated {datetime.date.today().isoformat()} by render_plan.py from {html.escape(os.path.basename(args.plan))}.
Cost tiers: patch 1, configuration change 2, replace or remove 5. Selection takes actions in plan
order and skips any that no longer fit, the same rule prioritise.py uses. Exposure is ThreatRank's
own L &times; C score; known-exploited counts use the CISA KEV catalogue.</footer>
</main>
<script>
const ROWS = {json.dumps(data)};
const TOTAL_COST = {total_cost!r}, TOP = {args.top};
const totalRisk = ROWS.reduce((s, r) => s + r.risk, 0) || 1e-9;
const totalKev = ROWS.reduce((s, r) => s + r.kev, 0);
const totalFound = ROWS.reduce((s, r) => s + r.found, 0);
const cards = [...document.querySelectorAll(".card")];
const slider = document.getElementById("budget"), more = document.getElementById("more");
let showAll = false;
const fmt = x => (Math.round(x * 10) / 10).toString();

function update() {{
  const pct = +slider.value, budget = TOTAL_COST * pct / 100;
  let spent = 0, n = 0, risk = 0, kev = 0, found = 0;
  ROWS.forEach((r, i) => {{
    const fits = spent + r.cost <= budget + 1e-9;
    if (fits) {{ spent += r.cost; n++; risk += r.risk; kev += r.kev; found += r.found; }}
    const c = cards[i];
    c.classList.toggle("dim", !fits);
    c.querySelector(".state").innerHTML = fits ? '<span class="in">In budget</span>'
                                               : '<span class="out">Next</span>';
  }});
  document.getElementById("budgetOut").textContent = pct + "%";
  document.getElementById("budgetText").textContent =
    "Budget: " + pct + "% of the total (" + fmt(budget) + " of " + fmt(TOTAL_COST) + " cost units).";
  document.getElementById("sActions").textContent = n;
  document.getElementById("sExposure").textContent = Math.round(100 * risk / totalRisk) + "%";
  document.getElementById("sKev").textContent = kev + " / " + totalKev;
  document.getElementById("sFound").textContent = found + " / " + totalFound;
  document.querySelectorAll(".presets button").forEach(b => b.classList.toggle("on", +b.dataset.p === pct));
  const visible = showAll ? ROWS.length : Math.max(TOP, n);
  cards.forEach((c, i) => c.classList.toggle("hide", i >= visible));
  more.style.display = visible >= ROWS.length && !showAll ? "none" : "";
  more.textContent = showAll ? "Show fewer actions" : "Show all " + ROWS.length + " actions";
}}
slider.addEventListener("input", update);
document.querySelectorAll(".presets button").forEach(b =>
  b.addEventListener("click", () => {{ slider.value = b.dataset.p; update(); }}));
more.addEventListener("click", () => {{ showAll = !showAll; update(); }});
update();
</script>
</body></html>
"""
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    open(args.out, "w", encoding="utf-8").write(page)
    budget = total_cost * args.budget
    spent = risk = kev = 0
    for d in data:
        if spent + d["cost"] <= budget + 1e-9:
            spent += d["cost"]; risk += d["risk"]; kev += d["kev"]
    total_risk = sum(d["risk"] for d in data) or 1e-9
    print(f"wrote {args.out}: at {args.budget:.0%}, {100 * risk / total_risk:.0f}% of exposure, "
          f"{kev}/{sum(d['kev'] for d in data)} KEV; the budget is adjustable on the page")


if __name__ == "__main__":
    main()
