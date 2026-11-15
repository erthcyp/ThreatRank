#!/usr/bin/env python3
"""Render a remediation plan written by prioritise.py as a one-page HTML report.

prioritise.py writes the plan as a CSV, one row per action in the order it should be done. That
is the pipeline's output and what a ticketing system would import. This turns it into a page a
person can read: a summary of what a budget buys, then one card per action saying what to fix,
what it costs, what it closes and why it sits where it does. It adds no number of its own; every
value comes from the CSV.

    python3 prioritise.py --graph ... --findings ... --correlate -o processed/plan_merged.csv
    python3 render_plan.py processed/plan_merged.csv --budget 0.05 -o figures/plan_report.html
"""

import argparse
import csv
import datetime
import html
import os

HERE = os.path.dirname(os.path.abspath(__file__))

TIER_LABEL = {"patch available": "Patch", "configuration change": "Configuration change",
              "no fix available": "Replace or remove"}
PRODUCT_LABEL = {"apache:http_server": "Apache HTTP Server", "wordpress:wordpress": "WordPress",
                 "php:php": "PHP", "oracle:mysql": "Oracle MySQL", "openbsd:openssh": "OpenSSH",
                 "openssl:openssl": "OpenSSL", "jquery:jquery": "jQuery"}


def product(raw):
    if raw in PRODUCT_LABEL:
        return PRODUCT_LABEL[raw]
    if ":" in raw:
        return raw.split(":", 1)[1].replace("_", " ").title()
    return raw[:1].upper() + raw[1:]


def num(row, key, cast=float):
    try:
        return cast(row.get(key) or 0)
    except ValueError:
        return cast(0)


def select(rows, budget):
    """The same greedy rule as prioritise.plan: in plan order, take what still fits."""
    chosen, spent = set(), 0.0
    for r in rows:
        c = num(r, "cost")
        if spent + c <= budget + 1e-9:
            chosen.add(r["rank"])
            spent += c
    return chosen, spent


def card(r, within):
    e = html.escape
    closed = num(r, "findings_closed", int)
    kev = num(r, "known_exploited", int)
    goal = r.get("reaches_goal", "")
    reached = goal.split("/")[0] if "/" in goal else goal
    reasons = [
        f"<b>{e(reached)}</b> of {closed} findings lie on a path to the security goal",
        f"<b>{num(r, 'remote_exploit', int)}</b> can be exploited remotely, "
        f"<b>{num(r, 'priv_escalation', int)}</b> lead to privilege escalation",
        f"Exploit likelihood from {e(r.get('likelihood_from', '').replace('+', ' + '))}",
        f"Reported by {e(r.get('scanners', '').replace('+', ' and '))}",
    ]
    badge = (f'<span class="kev">{kev} known-exploited</span>' if kev
             else '<span class="nokev">no known-exploited</span>')
    state = '<span class="in">In budget</span>' if within else '<span class="out">Next</span>'
    return f"""
<article class="card{' dim' if not within else ''}">
  <div class="rank">{e(r['rank'])}</div>
  <div class="body">
    <div class="head">
      <h3>{e(product(r.get('product', '')))} <span class="where">{e(r.get('host', ''))}:{e(r.get('port', ''))}</span></h3>
      {state}
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
                    help="fraction of the total cost to spend (default 0.05)")
    ap.add_argument("--top", type=int, default=12, help="actions to show as cards")
    ap.add_argument("-o", "--out", default=os.path.join(HERE, "figures", "plan_report.html"))
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.plan, encoding="utf-8")))
    total_cost = sum(num(r, "cost") for r in rows)
    total_risk = sum(num(r, "risk_removed") for r in rows) or 1e-9
    total_findings = sum(num(r, "findings_closed", int) for r in rows)
    total_kev = sum(num(r, "known_exploited", int) for r in rows)
    budget = total_cost * args.budget
    chosen, spent = select(rows, budget)
    sel = [r for r in rows if r["rank"] in chosen]
    risk = sum(num(r, "risk_removed") for r in sel)
    kev = sum(num(r, "known_exploited", int) for r in sel)
    found = sum(num(r, "findings_closed", int) for r in sel)
    hosts = sorted({r.get("host", "") for r in rows})

    cards = "".join(card(r, r["rank"] in chosen) for r in rows[:args.top])
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
.summary {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px;
           margin:22px 0 26px }}
.stat {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px }}
.stat .v {{ font-size:26px; font-weight:700 }}
.stat .l {{ color:var(--muted); font-size:13px }}
h2 {{ font-size:18px; margin:0 0 12px }}
.card {{ display:flex; gap:14px; background:var(--panel); border:1px solid var(--line);
        border-radius:10px; padding:14px 16px; margin-bottom:10px }}
.card.dim {{ opacity:.72 }}
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
.in {{ color:var(--ok); background:var(--okbg); border-radius:6px; padding:1px 8px; font-size:13px; font-weight:600 }}
.out {{ color:var(--muted); border:1px solid var(--line); border-radius:6px; padding:0 8px; font-size:13px }}
ul {{ margin:6px 0 4px; padding-left:18px; font-size:14px }}
.example {{ margin:4px 0 0; color:var(--muted); font-size:13px; overflow-wrap:anywhere }}
footer {{ margin-top:22px; color:var(--muted); font-size:13px }}
</style></head>
<body><main>
<header>
  <h1>ThreatRank Remediation Plan</h1>
  <p>{len(rows)} remediation actions over {len(hosts)} hosts, ordered by risk removed per unit of
     cost. Budget shown: {args.budget:.0%} of the total ({budget:g} of {total_cost:g} cost units).</p>
</header>
<section class="summary">
  <div class="stat"><div class="v">{len(sel)}</div><div class="l">actions within budget</div></div>
  <div class="stat"><div class="v">{100 * risk / total_risk:.0f}%</div><div class="l">of exposure removed (L &times; C)</div></div>
  <div class="stat"><div class="v">{kev} / {total_kev}</div><div class="l">known-exploited (CISA KEV) findings closed</div></div>
  <div class="stat"><div class="v">{found} / {total_findings}</div><div class="l">findings closed</div></div>
</section>
<h2>Actions, in the order to do them</h2>
{cards}
<footer>Generated {datetime.date.today().isoformat()} by render_plan.py from {html.escape(os.path.basename(args.plan))}.
Cost tiers: patch 1, configuration change 2, replace or remove 5. Exposure is ThreatRank's own
L &times; C score; known-exploited counts use the CISA KEV catalogue.
Showing the first {min(args.top, len(rows))} of {len(rows)} actions.</footer>
</main></body></html>
"""
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    open(args.out, "w", encoding="utf-8").write(page)
    print(f"wrote {args.out}: {len(sel)} actions within a {args.budget:.0%} budget, "
          f"{100 * risk / total_risk:.0f}% of exposure, {kev}/{total_kev} KEV")


if __name__ == "__main__":
    main()
