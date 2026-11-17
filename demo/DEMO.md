# Step-by-step demo

Walks through the ThreatRank pipeline one stage at a time, showing what each stage produces and
where its code lives. Each step is a short script that calls the real pipeline code; nothing in
`data/` is modified (live outputs go to `demo/out/`, which is gitignored).

```bash
./demo/run_all.sh              # every step, press Enter between steps (about 35 s of compute)
./demo/2_likelihood.sh         # or any single step
```

**Live or recorded.** Steps marked `[LIVE]` recompute from the committed data in a few seconds.
Steps marked `[RECORDED]` show results committed in the repository because recomputing them takes
minutes (training the two models) or needs XSB (building the MulVAL graph). `./reproduce.sh`
regenerates all of them.

## Steps

| # | Script | Stage | What it shows | Code |
|---|---|---|---|---|
| 0 | [0_parse_and_normalize.sh](0_parse_and_normalize.sh) | Parse and normalise | Raw OpenVAS XML and Nessus JSON parsed live into one CSV schema, identical byte for byte to the committed files | [parse_openvas.py:143](../data/parse_openvas.py#L143), [fetch_nessus.py:101](../data/fetch_nessus.py#L101), [parse_qualys.py:75](../data/parse_qualys.py#L75) |
| 1 | [1_correlate.sh](1_correlate.sh) | Correlate | OpenVAS and Nessus findings keyed by NVD's affected product; groups reported by both scanners | [correlate.py:68](../data/correlate.py#L68), [correlate.py:135](../data/correlate.py#L135) |
| 2 | [2_likelihood.sh](2_likelihood.sh) | Likelihood L | 217 findings take EPSS, 12 without a CVE take the surrogate; surrogate quality 0.59 vs severity 0.44 (recorded) | [likelihood.py:123](../data/likelihood.py#L123), [likelihood.py:178](../data/likelihood.py#L178), [prioritise.py:282](../data/prioritise.py#L282) |
| 3 | [3_impact.sh](3_impact.sh) | Impact classification | Classifier macro-F1 vs baselines (recorded); which graph facts use the NVD vector, the classifier or neither | [impact.py:106](../data/impact.py#L106), [findings_to_mulval.py:156](../data/findings_to_mulval.py#L156), [input.P](../mulval/cases/lab3/input.P) |
| 4 | [4_attack_graph.sh](4_attack_graph.sh) | Consequence C | The recorded MulVAL graph (357 vertices, 676 arcs); 169 of 229 findings on a path to the goal | [consequence.py:69](../data/consequence.py#L69), [consequence.py:119](../data/consequence.py#L119), [prioritise.py:298](../data/prioritise.py#L298) |
| 5 | [5_risk_and_actions.sh](5_risk_and_actions.sh) | Risk and actions | R = L × C per finding; 229 findings grouped into 47 actions; what is inside the top action | [prioritise.py:302](../data/prioritise.py#L302), [prioritise.py:136](../data/prioritise.py#L136), [prioritise.py:85](../data/prioritise.py#L85) |
| 6 | [6_prioritize.sh](6_prioritize.sh) | Prioritise | Greedy R / cost under a budget, graded against severity, EPSS, SSVC and VMC; the plan at 5% | [prioritise.py:166](../data/prioritise.py#L166), [prioritise.py:211](../data/prioritise.py#L211) |
| 7 | [7_report.sh](7_report.sh) | Report | Renders the HTML plan report (adjustable budget) and the interactive attack graph, then opens them | [render_plan.py:105](../data/render_plan.py#L105), [render_graph.py:69](../data/render_graph.py#L69) |

## Numbers to expect

| Step | Number |
|---|---|
| 0 | OpenVAS group B: 306 findings (Log included); identical to `data/processed/` |
| 1 | 279 findings (Log excluded) in 54 groups; 3 groups reported by both scanners |
| 2 | 217 EPSS, 12 surrogate; Spearman 0.59 vs 0.44 |
| 3 | macro-F1 0.42 / 0.38 / 0.47; 216 published, 10 estimated, 2 assumed |
| 4 | 169 of 229 findings reach the goal |
| 5 | 47 actions; top three: Apache (.110), Apache (.111), WordPress (.110) |
| 6 | 5% budget: 58% of exposure, 5 of 7 KEV; severity 34% and 4 (grouped), 1% and 0 (ungrouped) |
| 7 | Unreachable work by goal: 17, 23, 29 of 68 cost units |

Steps 2 to 7 use the three attack-graph hosts (web .110, app .111, database .112), which is why
the count drops from the whole of group B in steps 0 and 1 to 229 findings.

## Presenting from VS Code

1. Open this file with **Markdown: Open Preview** (`Ctrl+Shift+V`) on the left; the code links open
   the function the step runs.
2. Open a terminal on the right (`Ctrl+` `` ` ``) and run `./demo/run_all.sh`; press Enter to move
   to the next step.
3. At step 7 the two pages open in the browser. If they do not, open the paths it prints.
