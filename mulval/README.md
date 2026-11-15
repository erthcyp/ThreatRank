# The attack graph engine, and what is and is not kept here

MulVAL is not vendored into this repository. It is a third-party tool with its own licence and
history, and copying it here would fork it silently: a reader could no longer tell which version
produced a result. What is kept is the pin, the inputs we wrote, and the outputs a run produced.

## What MulVAL is, and what it is not

**It is a deduction engine, not a source of truth.** It takes facts this pipeline generated and a
topology we declared, applies its own rule base, and reports what follows. It guarantees only
that *if these facts hold, these conclusions follow*. It does not know whether the facts hold,
and a wrong topology yields a wrong reachability with no warning.

The three external answers this project is graded against are EPSS, the CVSS vectors NVD
publishes, and the CISA KEV catalogue. **The attack graph is not a fourth.** Verifying its
conclusions would mean attempting the chain in the lab and observing whether the database host is
actually reached, which has not been done and is the clearest gap a reader could close.

## Pin

```
https://github.com/risksense/mulval.git   commit 07d279f
XSB Prolog, installed at ~/XSB, on PATH as $HOME/XSB/bin
```

`setup.sh` clones that commit and reports what else is needed. It does not build XSB: that is a
separate dependency with its own installer, and pretending otherwise would produce a script that
fails halfway.

## Layout

```
mulval/setup.sh          clone the pinned commit, check for XSB and graphviz
mulval/cases/lab3/       our input: input.P and the topology it came from
mulval/cases/lab3/out/   what a run produced: VERTICES.CSV, ARCS.CSV, AttackGraph.*
```

Our own case files previously lived inside the cloned tree, untracked by either repository. A
single `git clean -fd` there would have removed the graph every number in `scans.md` rests on.

## Reproducing a run

```bash
cd mulval && ./setup.sh                       # clones to ~/mulval at the pinned commit
export MULVALROOT=$HOME/mulval
export PATH=$MULVALROOT/utils:$HOME/XSB/bin:$PATH

cd ../data
python3 findings_to_mulval.py \
    --findings processed/findings_openvas_b2.csv \
    --topology topology_lab3.json \
    --predicted processed/impact_estimates.csv \
    -o ../mulval/cases/lab3/input.P

cd ../mulval/cases/lab3 && graph_gen.sh input.P -v -p
```

`graph_gen.sh` writes its output beside the input, which is why `out/` holds a copy rather than
the working directory itself.
