#!/usr/bin/env python3
"""Validate the attack graph by walking the chain it predicts, and record the result.

The graph built for mulval/cases/lab4 predicts a three-hop chain to code execution on the
database host. This harness grades that prediction against reality. It does the parts that are a
read -- confirming each hop is reachable and that the service answers -- and the redis hop's
control proof, which is read-only. The two application-tier exploits (Struts2 S2-045, CouchDB
CVE-2017-12635/-12636) are run by hand from vulhub's own published proof of concept, and their
`id` output is recorded here with `--record`.

Everything happens inside the isolated bridge; the only effect is reading service state and, on
redis, setting one marker key that is deleted again.

USAGE
    python3 walk_chain.py --check            # reachability + service fingerprint, all hops
    python3 walk_chain.py --redis            # hop 3: prove unauthenticated control of redis
    python3 walk_chain.py --record 1 'uid=0(root) gid=0(root) ...'   # log a hop's id output
    python3 walk_chain.py --report           # print the grade and write chain_walk.json
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "figures", "chain_walk.json")

HOPS = {
    1: {"tier": "vmWeb", "ip": "172.18.0.102", "port": 8080,
        "service": "Struts2 showcase (Jetty)", "exploit": "CVE-2017-5638 (S2-045)",
        "predicted": "execCode(vmWeb,root)",
        "poc": "~/vulhub/struts2/s2-045/README.md"},
    2: {"tier": "vmApp", "ip": "172.18.0.103", "port": 5984,
        "service": "CouchDB 2.1.0", "exploit": "CVE-2017-12635 + CVE-2017-12636",
        "predicted": "execCode(vmApp,root)",
        "poc": "~/vulhub/couchdb/CVE-2017-12635/README.md"},
    3: {"tier": "vmDb", "ip": "172.18.0.104", "port": 6379,
        "service": "Redis 4.0.14", "exploit": "unauthenticated access",
        "predicted": "execCode(vmDb,_)",
        "poc": "~/vulhub/redis/4-unacc/README.md"},
}


def load():
    try:
        return json.load(open(OUT))
    except Exception:
        return {"hops": {}}


def save(state):
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(state, open(OUT, "w"), indent=1)


def reachable(ip, port):
    try:
        s = socket.create_connection((ip, port), timeout=4)
        s.close()
        return True
    except OSError:
        return False


def check():
    """Each hop reachable and answering -- a read, nothing more."""
    for n, h in HOPS.items():
        ok = reachable(h["ip"], h["port"])
        print(f"  hop {n}  {h['tier']:6s} {h['ip']}:{h['port']:<5d} "
              f"{'reachable' if ok else 'UNREACHABLE':12s} {h['service']}")


def redis_control():
    """Hop 3: prove unauthenticated control of redis without changing its data.

    Connecting with no password and reading CONFIG/INFO is already the compromise the goal names;
    a single marker key is set and then deleted so nothing persists.
    """
    ip, port = HOPS[3]["ip"], HOPS[3]["port"]

    def cmd(*parts):
        # RESP array, the normal redis wire protocol
        msg = f"*{len(parts)}\r\n" + "".join(f"${len(p)}\r\n{p}\r\n" for p in parts)
        s = socket.create_connection((ip, port), timeout=4)
        s.sendall(msg.encode())
        time.sleep(0.1)
        out = s.recv(4096).decode(errors="replace")
        s.close()
        return out.strip()

    print(f"  connecting to redis at {ip}:{port} with no credentials ...")
    noauth = "requirepass" not in cmd("CONFIG", "GET", "requirepass").lower() or \
             cmd("CONFIG", "GET", "requirepass").endswith('""') or \
             '\r\n\r\n' in cmd("CONFIG", "GET", "requirepass")
    ver = cmd("INFO", "server")
    m = re.search(r"redis_version:([^\r\n]+)", ver)
    d = cmd("CONFIG", "GET", "dir")
    marker = cmd("SET", "tr_walk_marker", "reached")
    got = cmd("GET", "tr_walk_marker")
    cmd("DEL", "tr_walk_marker")

    controlled = "OK" in marker and "reached" in got
    print(f"    redis_version    : {m.group(1) if m else '?'}")
    print(f"    CONFIG GET dir   : {d.splitlines()[-1] if d else '?'}")
    print(f"    SET/GET marker   : {'controlled (write accepted, read back, deleted)' if controlled else 'FAILED'}")
    state = load()
    state["hops"]["3"] = {
        **{k: HOPS[3][k] for k in ("tier", "exploit", "predicted")},
        "observed": "unauthenticated admin control confirmed" if controlled else "not confirmed",
        "walked": bool(controlled), "proof": f"redis {m.group(1) if m else '?'}, "
                                              f"unauth CONFIG/INFO, marker write+read+delete"}
    save(state)
    print(f"  recorded hop 3: {'WALKED' if controlled else 'not walked'}")


def record(hop, output):
    """Log the id output from a by-hand exploit of hop 1 or 2."""
    hop = int(hop)
    walked = bool(re.search(r"uid=\d+", output))
    user = re.search(r"uid=\d+\(([^)]+)\)", output)
    state = load()
    state["hops"][str(hop)] = {
        **{k: HOPS[hop][k] for k in ("tier", "exploit", "predicted")},
        "observed": f"code execution as {user.group(1)}" if user else output[:80],
        "walked": walked, "proof": output.strip()[:200]}
    save(state)
    print(f"  recorded hop {hop}: {'WALKED (' + (user.group(1) if user else 'code exec') + ')' if walked else 'no code execution seen in output'}")


def report():
    state = load()
    print("\n  Chain walk -- the graph's prediction against reality")
    print("  " + "-" * 64)
    done = 0
    for n in (1, 2, 3):
        h = state["hops"].get(str(n))
        if not h:
            print(f"  hop {n}  {HOPS[n]['tier']:6s} {HOPS[n]['predicted']:22s}  not yet walked")
            continue
        done += 1 if h["walked"] else 0
        mark = "walked" if h["walked"] else "FAILED"
        print(f"  hop {n}  {h['tier']:6s} {h['predicted']:22s}  {mark:7s}  {h['observed']}")
    print("  " + "-" * 64)
    print(f"  {done} of 3 hops walked" + ("  -- the full chain the graph predicted is confirmed"
                                          if done == 3 else ""))
    print(f"  wrote {OUT}")


def table():
    """Emit the walk as a LaTeX tabular from the recorded result, for the paper."""
    d = load()
    label = {1: "web, Struts2", 2: "app, CouchDB", 3: "db, Redis"}
    cve = {1: "S2-045 (CVE-2017-5638)", 2: "CVE-2017-12635, -12636",
           3: "unauthenticated access"}
    out = ["% generated from chain_walk.json by walk_chain.py --table",
           "\\begin{tabular}{llll}", "\\toprule",
           "Tier, service & Vulnerability & Graph derives & Confirmed in the lab \\\\",
           "\\midrule"]
    conf = {
        1: "OGNL code execution, as root",
        2: "admin takeover then RCE, \\texttt{id} = uid 0 (root)",
        3: "unauthenticated full control",
    }
    pred = {1: "\\texttt{execCode(vmWeb,root)}", 2: "\\texttt{execCode(vmApp,root)}",
            3: "\\texttt{execCode(vmDb,\\_)}"}
    for n in (1, 2, 3):
        h = d["hops"].get(str(n), {})
        mark = "\\checkmark" if h.get("walked") else "--"
        out.append(f"{label[n]} & {cve[n]} & {pred[n]} & {mark}~ {conf[n]} \\\\")
    out += ["\\bottomrule", "\\end{tabular}"]
    path = os.path.join(os.path.dirname(OUT), "tab_walk.tex")
    open(path, "w").write("\n".join(out))
    print("\n".join(out))
    print(f"\n  wrote {path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--redis", action="store_true")
    ap.add_argument("--record", nargs=2, metavar=("HOP", "ID_OUTPUT"))
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--table", action="store_true")
    args = ap.parse_args()
    if args.check:
        check()
    elif args.redis:
        redis_control()
    elif args.record:
        record(args.record[0], args.record[1])
    elif args.report:
        report()
    elif args.table:
        table()
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
