#!/usr/bin/env python3
"""Convert normalised scanner findings into MulVAL input facts.

Gate 2, prediction 4. MulVAL ships its own Nessus adapter in src/adapter/, and it is
not usable here for three reasons, all of which are worth stating in the write-up:

  1. It requires MySQL. Four of its Java files open JDBC connections.
  2. It reads .nessus XML. Our Nessus data is JSON pulled from the REST API, because
     Nessus Essentials blocks file export.
  3. It is keyed on the CVE identifier. Its vuln_exists facts take Range and Losstype
     straight from an NVD dump, so a finding with no CVE produces no fact and there-
     fore no node. Covering exactly those findings is the point of this project.

WHAT IS EXCLUDED

Log-level rows are dropped. They report that a service or product was detected, not that
anything is wrong with it, and an attacker cannot exploit a detection. They were included
until 28 September 2026, which put 32 non-weaknesses into the graph of a three-host lab and
made the count of CVE-less findings in the graph look larger than it was.

WHAT THE SCANNER CANNOT TELL US

Three things this script needs are absent from every scanner report, and it refuses to
invent them. They come from --topology instead:

  hacl(...)         reachability. A scan of one host says nothing about what that host
                    can reach. Guessing it would make every consequence score fiction.
  the service account  networkServiceInfo's last argument is the account a service runs
                    as, and it becomes the privilege the attacker obtains. An
                    unauthenticated scan cannot see it.
  attackerLocated   where the attacker starts is a modelling choice, not a measurement.

THE SOFTWARE NAME IS THE TRAP

The rule that fires for a remote exploit is:

    execCode(H, Perm) :-
        vulExists(H, _, Software, remoteExploit, privEscalation),
        networkServiceInfo(H, Software, Protocol, Port, Perm),
        netAccess(H, Protocol, Port).

Software is the same variable in both facts. If vulExists says httpd and
networkServiceInfo says apache2, nothing derives, the graph comes out empty, and
MulVAL reports no error. This script therefore takes the software name for a port
once, from the topology file, and uses that one string in both facts.

RANGE AND CONSEQUENCE COME FROM THE PUBLISHED CVSS VECTOR

vulProperty's two arguments decide what a finding lets an attacker do, and they are taken
from the CVSS vector NVD publishes rather than from anything this project invented: the
attack vector gives the range, the impact metrics give the consequence.

A finding whose CVEs have no published vector, or which cites no CVE at all, is emitted
with the most permissive pair the rule base admits, and every such fact is **marked in the
output** so a reader can tell it apart from one NVD supplied.

Two alternatives were tried and recorded in scans.md. Dropping these findings took
`Apache ActiveMQ Web Console Default / No Credentials` at severity 10.0 and
`Redis Server No Password` out of the plan, and a remediation plan that omits a service
running without a password is wrong in a way a practitioner sees immediately. A classifier
trained on the findings NVD does describe returned this same pair for 28 of 29 rows in any
case, because MulVAL offers privEscalation and dos while the correct answer for a finding
whose whole impact is the disclosure of a host's uptime is neither of them.

The cost is stated rather than hidden. `TCP Timestamps Information Disclosure` reaches the
middle of the plan on an assumption, consequence.py reports what the graph would lose if
every assumed fact were removed, and on the three-tier lab that is nothing: none of the
nine facts it derives depends on one.
"""

import argparse
import collections
import csv
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Prolog atoms: bare if they start lowercase and hold only word characters,
# single-quoted otherwise, with internal quotes doubled.
_BARE = re.compile(r"^[a-z][A-Za-z0-9_]*$")


def patom(value):
    text = str(value)
    if _BARE.match(text):
        return text
    return "'" + text.replace("'", "''") + "'"


def split_port(field):
    """'80/tcp' -> (80, 'tcp'). 'general/tcp' and friends -> (None, None)."""
    if not field or field.startswith("general/"):
        return None, None
    if "/" not in field:
        return None, None
    number, _, protocol = field.partition("/")
    if not number.isdigit():
        return None, None
    return int(number), protocol.lower()


def vuln_id(row):
    """Prefer the first CVE. Fall back to the scanner's own test id.

    The fallback is the whole point: a finding with no CVE still gets an identity, so
    it still becomes a node. MulVAL never interprets this string, it only joins on it.

    Never put a colon in this string. MulVAL's graph writer uses ':' as an internal
    field separator, and a colon here is silently stripped out of every vertex and
    dumped at the front of VERTICES.CSV and AttackGraph.dot, which corrupts line 1 of
    both and makes graphviz refuse to render. Found by feeding it 23 real findings
    whose fallback id began 'oid:'. Underscore instead.
    """
    cves = [c for c in (row.get("cves") or "").split(";") if c]
    if cves:
        return cves[0], True
    oid = row.get("nvt_oid") or ""
    return (f"oid_{oid}" if oid else "unknown"), False


# Used where NVD publishes no vector for any of a finding's CVEs, and where a finding
# carries no CVE at all. It is the most permissive pair the rule base admits, so it gives
# such a finding the benefit of the doubt rather than dropping it.
#
# Two alternatives were tried and both were worse. Dropping these findings removed
# `Apache ActiveMQ Web Console Default / No Credentials` at severity 10.0 and
# `Redis Server No Password` from the plan entirely, and a plan that omits a service with
# no password is wrong in a way a practitioner sees at once. A classifier trained on the
# findings NVD does describe returned this same pair for 28 of 29 rows anyway, because
# MulVAL offers privEscalation and dos while the correct answer for a finding whose whole
# impact is the disclosure of a host's uptime is neither.
#
# The cost is real and is not hidden: `TCP Timestamps Information Disclosure` reaches the
# middle of the plan on an assumption. Every such fact is marked in input.P and counted
# here, and consequence.py reports what the graph would lose without them, measured at
# nothing. See scans.md, 28 and 29 September.
ASSUMED = ("remoteExploit", "privEscalation")

REMOTE_VECTORS = ("NETWORK", "ADJACENT_NETWORK", "ADJACENT")
LOCAL_VECTORS = ("LOCAL", "PHYSICAL")

# CVSS v3 states whether a human has to do something for the attack to work. MulVAL
# distinguishes the same thing: `remoteExploit` is an attacker reaching a service directly,
# `remoteClient` needs a victim to open something, and two of the rule base's rules match
# only the latter. Until this was added every network-reachable finding was emitted as
# `remoteExploit`, so 95 findings in this corpus that require user interaction were given a
# path the attacker cannot take alone, and those two rules had never fired at all. It is the
# same shape of fault as emitting every finding as `privEscalation`, which let 44
# denial-of-service findings derive code execution.
UI_REQUIRED = re.compile(r"/UI:R(?:/|$)")


def cvss_properties(row, cvss_map):
    """(range, consequence) from the CVSS vectors NVD publishes, or (None, None).

    Range comes from the attack vector and consequence from the impact metrics: a loss of
    confidentiality or integrity is a privilege escalation as MulVAL's rule base uses the
    term, while a loss of availability alone is a denial of service and must not derive
    execCode. Getting that second case wrong is not cosmetic. Every finding was previously
    emitted as privEscalation, so 44 denial-of-service findings on this host set were
    granting code execution they cannot grant, and every finding on a host therefore sat
    the same number of derivation steps from the goal.

    Multi-CVE findings resolve to the worst case each axis admits, matching the rule
    already used for the maximum EPSS: remoteExploit over localExploit, privEscalation
    over dos.
    """
    rng = cons = None
    for cve in [c.strip() for c in (row.get("cves") or "").split(";")
                if c.strip().startswith("CVE-")]:
        vector = (cvss_map.get(cve) or {}).get("cvss") or {}
        av = (vector.get("attackVector") or "").upper()
        impacted = lambda k: (vector.get(k) or "").upper() not in ("", "NONE")

        needs_user = bool(UI_REQUIRED.search(vector.get("vector") or ""))
        this_rng = ("remoteClient" if av in REMOTE_VECTORS and needs_user
                    else "remoteExploit" if av in REMOTE_VECTORS
                    else "localExploit" if av in LOCAL_VECTORS else None)
        this_cons = ("privEscalation" if impacted("confidentiality") or impacted("integrity")
                     else "dos" if impacted("availability") else None)

        # Worst case across a finding's CVEs, as elsewhere: a directly reachable flaw
        # outranks one needing a victim, which outranks a local one.
        order = {"remoteExploit": 3, "remoteClient": 2, "localExploit": 1}
        if this_rng and order.get(this_rng, 0) > order.get(rng, 0):
            rng = this_rng
        if this_cons and cons != "privEscalation":
            cons = this_cons
    return rng, cons


def consequence_from_impact(confidentiality, integrity, availability):
    """The same rule `cvss_properties` applies, over impact values from any source.

    Pulled out so an estimate and a published vector cannot be interpreted differently. A
    loss of confidentiality or integrity is a privilege escalation as MulVAL uses the term;
    a loss of availability alone is a denial of service and must not derive execCode.
    """
    hit = lambda v: (v or "").upper() not in ("", "NONE")
    if hit(confidentiality) or hit(integrity):
        return "privEscalation"
    if hit(availability):
        return "dos"
    return None


def row_key(row):
    """What identifies a finding across the pipeline's CSVs."""
    return (row.get("host", ""), row.get("port", ""), row.get("nvt_name", ""))


def load_predictions(path):
    """Estimated impact metrics from `impact.py --predict`, as {row key: consequence}.

    The file is optional. Without it the pipeline behaves exactly as it did before this
    stage existed, which keeps every earlier number in `scans.md` reproducible.
    """
    if not path or not os.path.exists(path):
        return {}
    out = {}
    with open(path, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            cons = consequence_from_impact(r.get("confidentiality"), r.get("integrity"),
                                           r.get("availability"))
            if cons:
                out[(r.get("host", ""), r.get("port", ""), r.get("nvt_name", ""))] = cons
    return out


def load_topology(path):
    with open(path, encoding="utf-8") as fh:
        topo = json.load(fh)
    for key in ("attacker_zone", "hosts", "hacl", "goal"):
        if key not in topo:
            sys.exit(f"topology file is missing required key: {key}")
    return topo


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", required=True, action="append", metavar="CSV",
                    help="normalised findings CSV; repeatable")
    ap.add_argument("--topology", required=True, metavar="JSON",
                    help="reachability, service accounts and attacker position. "
                         "Required: none of it is present in a scanner report")
    ap.add_argument("-o", "--out", required=True, metavar="FILE",
                    help="MulVAL input file to write, conventionally input.P")
    ap.add_argument("--predicted", metavar="CSV",
                    help="estimated impact metrics from `impact.py --predict`; without it "
                         "findings with no published vector keep the assumed constant")
    ap.add_argument("--override-published", action="store_true",
                    help="let --predicted replace a published consequence too. Only for "
                         "mulval_check.py, which grades the estimates against the vectors "
                         "they replace; never for a graph a result is reported from")
    ap.add_argument("--cvss", default=os.path.join(HERE, "cwe_map.json"), metavar="JSON",
                    help="CVE to CVSS map from fetch_labels.py --cwe. A finding whose CVEs "
                         "are absent from it is not emitted, and the count is reported")
    ap.add_argument("--min-qod", type=float, default=0,
                    help="drop findings below this detection confidence "
                         "(default 0, keep everything)")
    args = ap.parse_args()

    topo = load_topology(args.topology)
    try:
        with open(args.cvss, encoding="utf-8") as fh:
            cvss_map = json.load(fh)
    except FileNotFoundError:
        print(f"note: no CVSS map at {args.cvss}, so no finding has published properties")
        print("      and the graph would come out empty. Build one with:")
        print("      python3 fetch_labels.py --cwe")
        cvss_map = {}
    hosts = topo["hosts"]

    rows = []
    for path in args.findings:
        with open(path, encoding="utf-8") as fh:
            rows.extend(csv.DictReader(fh))
    if not rows:
        sys.exit("no findings loaded")

    skipped = collections.Counter()
    facts_vuln, facts_prop = [], []
    services = {}          # (host_atom, software) -> (protocol, port, account)
    seen_ids = set()
    cveless_emitted = 0
    from_cvss = 0
    assumed = 0
    estimated = 0
    predicted = load_predictions(getattr(args, "predicted", None))
    if predicted:
        print(f"note: {len(predicted)} estimated consequences loaded from "
              f"{args.predicted}")
    property_mix = collections.Counter()

    for row in rows:
        # Log-level entries are service and product detections, not weaknesses. Every
        # measurement in this project already excludes them; the graph did not, so 32 of
        # the 35 Log rows on this host set were entering it as exploitable vulnerabilities
        # and inflating both the node count and the CVE-less count. A detection is not
        # something an attacker can use.
        if row.get("threat") == "Log":
            skipped["Log-level detection, not a weakness"] += 1
            continue
        ip = row.get("host", "")
        if ip not in hosts:
            skipped["host not declared in topology"] += 1
            continue
        try:
            if float(row.get("qod") or 0) < args.min_qod:
                skipped["below --min-qod"] += 1
                continue
        except ValueError:
            pass

        host_atom = hosts[ip].get("atom") or ip
        declared = hosts[ip].get("services", {})
        port_field = row.get("port", "")
        port, protocol = split_port(port_field)

        vid, from_cve = vuln_id(row)

        if port is None:
            # Host-level finding: no listening port to reach it through.
            software = hosts[ip].get("host_software", "os")
            fallback_rng = "localExploit"
        else:
            if port_field not in declared:
                skipped[f"port {port_field} not declared for {ip}"] += 1
                continue
            entry = declared[port_field]
            software = entry["software"]
            fallback_rng = "remoteExploit"
            # The service is declared whatever the range turns out to be: a locally
            # exploitable flaw in a listening service is still a flaw in that service.
            services[(host_atom, software)] = (protocol, port, entry["account"])

        # What NVD publishes wins over what the port field implies. A finding on an open
        # port is not remotely exploitable merely because the port is open.
        cvss_rng, cvss_cons = cvss_properties(row, cvss_map)
        published = bool(cvss_rng and cvss_cons)
        rng = cvss_rng or fallback_rng
        # Three sources, in descending order of what can be said about them. A published
        # CVSS vector is NIST's answer. An estimate is the classification stage's, trained on
        # those vectors and measured against a majority-class baseline it beats on every
        # field. The constant is neither, and until this stage existed it covered both of the
        # other cases. Each is marked in the emitted fact, so consequence.py can still report
        # what the graph would lose without any one of them.
        if args.override_published and row_key(row) in predicted:
            cons, source = predicted[row_key(row)], "estimated"
            estimated += 1
        elif cvss_cons:
            cons, source = cvss_cons, "published"
            from_cvss += 1
        elif predicted and row_key(row) in predicted:
            cons, source = predicted[row_key(row)], "estimated"
            estimated += 1
        else:
            cons, source = ASSUMED[1], "assumed"
            assumed += 1
        property_mix[(rng, cons)] += 1

        key = (host_atom, vid, software)
        if key in seen_ids:
            continue
        seen_ids.add(key)
        if not from_cve:
            cveless_emitted += 1

        facts_vuln.append(
            f"vulExists({patom(host_atom)}, {patom(vid)}, {patom(software)}).")
        # The marker is not decoration. A reader of input.P, and consequence.py, can tell
        # which facts came from a published vector, which were estimated by the
        # classification stage and which are the constant, and no number derived from this
        # file has to be taken on trust about which it rests on.
        note = {"published": "",
                "estimated": "   /* ESTIMATED: classifier, no published vector */",
                "assumed": "   /* ASSUMED: no published vector, no estimate */"}[source]
        facts_prop.append(f"vulProperty({patom(vid)}, {rng}, {cons})." + note)

    if not facts_vuln:
        sys.exit("no facts produced. Check that topology host keys match the "
                 "'host' column of the findings CSV.")

    out = []
    out.append("/* Generated by findings_to_mulval.py. Do not edit by hand. */")
    out.append(f"/* findings: {', '.join(args.findings)} */")
    out.append(f"/* topology: {args.topology} */")
    out.append("")
    out.append("/* --- attacker position and goal: modelling choices, from topology --- */")
    out.append(f"attackerLocated({patom(topo['attacker_zone'])}).")
    out.append(f"attackGoal({topo['goal']}).")
    out.append("")
    out.append("/* --- reachability: declared, NOT observed by any scanner --- */")
    for src, dst, proto, port in topo["hacl"]:
        port_text = "_" if port in (None, "_") else str(port)
        proto_text = "_" if proto in (None, "_") else patom(proto)
        out.append(f"hacl({patom(src)}, {patom(dst)}, {proto_text}, {port_text}).")
    out.append("hacl(H, H, _, _).")
    out.append("")
    out.append("/* --- services: port and protocol observed, account declared --- */")
    for (host_atom, software), (proto, port, account) in sorted(services.items()):
        out.append(f"networkServiceInfo({patom(host_atom)}, {patom(software)}, "
                   f"{patom(proto)}, {port}, {patom(account)}).")
    out.append("")
    out.append(f"/* --- {len(facts_vuln)} findings --- */")
    for v, p in zip(facts_vuln, facts_prop):
        out.append(v)
        out.append(p)

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")

    total = len(rows)
    print(f"read      {total} findings from {len(args.findings)} file(s)")
    print(f"consequence source: {from_cvss} published, {estimated} estimated, "
          f"{assumed} assumed")
    if estimated:
        print(f"  the estimated ones come from a classifier measured at 2.4-2.8x the "
              f"majority-class\n  baseline on macro-F1; consequence.py reports what the "
              f"graph would lose without them")
    for pair, count in property_mix.most_common():
        print(f"          {count:4d}  {pair[0]}/{pair[1]}")
    print(f"emitted   {len(facts_vuln)} vulExists/vulProperty pairs, "
          f"{len(services)} services")
    print(f"          of those, {cveless_emitted} carry no CVE and exist in the graph "
          f"only because the fallback identifier gives them one")
    if skipped:
        print("skipped:")
        for reason, count in skipped.most_common():
            print(f"  {count:>4}  {reason}")
    print(f"wrote     {args.out}")


if __name__ == "__main__":
    main()
