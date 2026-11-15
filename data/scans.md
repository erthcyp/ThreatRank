# ThreatRank - Scan Log

One entry per scan, so results stay reproducible and it is always clear which
conditions produced which numbers.

**Always record:** feed version, export filter, scan config, port list. All of them
change the results; without them a later mismatch is impossible to explain. The
port list in particular invalidated a whole comparison once - see Scan 3.

---

## Directory layout

```
~/data/
├── raw/openvas/      raw Greenbone XML - never edit
├── raw/nessus/       raw API responses as JSON - never edit
├── processed/        parser output - safe to regenerate
├── parse_openvas.py  OpenVAS XML  -> CSV
├── parse_nessus.py   .nessus file -> CSV  (unused: Essentials blocks file export)
├── fetch_nessus.py   Nessus REST API -> CSV + raw JSON
├── compare_scanners.py
├── kev_catalog.json  CISA KEV snapshot (1,666 CVEs, catalogVersion 2026.08.17)
└── scans.md          this file
```

Filenames: `YYYY-MM-DD_scanner_group_target.{xml,json}`

---

## Host identity

**The container IP is the host identifier in the dataset**, so it has to stay constant
across scans. Docker does not guarantee that: addresses are allocated in the order
containers attach, and Greenbone's own 16 containers occupy `172.18.0.2`–`.17` in an order
that varies between reboots. On 18 Aug the ActiveMQ target came up as `.18` rather than the
`.17` it had held the day before, purely because a Greenbone container claimed `.17` first.

Targets are therefore attached with an explicit address from `.100` upward, outside the
range Greenbone assigns itself:

```bash
docker network connect --ip 172.18.0.100 \
  greenbone-community-edition_default <container>
```

```
172.18.0.100 – .109    group A  (vulhub, curated vulnerabilities)
172.18.0.110 – .119    group B  (ordinary old images)
```

### ⚠️ Address change affecting existing data

| Address | Period | Host |
|---|---|---|
| `172.18.0.17` | 17–18 Aug 2026 | ActiveMQ 5.11.1 (`cve-2016-3088`) |
| `172.18.0.100` | 18 Aug 2026 onward | **the same machine** |

Scans 1–3 below record `172.18.0.17`, which was correct at the time. **When merging those
results with anything scanned later, treat `172.18.0.17` and `172.18.0.100` as one host** -
otherwise host-level grouping and the host-level train/test split will count one container
as two machines.

---

## Scan 1 - OpenVAS, IANA ports

`raw/openvas/2026-08-17_openvas_A_activemq-CVE-2016-3088.xml`

**Purpose: validate the pipeline end to end.** Superseded for comparison purposes
by Scan 3, which uses a port range comparable to Nessus.

| | |
|---|---|
| Target | `172.18.0.17` (container IP on the greenbone network) |
| Source | `vulhub/activemq/CVE-2016-3088` - ActiveMQ 5.11.1 + Jetty 8.1.16 (2014) |
| Group | **A** (vulhub - selected for notoriety, therefore selection-biased) |
| Scanner | OpenVAS 23.50.0, config `Full and fast` |
| **Port list** | **All IANA assigned TCP** |
| Alive test | Consider Alive (required - and see the note below) |
| Authentication | none |
| Apply Overrides / Min QoD | Yes / 70% (task defaults) |
| Duration | 8 minutes |
| Result | **32 findings** - Critical 3 / High 3 / Medium 6 / Low 4 / Log 16 |

**Feed versions** - baked into the container images rather than synced live, which
makes scans reproducible if the versions are recorded:

```
NVT        202608141605
SCAP       20260814T0251
CERT       20260814T0447
GVMD_DATA  20260814T0533
```

**Export filter**

```
apply_overrides=0 min_qod=0 first=1 sort-reverse=severity rows=1000
levels=chlmgf result_hosts_only=1 notes=1 overrides=1
```

Everything was exported (`min_qod=0`) and filtered during analysis instead.
`levels=chlmgf` keeps all six severity classes including False Positive.

---

## Scan 2 - Nessus

`raw/nessus/2026-08-17_nessus_A_test-activemq-nessus.json`

| | |
|---|---|
| Target | `172.18.0.17` |
| Scanner | Nessus Essentials Plus 10.12.3, policy `Basic Network Scan` |
| **Port range** | **1-65535** |
| Authentication | none |
| Duration | 14 minutes |
| Result | **20 plugins** - Critical 0 / High 0 / Medium 2 / Low 1 / Info 17 |

**Licence: 20 IPs, not the 5 recorded in earlier project notes.** Verified in the
UI after registration. This materially enlarges the feasible lab.

**Export is disabled in Essentials**, so results were pulled through the local REST
API with `fetch_nessus.py` - the same interface the web UI itself calls. Raw API
responses are archived because a rescan is a new observation, not a reproduction.

**Reproducibility: confirmed.** The task was launched twice (1:09-1:24 and
1:28-1:42). Both runs: 14 minutes, 17 vulnerabilities, 2/1/28 severity split.
Nessus is deterministic on this target.

**Three different counts, all correct, counting different units:**

| Unit | Count | Meaning |
|---|---|---|
| plugins returned by the API | 20 | what the CSV stores |
| UI "Vulnerabilities" tab | 17 | excludes 3 scanner-metadata plugins |
| total instances | 31 | sum of each plugin's `count` (SYN scanner alone = 7) |

**Nessus SYN scanner found 7 open ports:** 1883, 5672, 8161, 32933, 61613, 61614,
61616 - and labelled 61616 as `activemq`. It identified the service and still
produced no vulnerability finding for it.

---

## Scan 3 - OpenVAS, full ports (the fair comparison)

`raw/openvas/2026-08-18_openvas_A_activemq-fullports.xml`

Identical to Scan 1 in every setting **except the port list**, which was replaced
with a custom list `T:1-65535` to match Nessus. One variable changed, so the
difference is attributable.

| | |
|---|---|
| **Port list** | **`TCP 1-65535 (match Nessus)`** (custom) |
| Everything else | as Scan 1 |
| Result | **56 findings** - Critical 4 / High 6 / Medium 11 / Low 6 / Log 29 |

*(Apply Overrides was set to No here rather than Yes. Verified to have no effect:
the overrides table is empty, and all 32 findings in Scan 1 had `severity ==
original_severity`. The switch only matters once overrides exist - revisit if any
are ever created, e.g. to mark false positives.)*

### Why this scan had to be run

Scan 1 used `All IANA assigned TCP`, which by definition **excludes the Dynamic
range 49152-65535**. ActiveMQ listens on 61613, 61614 and 61616 - all inside it.
OpenVAS never scanned those ports, while Nessus did.

The first cross-scanner comparison was therefore measuring a configuration
mismatch as if it were a difference between the tools.

### Effect of widening the port range

| Port | IANA ports | 1-65535 | What appeared |
|---|---|---|---|
| 8161 | 21 | 21 | unchanged |
| 1883 / 5672 | 3 | 3 | unchanged |
| **61614** | - | **20** | Critical 1, High 3, Medium 5, Low 2, Log 9 |
| **61616** | - | 1 | Log only |
| **61613 / 32933** | - | 3 | Log only |

**32 -> 56 findings (+75%), but almost none of it is a new vulnerability.**
18 of 23 NVTs that fired on 8161 fired again on 61614: ActiveMQ exposes the same
Jetty instance on both ports, so the same weaknesses are reported twice.

**61616, the main ActiveMQ OpenWire port, yielded one Log-level service detection
and nothing else** - matching Nessus, which named the service and stayed silent.
Neither scanner has a real check for the OpenWire protocol. With both port ranges
now equal, that is a finding about the tools rather than about the configuration.

---

## Cross-scanner comparison (Scan 3 vs Scan 2)

```bash
python3 compare_scanners.py --openvas processed/findings_openvas.csv \
                            --nessus  processed/findings_nessus_a.csv \
                            --expect CVE-2016-3088
```

| | Before the fix (Scan 1) | After the fix (Scan 3) |
|---|---|---|
| OpenVAS findings | 32 | **56** |
| Nessus findings | 20 | 20 |
| CVEs seen by both | 2 / 29 | **5 / 37** |
| **Jaccard similarity** | 0.069 | **0.135** |
| **CVEs only Nessus saw** | 3 | **0** |

**Roughly half the measured disagreement was self-inflicted.** Matching the port
ranges doubled the similarity.

**Nessus is now a strict subset of OpenVAS at CVE level.** Everything Nessus found,
OpenVAS also found, plus 32 more CVEs. The earlier reading - that the two tools
cover complementary ground - does not survive the corrected comparison.

Matching is done at CVE level only. OpenVAS identifies checks by NVT OID and Nessus
by plugin ID; those namespaces share nothing, and finding names differ by vendor.
CVE IDs are the only shared vocabulary, so they are the only defensible join key.

---

## Findings that hold after every correction

**1. Both scanners miss the vulnerability the target exists to demonstrate.**

```
CVE-2016-3088   OpenVAS: MISSED   Nessus: MISSED
```

Unchanged across the full 1-65535 range and across repeat runs. CVE-2016-3088 sits
at `/fileserver/` on port 8161 - the port OpenVAS hit with 21 checks. Detecting it
requires actually issuing a PUT, which unauthenticated scanning does not do. This
is a ceiling of the method, not a misconfiguration.

**2. The most severe findings carry no CVE.**

- `Eclipse Jetty End of Life Detection` (10.0) - EOL since 2014
- `Apache ActiveMQ Web Console Default / No Credentials` (10.0) - admin/admin, QoD 98

**EPSS cannot score either** - there is no CVE to look up. Across the OpenVAS
report, 64.8% of findings have no CVE at all; for Nessus it is 85.0%.

**3. Same version banner, opposite reporting decisions.**

Both scanners read `Server: Jetty(8.1.16.v20140903)`. OpenVAS emitted 10 Jetty
CVEs; Nessus emitted none, recording only `Eclipse Jetty Web Server Detection`.

This is a **reporting-policy difference, not a detection difference**. It
undermines reading agreement as evidence that a finding is real: silence from a
scanner does not mean absence. Agreement measures how many vendors chose to warn,
which is still useful for ranking, but it is not proof of existence.

**4. Both produce unflagged false positives.**

| Scanner | Claimed product | Present on host? |
|---|---|---|
| OpenVAS | Axway SecureTransport MFT | no |
| Nessus | Oracle PeopleSoft PeopleTools | no |

Both misidentified a product from an HTTP response, and neither marked its own
result as suspect (`false_positive count = 0`).

**5. Nessus reports no Critical or High at all on this host**, where OpenVAS reports
4 and 6. The severity distributions are not comparable between tools without
stating which tool produced them.

---

## Methodological choices discovered so far

Each of these changes the headline numbers and must be stated in the report.

| Choice | Effect measured |
|---|---|
| Count Log-level findings? | 56 vs 27 findings; CVE coverage 35.7% vs 67% |
| QoD threshold | GVM's default of 70 drops CVE coverage to ~12% - every Jetty CVE has QoD 30 |
| Drop CVEs from generic NVTs? | KEV rate 1.8% vs 0.0% |
| Count plugins or instances? | Nessus: 20 vs 31 for the same scan |
| One service on two ports = one finding or two? | 18 of 23 NVTs duplicated across 8161 and 61614 |
| Port list | 32 vs 56 findings; Jaccard 0.069 vs 0.135 |

`parse_openvas.py --compare` prints the first three automatically.

---

## Running the tools

```bash
cd ~/threatrank/data

# OpenVAS - one report at a time; globbing several merges and double-counts
python3 parse_openvas.py "raw/openvas/2026-08-18_*.xml" --offline \
        -o processed/findings_openvas.csv

# see how much each methodological choice moves the numbers
python3 parse_openvas.py "raw/openvas/2026-08-18_*.xml" --offline --compare

# Nessus - via the REST API (prompts for credentials, stores nothing)
python3 fetch_nessus.py --list
python3 fetch_nessus.py --scan-name test-activemq-nessus --group A --offline \
        -o processed/findings_nessus_a.csv

# compare
python3 compare_scanners.py --openvas processed/findings_openvas.csv \
        --nessus processed/findings_nessus_a.csv --expect CVE-2016-3088
```

---

## Scan 4 and 5 - group B, first VM target

`raw/openvas/2026-08-19_openvas_B_ubuntu2004-lamp.xml`
`raw/nessus/2026-08-19_nessus_B_scan-b1-ubuntu2004-nessus.json`

First target that is a real machine rather than a container.

| | |
|---|---|
| Host | `target-b1` at `192.168.194.150` (VMware NAT, static) |
| OS | Ubuntu 20.04.6 LTS, kernel 5.4.0-144, 653 packages |
| Services | Apache 2.4.41, MySQL 8.0.42 (localhost only), PHP 7.4.3 |
| Group | **B**: selected for age alone, not for known vulnerabilities |
| Build | installed from the release ISO with the network adapter disconnected, so no updates could be applied; never patched afterwards |
| Behind archive | 208 packages |
| Scanners | OpenVAS and Nessus, both unauthenticated, both 1-65535 |

The build procedure matters: the first installation attempt was discarded because the Ubuntu
installer downloads security updates at the end, which would have left the machine in a
partially patched state that is neither current nor original, and therefore not reproducible.

### Group A versus group B

| | A / OpenVAS | A / Nessus | B / OpenVAS | B / Nessus |
|---|---|---|---|---|
| findings | 56 | 20 | 63 | 31 |
| non-Log | 27 | 3 | 45 | 2 |
| Critical + High | 10 | 0 | 20 | 0 |
| with a CVE | 35.7% | 15.0% | 63.5% | 6.5% |
| unique CVEs | 37 | 5 | 71 | 2 |
| touching KEV | 1.8% | 0% | 3.2% | 0% |

**The KEV comparison is not yet interpretable.** One host per group, with one and two KEV
findings respectively, is noise rather than signal. The selection-bias question stays open
until many more hosts exist.

**CVE coverage went up on group B, not down.** The expectation had been that an ordinary
machine would carry proportionally more configuration findings and fewer CVE-linked ones. The
opposite happened, and the reason is visible in the data: a full operating system with 653
packages gives version-inference checks far more to match against than a single-service
container does. The driver is how much software is installed and how outdated it is, not
whether the target was curated.

---

## Scan 6 - target-b1 rescan after the accidental patching

**Registered 20 Aug 2026, before the scan was run.**

The automatic upgrade that spoiled the first audit also created a controlled comparison we
could not have set up deliberately: the same host, the same scanner, the same settings, with
only the patch state changed.

| | Scan 5 (19 Aug) | Scan 6 (20 Aug) |
|---|---|---|
| `apache2` | `2.4.41-4ubuntu3.23` | `2.4.41-4ubuntu3.23` (unchanged) |
| `openssh-server` | `1:8.2p1-4ubuntu0.5` | `1:8.2p1-4ubuntu0.13` |
| `libssl1.1` | `1.1.1f-1ubuntu2.17` | `1.1.1f-1ubuntu2.24` |
| kernel | 5.4.0-144 | 5.4.0-216 |

### Predictions, fixed in advance

| # | Prediction | Falsifies what if wrong |
|---|---|---|
| 1 | The seven OpenSSH findings judged **true positives** disappear | the version comparison in `verify_backport.py`, and with it the whole corrected audit |
| 2 | The six Apache Critical/High findings judged **false positives** remain, unchanged | the claim that `apache2` was never modified |
| 3 | Total findings fall by roughly 7 to 15 | nothing critical, recorded for completeness |
| 4 | No finding that was absent on 19 Aug appears as Critical or High | an unnoticed change to the host |

Prediction 1 is the one that matters. If those seven findings are still present after the
packages that fix them have been installed, then the audit is measuring something other than
what it claims to measure, and the corrected numbers are no more trustworthy than the
original ones were.

Prediction 2 is the control. Apache did not change, so its findings must not change either.

### Result

`raw/openvas/2026-08-20_openvas_B_ubuntu2004-lamp-patched.xml`, scan 18:59:57 to 19:16:23,
status Done, NVT feed `202608141605`, unchanged from Scan 5. Same task, same settings.

| # | Prediction | Outcome |
|---|---|---|
| 1 | the seven OpenSSH findings disappear | **FAILED** |
| 2 | the six Apache findings remain unchanged | held |
| 3 | total findings fall by 7 to 15 | **FAILED**, the total did not move |
| 4 | nothing new appears at Critical or High | held |

```
findings   19 Aug = 63      20 Aug = 63
disappeared 0    appeared 0
Critical=9  High=11  Medium=19  Low=6  Log=18     on both days
```

**Nothing changed. Not one finding, not one severity, not one CVE.**

### Why prediction 1 failed, and why the answer is better than the prediction

The prediction assumed the scanner reads the distribution revision. It does not. The banner
it collects is identical on both days:

```
SSH-2.0-OpenSSH_8.2p1        19 Aug and 20 Aug
Apache/2.4.41                19 Aug and 20 Aug
```

Ubuntu keeps the upstream version in the banner and carries its own revision only in the
package metadata, which an unauthenticated scan never sees. `4ubuntu0.5` and `4ubuntu0.13`
are indistinguishable from the network. The scanner is matching `8.2p1` against upstream
release history and reporting everything fixed after it, exactly as it did the day before.

### What this establishes

This is a controlled experiment with one variable. The host's security state changed
materially: `openssh-server` advanced eight revisions and gained fixes for seven CVEs
including a 9.8 RCE. The scanner's output did not change at all.

| | 19 Aug, openssh `0.5` | 20 Aug, openssh `0.13` |
|---|---|---|
| scanner output | 63 findings | **the same 63 findings** |
| of those, actually false | 7 | **14** |
| of those, actually true | 7 | **0** |
| Critical/High actually false | 6 of 20 | **8 of 20** |

**The same report describes a host with seven real vulnerabilities and a host with none.**
Whether a finding is true is not a property the report carries, at any confidence level, in
any field. Determining it required reading the installed package versions, which is
information from outside the report entirely.

This is a stronger and cleaner statement of the problem than the original audit made, and it
rests on a designed comparison rather than on a single snapshot.

*An aside worth recording.* The figures in the original, retracted audit (14 of 40 findings
false, 8 of 20 Critical/High) are exactly right for the 20 Aug scan. They were computed from
changelogs read after the host had patched itself, so they described the machine as it stood
that evening rather than the one that had been scanned. The arithmetic was never wrong; it
was answering a question about a different machine.

### Consequences for the project

**It does not rescue QoD.** The refutation stands on the 19 Aug data, where 7 genuine and 7
false findings all sat at QoD 30. The 20 Aug scan cannot test the question at all, since
every finding with a verdict is now false and a feature cannot be shown to discriminate
between one class and an empty one.

**It sharpens what the false-positive contribution can claim.** Not "report-level context
predicts false positives", which is now measured and false, but the harder and more useful
statement: **unauthenticated scanner output is invariant to the target's patch state**, so
any method that resolves these findings must bring in information the report does not have.
Credentialed scanning is one such source; distribution security feeds keyed on an exact
package revision are another; a model trained on labelled examples is a third and the only
one that works when the host is unreachable.

**It is an argument for the credentialed-scanning experiment**, which is now the obvious next
step rather than an open question.

---

## Scan 7 - target-b1 with credentials

**Registered 20 Aug 2026, before the scan was run.**

Scan 6 showed that an unauthenticated scan cannot see the distribution revision, and
therefore cannot tell a patched host from a vulnerable one. A credentialed scan reads the
installed package list directly. This scan tests what that changes, on a host whose exact
package state is recorded (`evidence/target-b1_pkgs_2026-08-20_1858.tsv`, 658 packages).

The host reports `0 updates can be applied immediately`. It is fully patched for everything
Ubuntu publishes without an ESM subscription, while `focal` itself passed end of standard
support in May 2025.

| | value |
|---|---|
| Host | `target-b1`, 192.168.194.150, unchanged since Scan 6 |
| Difference from Scan 6 | SSH credentials supplied; everything else identical |
| Key versions | `apache2 2.4.41-4ubuntu3.23`, `openssh-server 1:8.2p1-4ubuntu0.13`, `libssl1.1 1.1.1f-1ubuntu2.24` |

### Predictions, fixed in advance

| # | Prediction | Falsifies what if wrong |
|---|---|---|
| 1 | The 14 version-inference false positives are **still reported**, because the remote checks run regardless of credentials | the assumption that credentials suppress remote NVTs |
| 2 | **No package-level check corroborates any of them.** The credentialed and uncredentialed halves of the same report disagree | the premise that credentialed checks are more accurate here |
| 3 | Package-level CVE findings are **few or none**, since the host is fully patched | either the host is not as patched as recorded, or ESM-gap vulnerabilities are being reported |
| 4 | Total findings **increase**, from local detections (installed packages, OS details) rather than from vulnerabilities | nothing critical |
| 5 | An end-of-life or unsupported-release finding appears | nothing critical |

Prediction 2 is the one that matters. If it holds, a single report contains two accounts of
the same host that contradict each other, and only one of them had access to the facts.

### Result

`raw/openvas/2026-08-21_openvas_B_ubuntu2004-lamp-auth.xml`, 19:46 to 20:04, status Done.
Authentication succeeded: 125 findings from the `Ubuntu Local Security Checks` family and no
login-failure result. Package state verified identical to Scan 6 by diffing the two snapshots
in `evidence/`, so credentials are the only variable.

| # | Prediction | Outcome |
|---|---|---|
| 1 | the version-inference findings survive | held, all 38 still present |
| 2 | no package-level check corroborates them | **FAILED**, 18 CVEs overlap |
| 3 | few or no package-level CVE findings, the host being patched | **FAILED badly**, 125 advisories |
| 4 | total findings increase | held, 63 to 399 |
| 5 | an end-of-life finding appears | held, PHP and OpenSSL EOL at 10.0 |

### The host was never fully patched, and `apt` could not have told us

| | unauthenticated | credentialed |
|---|---|---|
| findings | 63 | **399** |
| carrying a CVE | 40 | 331 |
| unique CVEs | 71 | **646** |
| Critical | 9 | **46** |
| High | 11 | **124** |
| KEV CVEs | 2 | 8 |

125 Ubuntu advisories fire, and **110 of them can only be fixed with an Ubuntu Pro
subscription**:

```
Vulnerable package: apache2
Installed version:  apache2-2.4.41-4ubuntu3.23
Fixed version:      >=apache2-2.4.41-4ubuntu3.23+esm3
```

`focal` left standard support in May 2025. Without ESM configured the archive has nothing
newer to offer, so `apt policy` reports `Installed` equal to `Candidate` and the host says
`0 updates can be applied immediately`. **That is not a statement that the machine is
patched. It is a statement that apt cannot see the repository holding the patches.** Only 15
of the 125 advisories are fixable with plain `apt upgrade`.

**This retracts the claim, made earlier the same day, that `apache2` carried every fix Ubuntu
had published for it.** It carries every fix in the free archive. It is three ESM releases
behind.

### What this does to the false-positive count

For 13 of the 15 Apache Critical/High version-inference findings, **not one cited CVE is
re-flagged by any package-level check**, which is consistent with them being false positives.
Two are contaminated: `Apache HTTP Server < 2.4.60` has 4 of its 7 CVEs re-flagged, and
`< 2.4.59` has 2 of 3. Both were in the list of six.

**This is not yet resolvable and should not be asserted either way.** USN advisories bundle
CVEs, and the OpenVAS check reports every CVE named in an advisory once the version test
fires, so a re-flagged CVE may be genuinely unfixed or may be along for the ride. The
changelog places the fix for `CVE-2023-38709` at `3.17`, below the installed `3.23`, which
directly contradicts USN-8338-1 demanding `3.23+esm3`. Deciding between them needs the
advisory's own contents, which the host does not carry. **Open item.**

Stated conservatively: at least 4 of 20 Critical/High are unambiguously false, 2 are mixed,
and the clean framing of "false positives on a fully patched package" is gone.

### Correction, 26 Aug 2026: the two counts measure different surfaces

The comparison above was framed as the unauthenticated report missing nine tenths of what is
present. **That framing is wrong, and it is wrong in a way that inflates our own result.**

Classifying the 125 credentialed advisories by whether the package is reachable from the
network at all:

| | advisories |
|---|---|
| reachable over the network (`apache2`, `php7.4`, `libssl1.1`, `openssh`, `openssl`) | **13** |
| local only (`vim`, `git`, `curl`, `tar`, `wget`, python libraries, kernel) | **112** |

**90% of the credentialed report is for software a remote attacker cannot touch on this host.**
An unauthenticated scan is not failing to find `vim`; `vim` listens on no port, so it lies
outside what a network scan is for. The two numbers answer different questions:

- unauthenticated: what is exposed to the network
- credentialed: every outdated package on disk, exposed or not

Restricted to the network-reachable surface, the credentialed scan named **13** advisories
while the unauthenticated scan reported **40** CVE-bearing findings on the same packages. On
the surface a remote attacker can actually reach, **the scanner over-reports rather than
under-reports**, which is the opposite of what this section originally claimed.

What survives: the credentialed scan sees a patch state the network cannot, and that matters
under a different threat model, namely an attacker already on the host or moving laterally. It
is a real gap. It is not evidence that unauthenticated scanning misses most of the remote
attack surface.

*This error is the same shape as one already documented in the literature. Pashchenko et al.,
cited in the OSV ground-truth evaluation (arXiv 2604.21111, 2026), show that counting at the
dependency level substantially overestimates vulnerability counts. We counted at the package
level and compared against a service-level scan.*

### A vocabulary correction that follows from the same paper

That evaluation never uses the term "false positive". It reports **recall** against a
ground-truth snapshot and **overlap**, the share of tool findings that coincide with the
reference, and states explicitly that overlap must be read relative to the snapshot because
the reference is itself incomplete and lags disclosure.

We should adopt that discipline. A finding our reference does not corroborate is **not
corroborated**, which is not the same as **false**. The ESM discovery is exactly why: findings
we had called false were, on a fuller reference, unfixed. The audit sections above have been
left with their original wording so the sequence of corrections stays legible, but any figure
carried into a report should use the weaker and more accurate term.

The same paper separates *advisory* from *vulnerability* and calls that distinction central to
interpreting tool output. That is our unresolved USN bundling problem under a different name.

### The result that does not depend on any of that

Two scans of one machine, in the same hour, with a package list proven byte-identical
between them, produced 63 findings and 399 findings.

**The unauthenticated report is wrong in both directions at once**, though not in the
proportions first claimed. It invents findings by inferring from version strings on backported
packages. It is also blind to the patch state of everything that does not listen on a port,
which on this host is 112 of 125 advisories. Neither error is detectable from inside the
report.

Which direction dominates depends on the threat model, and that is the honest way to state it.
For a remote attacker the scanner over-reports on a surface it can see. For an attacker already
on the host, or for supply-chain and lateral-movement questions, the unauthenticated report is
close to silent.

### QoD becomes informative only once credentials exist

| QoD | unauthenticated | credentialed |
|---|---|---|
| 30 (version-inferred) | 41 | 216 |
| 80 | 19 | 45 |
| **97 (package-verified)** | **0** | **127** |

Unauthenticated, QoD has almost no variance where it matters and cannot discriminate, which
is what the 19 Aug audit found. Credentialed, a genuinely high-confidence population appears.
**QoD is not a property of a finding so much as a property of the access the scanner was
given**, which is a more useful way to state it and a more defensible feature design.

---

## Gate 2 (planned) - can the attack-graph engine be built at all

**Registered 26 Aug 2026, before the first attempt.**

The consequence head depends entirely on a logical attack-graph engine, and after six weeks
the engine has never been compiled once. The architecture page names this the largest single
risk in the design. This entry exists so the outcome is recorded whichever way it goes.

The engine is MulVAL, which depends on XSB Prolog. XSB is long-lived C code and the usual
point of failure on a modern toolchain. Host is Ubuntu 24.04.4, x86_64, GCC 13 era, with no
compiler, JDK or graphviz installed yet.

### Predictions, fixed in advance

| # | Prediction | What it means if wrong |
|---|---|---|
| 1 | XSB configures and builds from source without patching | the dependency is the blocker, not MulVAL |
| 2 | MulVAL builds once XSB is present | the engine itself is stale |
| 3 | The bundled example input produces a graph | it builds but does not run, the worst outcome to find late |
| 4 | Feeding it one real finding from `target-b1` needs an input format we do not yet have | expected, and the real work of the consequence head |

Prediction 3 is the one that matters. A build that succeeds and then cannot process its own
example is a dead dependency, and the consequence head would need a different engine.

### Fallback if the build fails

A container image with MulVAL preinstalled would answer the narrower question of whether the
engine runs, but not whether we can build and modify it. For a project whose contribution
includes attack-graph rules for findings with no CVE, being able to edit the rule base is not
optional, so a working image would be a partial result rather than a pass.

### Result

**Attempted 4 Sep 2026. The engine builds and runs.** Predictions 1 and 3 held. Prediction 2 was
wrong, and wrong for the reason it anticipated: the engine is stale against a modern toolchain.
What "stale" turned out to mean is narrow, and worth stating precisely, because it is the
difference between a dead dependency and an afternoon of build flags.

| # | Prediction | Outcome |
|---|---|---|
| 1 | XSB configures and builds without patching | **Held.** XSB 3.8.0, released October 2017, configured and compiled on GCC 13.3.0 with no change of any kind. |
| 2 | MulVAL builds once XSB is present | **Wrong.** Four separate failures, none of them a defect in MulVAL. |
| 3 | The bundled example produces a graph | **Held.** A 26-vertex graph reaching `execCode(workStation,root)`. |
| 4 | Feeding a real finding needs an input format we do not have | **Held, and now specific.** See the schema notes below. |

**The four failures under prediction 2, in the order they appeared.** Every one is the toolchain
moving on while the code stood still, six to eight years apart:

| Failure | Cause |
|---|---|
| `cp: '../../bin/adapter': No such file` | `bin/` is absent from the repository, because git does not track empty directories |
| `graphit.tab.h: No such file` | bison 3.8 writes `#include "graphit.tab.h"` into the generated `.c`, and the Makefile renames that header away straight afterwards |
| `reference to 'data' is ambiguous`, about twenty times | C++17 added `std::data`; the code declares a global named `data` and does `using namespace std`; GCC 13 defaults to C++17 |
| `multiple definition of 'mylval'` | GCC 10 changed the default from `-fcommon` to `-fno-common`, so a tentative definition appearing in both the parser and the lexer no longer merges |

Note that `-fpermissive` does **not** cover the ordered comparison of a pointer against integer
zero at `attack_graph.cpp:1197`. That one needs the source edit.

**Total change required: five lines, none in the rule base.**

| File | Change |
|---|---|
| `src/attack_graph/Makefile` | `mv` to `cp` for the bison header; `-fcommon -std=gnu++14 -fpermissive` added to the g++ line; `-fcommon` added to the gcc line |
| `src/attack_graph/attack_graph.cpp:1197` | `fa > 0` to `fa != 0`, a null check that was written as an ordered comparison |
| `bin/`, `bin/adapter`, `bin/metrics` | created by hand |
| `kb/` | **untouched** |

Originals kept as `Makefile.orig` and `attack_graph.cpp.orig`.

**What prediction 3 produced.** `graph_gen.sh input.P -v -p` wrote `AttackGraph.txt`, `.xml`,
`.dot`, `.eps`, `VERTICES.CSV` and `ARCS.CSV`. Only the last step, EPS to PDF, failed, for want of
`epstopdf`; that is cosmetic, and `dot -Tpdf AttackGraph.dot` renders the same graph without it.

**Two schema corrections the run settled**, both of which had been assumed rather than checked
when the architecture page documented the graph:

- `vulExists` and `vulProperty` are separate facts in the input file, but MulVAL **merges them
  into one LEAF node**: `vulExists(webServer,'CAN-2002-0392',httpd,remoteExploit,privEscalation)`.
  An adapter must emit both and should expect one node back.
- The rule base derives **seven** predicates, not the three that were listed: `execCode`,
  `netAccess`, `canAccessHost`, `accessFile`, `principalCompromised`, `logInService`,
  `accessMaliciousInput`. The three-host example reaches only three of them, so reading the
  example alone would have understated the vocabulary.

A third detail worth recording: the goal is declared in the input as `attackGoal(...)`, which
makes it a modelling choice of ours in the same way `attackerLocated` is.

**Consequence for the project.** The fallback registered above, a prebuilt container, is not
needed. The engine builds from source and the rule base is editable, which was the stated
condition for a pass rather than a partial result. Prediction 4 is now the live work, and it is
narrower than feared, because the fact vocabulary is fixed, small, and now read off real output
rather than guessed.

---

## Gate 3 (planned) - is the dataset large enough to train a ranker at all

**Registered 28 Aug 2026, before the first attempt.**

Prioritisation is designed as learning to rank. Learning to rank treats one report as one
query group and learns an ordering within it, so the unit that matters is not the number of
findings but the number of *hosts*. The Nessus licence allows 20 IPs, so the ceiling is 20
query groups. Standard ranking benchmarks are three orders of magnitude larger.

| | query groups |
|---|---|
| MSLR-WEB10K, the usual LTR benchmark | 10,000 |
| this project, at the licence ceiling | 20 |

That gap is not a detail. It is plausible that the ranker cannot be separated from a plain
sort of the classifier score, and it is better to know that before the technique is written
into a chapter as a contribution.

### Relevance grades, fixed now so they cannot be tuned to the result

Graded from external sources only, never from the team's own judgement:

| grade | condition |
|---|---|
| 2 | the finding's CVE is in CISA KEV |
| 1 | the scanner confirmed interaction rather than inferring from a banner (QoD 95+) |
| 0 | everything else |

### Predictions, fixed in advance

| # | Prediction | What it means if wrong |
|---|---|---|
| 1 | The ranker trains without erroring on roughly 20 query groups | the group count alone is not the blocker |
| 2 | NDCG@10 under host-held-out splitting is **no better** than sorting by the classifier probability | LTR is earning its place, a stronger result than expected |
| 3 | Variance across held-out hosts is wide enough that the two cannot be separated | the sample is too small to answer the question at all, which is a finding about the study design rather than about LTR |
| 4 | Adding list-level features (shared fix action, cost per action) changes the ordering measurably | the one thing a ranker can use that a per-finding score cannot has no effect here, and the two-stage design loses its justification |

Prediction 2 is the one that matters. If a ranker trained on this data cannot beat sorting by
the score, the honest move is to say so and drop the stage, not to keep it because it was
planned.

### Fallback if the ranker cannot be separated from a sort

Sort by the classifier probability, then select under budget k with a knapsack over fix
actions. No learning in that step. The contribution survives, because the learned part was
always the score rather than the sort, and selection under a fixed remediation budget is an
optimisation problem in the first place. Contribution 3 is stated as a model that *scores*
every finding; the classifier satisfies that on its own.

### Result

*(to be filled in after the attempt)*

---

## The false-positive audit

> **Revised 20 Aug 2026. The original conclusion in this section was partly wrong and has
> been retracted.** It reported 8 of 20 Critical/High findings as false and claimed QoD
> separated false findings from genuine ones. The corrected figures are 6 false, 2 genuine,
> and QoD separates neither. What follows is the corrected analysis and the reason the first
> one failed, kept in full because the failure is itself a methodological result.

### Why the first audit was wrong: the host patched itself mid-scan

`target-b1` had been built with the network disconnected so that it would stay unpatched.
Scanning it requires reconnecting the network. Ubuntu's `apt-daily-upgrade.timer` is set
`Persistent=true`, so a job missed while the machine was powered off runs shortly after the
next boot. Powering the VM on to scan it therefore triggered `unattended-upgrades`.

| time (GMT+7) | event |
|---|---|
| 13:53:04 | `unattended-upgrades` starts, six seconds before the scan |
| 13:53:10 | OpenVAS scan starts |
| 13:56:26 | Nessus scan starts |
| **13:58:18** | **`libssl1.1` upgraded, 2.17 to 2.24** |
| **14:02:30** | **`openssh-server` upgraded, 4ubuntu0.5 to 4ubuntu0.13** |
| 14:03:34 | Nessus scan ends |
| 14:09:50 | OpenVAS scan ends |
| 14:11:35 | `unattended-upgrades` finishes, 140+ packages |

The host changed underneath both scans. The changelogs were then read hours later, so they
described a machine that no longer matched the one that had been scanned. Seven genuine
findings were marked false on that basis.

`apache2` was never upgraded, at any point in the machine's life. That is why part of the
original result survived.

### The corrected method

The first version asked "is this CVE listed in the changelog?". That is the wrong question.
The right one is "was the fix present in the version installed **at the moment of the scan**?"

| package | version during the scan | note |
|---|---|---|
| `apache2` | `2.4.41-4ubuntu3.23` | never modified; `Installed` equals `Candidate`, so fully patched |
| `openssh-server` | `1:8.2p1-4ubuntu0.5` | upgraded to `0.13` at 14:02:30, mid-scan |
| `libssl1.1` | `1.1.1f-1ubuntu2.17` | upgraded to `2.24` at 13:58:18, mid-scan |

Versions are compared with `dpkg --compare-versions`, not as strings. The analysis is
implemented in `verify_backport.py`, which takes the scan-time versions as an explicit
required argument so the original mistake cannot be repeated silently:

```bash
python3 verify_backport.py --findings processed/findings_openvas_b.csv \
    --changelog-dir evidence \
    --version apache2=2.4.41-4ubuntu3.23 \
    --version openssh-server=1:8.2p1-4ubuntu0.5 \
    --version libssl1.1=1.1.1f-1ubuntu2.17 --by-qod
```

### Corrected results, OpenVAS on `target-b1`

| | original claim | corrected |
|---|---|---|
| findings carrying a CVE | 40 | 40 |
| **false positive** | 14 (35%) | **7 (17.5%)** |
| **true positive** | not reported | **7 (17.5%)** |
| **undetermined** | not reported | **26 (65%)** |
| **Critical/High false** | **8 of 20 (40%)** | **6 of 20 (30%)** |
| **Critical/High true** | not reported | **2 of 20** |
| Critical/High undetermined | not reported | 12 of 20 |

> **These corrected figures were themselves superseded later the same day.** Scan 7 showed the
> host was never fully patched, which contaminates two of the six. See Scan 7 for the current
> position: at least 4 unambiguously false, 2 mixed, one contradiction unresolved. The figures
> in this table are kept as the record of the second of three passes.

**The six confirmed false positives.** All `apache2`, all against a package carrying every
fix Ubuntu has published for it:

```
Critical 9.8  Apache HTTP Server < 2.4.60 Multiple Vulnerabilities
Critical 9.8  Apache HTTP Server 2.4.0 - 2.4.55 HTTP Request Smuggling
Critical 9.0  Apache HTTP Server < 2.4.55 Multiple Vulnerabilities
High     7.5  Apache HTTP Server 2.4.30 - 2.4.55 HTTP Request Smuggling
High     7.5  Apache HTTP Server < 2.4.59 Multiple Vulnerabilities
High     7.5  Apache HTTP Server < 2.4.58 mod_macro Out-of-bounds Read
```

(plus one Medium, `Apache HTTP Server 2.4.17 - 2.4.57 DoS`, for seven in total)

**The seven previously miscounted findings are true positives.** All `openssh-server`, all
citing CVEs whose fixes arrived after `4ubuntu0.5`:

```
Critical 9.8  OpenBSD OpenSSH < 9.3p2 RCE            CVE-2023-38408  fixed in 0.8
High     7.0  OpenSSH 6.2 <= 8.7 Privilege Escalation CVE-2021-41617  fixed in 0.11
Medium   6.8  OpenBSD OpenSSH 6.8p1 - 9.9p1 MitM
Medium   6.5  OpenBSD OpenSSH < 9.6 (Terrapin)        CVE-2023-48795  fixed in 0.10
Medium   5.9  OpenBSD OpenSSH Information Disclosure
Medium   5.9  Prefix Truncation Attacks in SSH (Terrapin)
Low      3.8  OpenBSD OpenSSH 7.4 - 9.9 Unspecified
```

### Nessus was right, and the earlier claim against it is withdrawn

This section previously stated that Nessus's single Medium CVE finding, Terrapin
(CVE-2023-48795), was also a false positive, on the evidence that the server advertises
`kex-strict-s-v00@openssh.com`. That check was run after the machine had already upgraded
openssh, so it tested `0.13`, not the `0.5` that Nessus had scanned. Ubuntu shipped the
strict key-exchange fix in `0.10`. At scan time the host did not have it.

**Nessus produced no false positives on this host at all.**

### QoD does not separate false findings from genuine ones

The strongest claim in the original audit was that detection confidence predicted which
findings were wrong. It does not.

| QoD | false positive | true positive |
|---|---|---|
| 30 | 7 | 7 |

Every finding with a verdict, in both directions, sits at QoD 30. The apparent correlation
was an artefact: once the openssh findings were wrongly labelled false, the false set
contained everything, and everything version-inferred is QoD 30 by definition. QoD 30 means
"inferred from a version string", which is exactly the population in which both correct and
incorrect findings live.

**This is a negative result and it should be reported as one.** It does not defeat the
project's premise, but it removes the one concrete piece of evidence that had been offered
for it. What separated the two groups here was the package, not anything present in the
report.

### What survives

- **Backporting false positives are real and measured.** `apache2` sat at
  `2.4.41-4ubuntu3.23` with `Installed` equal to `Candidate`, having never been modified,
  and OpenVAS still reported six Critical/High findings against it. Nothing about the
  timeline incident touches this: the scanned version and the audited version are the same.
- **It reframes scanner disagreement.** Part of the gap between the tools is one of them
  being wrong, and the quieter tool being closer to correct. This holds more strongly now,
  since Nessus's error count on this host is zero.
- **The mechanism generalises.** Every distribution that backports exposes version-inference
  checks to it.

**Caveat to state in the report:** the evidence is package version comparison against the
distribution's patch record, not exploit testing.

### Limitation: the changelog only reaches back ten revisions

Ubuntu ships a truncated changelog. All three files retrieved from `target-b1` contain
exactly ten stanzas: `apache2` reaches back only to `3.13` although `3.23` is installed,
`openssh` to `0.4`, `openssl` to `2.15`. Anything fixed before that window is invisible.

This is why 26 of 40 CVE-bearing findings are undetermined rather than judged. **The
false-positive count is a lower bound**, and "undetermined" must not be read as "genuine".
Obtaining the full history needs the distribution's published security data (USN or OVAL)
rather than the file on disk.

### Limitation: the verification method does not generalise

Comparing installed package versions against the distribution's patch record requires
filesystem access to the target. We have it because we built these machines. **In a real assessment the analyst
usually does not**, which is the situation vulnerability prioritisation exists to serve. The
false-positive rate reported here is therefore established under conditions the method itself
cannot be used in.

This is a limitation of the *verification*, not of the finding. The false positives are real
and the mechanism that causes them (backporting) applies to every Ubuntu, Debian and RHEL
host in the world, whether or not anyone can prove it on a given machine.

Options for the case where the host cannot be inspected, roughly in order of practicality:

| Approach | Viability |
|---|---|
| **Credentialed scanning** | The standard industry answer. With credentials the scanner reads installed package versions directly and the whole error class disappears. Not available when the engagement is external or credentials are withheld. |
| **Distribution security feeds (OVAL, USN)** | Ubuntu publishes machine-readable data mapping each CVE to the package version that fixes it. Usable without touching the host, **but only if the exact distribution revision is known**. Unauthenticated scanning yields the upstream version (`2.4.41`) and not the revision (`-4ubuntu3.x`), so it cannot resolve the question on its own. |
| **Active verification / exploitation** | Testing whether the weakness actually responds. Out of scope for now as a time decision, not an ethical one (Section A of `project_context.md` was corrected on this). Weaker for this particular question than it first appears: see below. |
| **Predicting likely false positives from report context** | The direction that fits this project, and the only one that works **without any host access at all**. It is also now known to be hard: the obvious feature, QoD, was tested and carries no signal, so a model would have to combine weaker ones and may not succeed. |

The last row is worth pursuing if time allows. It would turn the limitation into a result:
verification gives labelled examples on hosts we control, those labels train a model, and the
model is then applicable to hosts we do not control. Establishing whether it generalises needs
the same audit repeated across several hosts, since one host cannot distinguish a real signal
from a coincidence.

Set expectations honestly, though. On the one host audited so far, the feature that looked
most promising turned out to carry nothing, and the thing that actually separated correct
findings from incorrect ones was which package they concerned, which the report does not
say. A model may well find no usable signal. That outcome is publishable as a negative
result, but it should not be planned for as though success were likely.

### Why exploitation is not the obvious answer it looks like

Discussed 20 Aug 2026, after P'Ohm suggested pentesting as the way to confirm false positives
and the team asked whether to add it as an optional component. Two objections, neither of
which depends on the ethics question:

**1. The evidence is asymmetric.** A successful exploit proves a finding is a *true positive*.
A failed exploit proves nothing at all, because failure and a patched target are
indistinguishable from outside: the module may target a different build, the service config
may differ, the module may simply be unreliable, or some unrelated mitigation may be blocking
it. So exploitation confirms real findings but **cannot confirm false ones**, which is the
label we actually need.

The changelog has exactly the opposite shape. It proves a fix was applied, but silence in a
changelog is not proof of vulnerability. The two methods are complementary rather than
substitutable:

| | changelog says fixed | changelog silent |
|---|---|---|
| **exploit succeeds** | contradiction, worth investigating | confirmed true positive |
| **exploit fails** | confirmed false positive (two independent sources) | unknown |

Most findings land in the bottom-right cell, which is the standing argument for a model.

**2. Exploit-module coverage carries the same bias we built group B to avoid.** Working,
packaged exploit modules exist for a few thousand vulnerabilities against a CVE population in
the hundreds of thousands, and the ones that exist are the *famous* ones. Labelling false
positives by what can be exploited would reintroduce selection on the dependent variable, the
exact defect that makes vulhub unusable as a sole dataset. The changelog covers every packaged
component regardless of fame, so on this specific question **its coverage is better than
exploitation's**, which is counterintuitive but holds.

**Where exploitation does help.** Not as a product and not as the primary oracle, but as a
supplementary label source that fills the top-right cell above. It also needs no exploitation
in many cases: the useful tier is *active verification*, meaning querying a service for what
it actually supports rather than trusting its version banner. The Terrapin check already run
on `target-b1` is an example: `ssh -vv` showed the server advertising
`kex-strict-s-v00@openssh.com`, which settled the question without touching the vulnerability.

Note that this tier is what a QoD of 95+ already means. Scanners are capable of it and decline
to do it broadly because it is slow and risky against production systems. A lab has neither
constraint, so **the lab can generate labels that production scanning cannot**, which is an
argument for the lab's existence in the methodology chapter.

If this is taken up, the boundary to write down first: a probe may not change state on the
target and may not cause the vulnerable code path to execute. Note also that scanner-to-
exploit validation already ships commercially (Rapid7 pairs Nexpose findings with Metasploit),
so it is not available as a novelty claim; verify the specifics before citing them.

---

## Not done yet

- [x] Group B, first host: `target-b1`, Ubuntu 20.04.6 VM
- [ ] Group B, more hosts: 18.04 and 22.04 VMs, to measure how findings scale with age
- [ ] Four more group-A targets across different stacks
- [ ] Determine how many of the 26 remaining CVE-bearing OpenVAS findings on `target-b1` are genuine, using the same changelog method
- [ ] Decide whether QoD 30 findings should be excluded, down-weighted, or kept with a flag
- [ ] OpenVAS repeatability check - Nessus was verified deterministic, OpenVAS was not
- [ ] Decide how to count a service exposed on multiple ports
- [ ] Decide which option set to report, and state it in the methodology chapter
- [ ] Decide on authenticated scanning, which would remove the backport error class outright and also answers P'Ohm's point about Nessus yield
- [ ] *Optional, only if time remains:* a small active-verification probe set (5 to 10 finding classes, non-invasive) as a second label source. Needs P'Ohm's sign-off and a written probe boundary first

---

# Reproduction audit, registered 5 Sep 2026

Every number in this file was produced once, months of decisions ago, by scripts that have
since been edited. Two results have already been retracted here, both analysis errors rather
than build errors. Before the MulVAL adapter is written, the parser output it will consume has
to be shown to still be what this log says it is. If the parser is wrong the graph is wrong,
and nothing downstream would reveal it.

## Why `diff` is a fair test

`parse_openvas.py` sorts its input paths (line 260) and its KEV hits (line 135), writes no
timestamp into the CSV, and with `--offline` reads KEV from the local `kev_catalog.json` rather
than the network. Re-running the same command on the same input must therefore produce a
byte-identical file. Any difference is a real change, not noise.

## Predictions, fixed before running

| # | Prediction | If wrong, what it means |
|---|---|---|
| 1 | All seven CSVs in `processed/` regenerate byte-identical | a script changed behaviour after its output was archived, and every number derived from that CSV is suspect |
| 2 | The cross-scanner figures still hold: OpenVAS 56, Nessus 20, 5 of 37 CVEs shared, Jaccard 0.135 | the comparison logic drifted |
| 3 | The backport audit still returns 7 false / 7 true / 26 undetermined of 40 | the version comparison drifted, which is the one that cost a retraction before |
| 4 | The CVE-less percentage resolves the 64.3 vs 64.8 discrepancy below | one of the two is a transcription error and the introduction quotes it |

## A discrepancy this audit must settle

`project_context.md` records both "56 findings, 35.7% carrying a CVE" and "64.8% of OpenVAS
findings have no CVE" for the same scan. Those cannot both be right: 35.7% of 56 is 20
findings, leaving 36 without, which is **64.3%**, not 64.8%. 64.8% would need a different
denominator. **The 64.8% figure is quoted in the D2 introduction draft**, so this is not
cosmetic.

## A reproducibility hole found while preparing this

`kev_catalog.json` is listed in `.gitignore`. It is 1.5 MB, dated 17 Aug 2026, and exists only
on this VM. Every KEV number in this log depends on it, and `--offline` silently skips KEV
lookup entirely when the cache is absent, so a teammate cloning the repo would get different
numbers with no error raised. It is a public CISA feed containing nothing sensitive.
**Recommendation: remove it from `.gitignore` and commit it**, so the KEV figures are pinned to
a specific snapshot rather than to whatever CISA published on the day someone re-ran the script.

## Result, 5 Sep 2026

Predictions 1 to 3 held exactly. Prediction 4 found the error it was looking for. Two further
defects surfaced that were not predicted, and both were live.

| # | Prediction | Outcome |
|---|---|---|
| 1 | CSVs regenerate byte-identical | **Held.** 6 of 6 identical. `findings_nessus.csv` was not regenerated, for the reason in defect A |
| 2 | OpenVAS 56, Nessus 20, 5 of 37 shared, Jaccard 0.135 | **Held exactly**, including 0 CVEs seen only by Nessus |
| 3 | Backport audit returns 7 false / 7 true / 26 undetermined of 40 | **Held exactly.** Critical/High 6 false, 2 true. All 14 findings with a verdict carry QoD 30, so QoD still fails to separate them |
| 4 | The 64.3 vs 64.8 discrepancy resolves | **Resolved. 64.8% is wrong; the correct figure is 64.3%** (20 of 56 carry a CVE, leaving 36) |

Every headline figure for group A reproduces: 56 and 20 findings, 35.7% and 15.0% carrying a
CVE, 1.8% and 0% touching KEV, Critical/High 4/6 and 0/0. The D1 introduction's paired-scan
numbers also reproduce exactly: 63 findings citing 71 distinct CVEs with 20 Critical or High,
against 399 findings citing 646 distinct CVEs with 170 Critical or High.

### Defect A: `findings_nessus.csv` points at the wrong host

`findings_nessus.csv` is **byte-identical to `findings_nessus_b.csv`** (both sha256 `efffb217`).
It holds the 31 findings from the Ubuntu VM, not the 20 from the ActiveMQ container.

`compare_scanners.py` defaults to `--nessus processed/findings_nessus.csv`. So the command this
log records for the cross-scanner comparison,

```bash
python3 compare_scanners.py --openvas processed/findings_openvas.csv --expect CVE-2016-3088
```

today compares group A OpenVAS against **group B Nessus**: two different machines. It raises no
error and prints plausible numbers. Reproducing the recorded 0.135 required naming
`findings_nessus_a.csv` explicitly.

Nothing published is wrong, because the original run predates the file being overwritten. The
trap is for whoever runs the documented command next.

**Fixed the same day.** Deleting the file alone would not have been enough: three scripts
defaulted to that one generic filename, so the next run without `-o` would have recreated it.

| Change | File |
|---|---|
| Stale duplicate deleted (recoverable from git history) | `processed/findings_nessus.csv` |
| `--openvas` and `--nessus` are now **required**. The old `--openvas` default pointed at `processed/findings.csv`, which does not exist | `compare_scanners.py` |
| **Refuses to run when the two inputs share no host**, printing both host sets and both filenames. Warns and narrows to the intersection when they only partly overlap | `compare_scanners.py` |
| `-o` is now **required**, so a scan cannot silently overwrite another scan's output | `fetch_nessus.py`, `parse_nessus.py` |
| Recorded commands updated: they named no `--nessus`, and used a `cd ~/data` that has not been the right path for some time | this file |

Verified both ways after the change. Pairing group A OpenVAS with group B Nessus now stops with
`refusing to compare: the inputs cover no host in common`, naming `172.18.0.17` against
`192.168.194.150`. The correct pairing still reproduces the published figures exactly: 56 and 20
findings, 37 and 5 unique CVEs, 5 reported by both, 0 seen only by Nessus, Jaccard 0.135.

### Defect B: the "36% to 65%" range covers less than it claims

The D2 introduction draft says findings without a CVE range "from 36% to 65% of findings across
the hosts and scanners measured so far". Measured across every archived scan:

| Scan | Findings | No CVE |
|---|---|---|
| OpenVAS, group A container | 56 | **64.3%** |
| OpenVAS, `target-b1` unauthenticated | 63 | **36.5%** |
| OpenVAS, `target-b1` credentialed | 399 | **17.0%** |
| Nessus, group A container | 20 | **85.0%** |
| Nessus, `target-b1` | 31 | **93.5%** |

The stated range covers only the two unauthenticated OpenVAS scans. The true range across hosts
and scanners is **17.0% to 93.5%**. The sentence claims a breadth it does not have, and it
understates the problem badly for Nessus, where the CVE-less share is the highest in the corpus
and the argument for covering those findings is strongest.

Note also that credentialed scanning *lowers* the CVE-less share, from 36.5% to 17.0%, because
what it adds is mostly vendor advisories that carry CVEs. Any claim about coverage has to say
which access level it refers to.

---

# Gate 2, prediction 4: the adapter. Result 5 Sep 2026

Prediction 4 was that feeding a real finding to MulVAL would need an input format we did not
have. It held, and building that format surfaced two things worth keeping.

## MulVAL's own adapter cannot be used, and the reason is our contribution

`src/adapter/` ships a Nessus translator. Three blockers, in increasing order of importance:

1. **It requires MySQL.** Four of its Java files open JDBC connections.
2. **It reads `.nessus` XML.** Our Nessus data is JSON from the REST API, because Essentials
   blocks file export.
3. **It is keyed on the CVE identifier.** Its `vuln_exists` facts take Range and Losstype from
   an NVD dump, so a finding with no CVE yields no fact and therefore no node.

Point 3 is the CVE coverage gap, demonstrated in the reference implementation's own code rather
than asserted. Worth stating in D2 exactly this way.

## The trap that produces an empty graph with no error

The rule that fires for a remote exploit binds one variable across two facts:

```prolog
execCode(H, Perm) :-
    vulExists(H, _, Software, remoteExploit, privEscalation),
    networkServiceInfo(H, Software, Protocol, Port, Perm),
    netAccess(H, Protocol, Port).
```

If `vulExists` says `httpd` and `networkServiceInfo` says `apache2`, nothing derives, the graph
is empty, and MulVAL reports success. `findings_to_mulval.py` therefore reads the software name
for a port once, from the topology file, and uses that one string in both facts.

Note also that `Perm` is the account the service runs as, and it becomes the privilege the
attacker is modelled as gaining. **An unauthenticated scan cannot see it.** It is declared in
the topology file, alongside `hacl` and `attackerLocated`, which are equally absent from every
scanner report. The script refuses to invent all three.

## A bug only real data could find

The first run corrupted `VERTICES.CSV` and `AttackGraph.dot`, and graphviz refused to render.
Cause: **MulVAL's graph writer uses `:` as an internal field separator.** The fallback identifier
for a CVE-less finding was `oid:<nvt_oid>`, so 23 colons were stripped out of the vertices and
dumped at the front of line 1 of both files. Changed to `oid_`. Recorded in the function's
docstring so it cannot be reintroduced.

## Result

```bash
python3 findings_to_mulval.py --findings processed/findings_openvas_b.csv \
        --topology topology_target_b1.json -o input.P
export MULVALROOT=$HOME/mulval
export PATH=$HOME/XSB/bin:$MULVALROOT/bin:$MULVALROOT/utils:$PATH
graph_gen.sh input.P -v -p
dot -Tpdf AttackGraph.dot -o AttackGraph.pdf      # epstopdf is absent; this replaces it
```

| | |
|---|---|
| Findings read | 63 |
| Facts emitted | 62 pairs, 1 duplicate collapsed, plus 2 `networkServiceInfo` |
| **Of those, carrying no CVE** | **23, and all 23 appear in the finished graph** |
| Graph | **139 vertices, 252 arcs**: 69 LEAF, 66 AND, 4 OR |
| Goal | `execCode(targetB1,'www-data')` reached |
| Rules that fire | 1 (local exploit), 2 (remote exploit of a server program), 5 (multi-hop access), 6 (direct network access) |

For scale, the example bundled with MulVAL produces 26 vertices. One real unauthenticated scan
of one host produces 139.

**RULE 5, multi-hop access, fires.** That is the lateral-movement machinery P'Ohm asked about,
working. It currently matches only the `hacl(H,H,_,_)` self-loop, because the lab is one flat
network with one target. The rule needs no change; the topology does.

## Still provisional

`vulProperty`'s consequence is `privEscalation` for every finding, because that is the only
value the rule base acts on for server programs. It should come from the CWE that the
Classification stage assigns, and that stage is designed but not built. The mapping is isolated
in `consequence_for()` for exactly this reason. **Any consequence number derived from the graph
today is a demonstration that the pipeline runs, not a measurement of consequence**, and must
not be reported as one.

---

# The three open decisions, closed 6 Sep 2026

Deliverable 2 has to propose a whole system, so these three could not stay open. Each is
committed to below **together with the measurement that would show it is wrong and the fallback
if it is**, so that revising any of them in Deliverable 3 is evidence acting on a registered
prediction rather than an embarrassment.

Two counts over the archived corpus decided all three. They are measured, not assumed:

| | |
|---|---|
| Findings archived | 632 |
| Carrying a CVE | 436 |
| **Touching CISA KEV** | **17** |
| **Distinct CVEs** | **682** |

17 positives is not a training set for anything. 682 continuous targets is.

## Decision 1: a finding with no CVE gets an EPSS surrogate

Train a gradient boosting **regressor** to predict EPSS from report-level features only, using
features every finding has, then apply it where EPSS does not exist. Target `logit(EPSS)`, since
EPSS is heavily skewed toward zero. Training set: the 682 distinct CVEs, scored from a pinned
FIRST.org snapshot held the same way `kev_catalog.json` is.

**This does not contradict the earlier rejection of regression.** That rejection was of
regressing onto EPSS *as the answer key for risk*, where the best attainable result is a tie.
Here EPSS is imputed where it is missing and never used where it already exists. The surrogate
runs on the CVE-less subset alone.

**Falsified if** Spearman correlation between predicted and true EPSS on a held-out host split
falls below 0.3. **Fallback:** CVE-less findings take likelihood 0 and are ranked on consequence
alone, and the negative result is reported, because "report-level features do not carry
EPSS-like signal" answers Q1 in the negative and is worth knowing.

## Decision 2: the two heads are multiplied, not weighted by a learned model

`risk = likelihood x consequence`. Both inputs are bounded on [0, 1], so the product is too.

**The reason is the number 17.** Split by host, roughly ten KEV positives land in any training
fold. A weighting fitted on that is noise with a decimal point. Multiplying probability by
impact is the textbook definition of risk, requires no label, and applies to a finding with no
CVE exactly as to one with a CVE, so the extrapolation problem is removed rather than managed.

**Registered for comparison, not abandoned.** If the corpus reaches the 20 hosts the Nessus
licence allows, train a gradient boosting classifier over both head values with KEV as the label
on the CVE-bearing subset, and compare against the product by NDCG on held-out hosts. **Adopt it
in D3 only if it wins by a margin that survives the host split**, and state the extrapolation as
a limitation. If it does not win, the product stands and the comparison is the result.

## Decision 3: consequence is one over the shortest attack depth

A finding on no path to the goal scores **0**. Otherwise **1/d**, where d is the number of rule
nodes on the shortest attacker-to-goal path through it. Bounded on (0, 1], needs no training,
and reads as how many steps from here the goal is. A finding granting the goal outright has
d = 1 and scores 1.0.

**Path counting was considered and rejected:** counts explode combinatorially and measure the
shape of the graph more than the importance of the finding.

Interchangeable findings correctly receive identical consequence. The 34 Apache findings on
`target-b1` all yield the same `execCode`; deduplicating the *fix* belongs to Prioritise.

**Known degeneracy.** On the present one-host flat lab nearly everything scores d = 1, so the
measure discriminates nothing yet. That argues for building the multi-segment lab, not for
choosing another formula.

**Falsified if**, once separate segments exist, more than roughly 80% of findings still share a
single value of d. **Fallback:** binary reaches-the-goal, reported together with the degeneracy.

---

# External label sources, pinned 8 Sep 2026

Three of the four learned stages train on labels this project does not author. All three
are public catalogues that change daily, so all three are captured as dated snapshots and
read from disk afterwards. A number produced from a live lookup cannot be reproduced
tomorrow, and the reproduction audit above only worked because `kev_catalog.json` was
already pinned this way.

| Label | Trains | Source | Snapshot |
|---|---|---|---|
| CISA KEV membership | Risk prediction, and the relevance grades for Prioritise | CISA | `kev_catalog.json`, catalogVersion 2026.08.17, 1,666 CVEs |
| EPSS score | The exploit-likelihood surrogate | FIRST | `epss_scores-2026-09-08.csv.gz`, model_version v2026.06.15, score_date 2026-09-08T12:02:46Z, 369,025 CVEs |
| CWE assignment | Classification | NVD | `cwe_map.json`, fetched per CVE through the 2.0 API |

`fetch_labels.py` builds the last two. It reads only the CVEs actually cited in
`processed/findings_*.csv`, because downloading all of NVD would take hours and none of
the rest would be used.

## EPSS result

680 of the 682 distinct CVEs in the corpus carry an EPSS score. The two without are
`CVE-2022-49267` and `CVE-2024-8928`. The script prints the missing identifiers rather
than dropping them silently: those are rows the surrogate cannot be evaluated against, and
a count that appears without explanation is how a quiet exclusion becomes an inflated
result.

`epss_lookup.csv` carries the source filename and the model version in two comment lines
above the header, so a table derived from it can always be traced to the snapshot it came
from.

## Where the NVD API key lives

`data/.nvd_api_key`, mode 600, matched by a `.gitignore` rule added the same day and
verified with `git check-ignore`. The key is never written into `fetch_labels.py`. Without
a key NVD allows 5 requests per 30 seconds and the fetch takes about an hour; with one it
allows 50 and takes about eight minutes.

## What is still not pinned

Nothing else, but note what these snapshots do **not** fix. EPSS is recomputed daily by
FIRST, so a finding's likelihood on a later snapshot will differ even though nothing about
the finding changed. Any comparison across time has to name the snapshot on both sides.

---

# What the labels actually cover, measured 8 Sep 2026

Two questions were open: what Classification should predict, and where its label should come
from. Both are now answered by measurement rather than by preference, and a third thing
surfaced that neither question anticipated.

## The label source: CVSS, not CWE

MulVAL does not read CWEs. It reads `vulProperty(id, Range, Consequence)`, where Range is
one of `remoteExploit` / `localExploit` and the only Consequence the rule base acts on for
server programs is `privEscalation` or `dos`. A CWE is therefore an intermediate the
pipeline converts away, and the question is whether to predict it at all.

Both mappings are definitional and come from outside the project. NVD publishes a CVSS
vector per CVE: `AV:NETWORK` is `remoteExploit`, `AV:LOCAL` is `localExploit`, an impact on
confidentiality or integrity is `privEscalation`, an impact only on availability is `dos`.
Nothing here is a table the team wrote.

| Target | Classes | Findings labelled | Conflicting |
|---|---|---|---|
| CWE, rolled up to Class level | 64 | 410 | 151 (37%) |
| **(range, consequence) from CVSS** | **4** | **430** | 108 (25%) |
| (range, consequence), splitting LOW impact out | 6 | 430 | 122 (28%) |

CVSS wins on every axis: fewer classes, more rows labelled, fewer conflicts. Splitting the
LOW impact band into its own `infoLeak` class makes conflicts worse without labelling
anything extra, so the two-level reading is kept.

**The conflicts resolve the same way EPSS does.** A finding citing several CVEs takes the
worst case each axis admits, `remoteExploit` over `localExploit` and `privEscalation` over
`dos`, which is the rule already written for the maximum EPSS. Applied, it leaves 430
findings across 4 classes with no conflicts by construction: 265, 83, 71 and 11.

**A correction worth recording.** The first run of this measurement reported only 518 CVEs
mappable and concluded that CVSS covered *less* than CWE. That was a bug in the analysis,
not a property of the data: CVSS v3 grades impact as NONE, LOW or HIGH, and the test
accepted only HIGH and the v2 spellings, discarding every LOW. 147 CVEs were dropped that
way. Counting LOW as an impact, which is what it means, raises coverage to 665 of 681.

## CWE consequences are not a usable substitute

MITRE publishes `Common_Consequences` for 944 CWEs, which raised the possibility of deriving
a consequence for a finding that has no CVE at all. Measured against the CVSS-derived label
on the CVEs where both exist, **they agree 72% of the time**, and they fill only 13 gaps
CVSS leaves.

The disagreement is structural rather than noise. MITRE describes what a weakness class can
generally cause; NVD describes what one vulnerability actually does. CWE-200 is scoped to
Confidentiality, which reads as `privEscalation`, while many CVE instances of it carry only
`C:LOW`. Potential of a class is not impact of an instance.

That 72% is worth keeping as a number, because it is the ceiling on the pipeline's last
step: even a classifier that predicts weakness type perfectly would still assign the wrong
consequence about a quarter of the time.

## The finding that changes the framing: 78% of CVE-less findings are Log level

| Threat | With CVE | Without CVE |
|---|---|---|
| Critical | 62 | **6** |
| High | 152 | **0** |
| Medium | 193 | 28 |
| Low | 28 | 9 |
| **Log** | 1 | **153** |

**153 of the 196 findings without a CVE are Log level**, which is service and product
detection. Those are observations that something is running, not weaknesses. Scoring the
risk of *HTTP Server type and version* is not meaningful, and leaving them in dilutes every
proportion this project has reported.

Excluding Log, the corpus is 478 findings of which **43 carry no CVE, which is 9% rather
than 31%**.

The contribution still holds, but its target is narrower than the raw count suggests. All
six Critical findings without a CVE score 10.0, and no High-severity finding lacks a CVE at
all. The population is small and sharp:

```
Critical 10.0  PHP End of Life (EOL) Detection
Critical 10.0  OpenSSL End of Life (EOL) Detection
Critical 10.0  Apache ActiveMQ Web Console Default / No Credentials
Critical 10.0  Mort Bay / Eclipse Jetty End of Life (EOL) Detection
Medium    6.4  MQTT Broker Does Not Require Authentication
```

**Decision: Log-level findings are filtered before scoring**, and the CVE coverage figures
are restated on the filtered corpus. Any figure quoted from before this date includes them.

## How much signal the existing features carry

Predicting the label from `nvt_family` alone reaches 69%, against 62% for always guessing
the largest class. **Seven points.** Whatever separates these classes is mostly in the text
of `nvt_name`, which has not been tested. Until it has, the Classification stage should be
treated as unproven rather than merely unbuilt.

And the limit is the lab, not the labels: 43 CVE-less non-Log findings drawn from two hosts
is too few to evaluate anything, however the label is defined.

---

# Gate 1: the group A against group B comparison, 9 Sep 2026

Registered at the start of the project and open ever since, because group B did not exist.
It does now. The question was whether the CVE coverage gap measured on deliberately
vulnerable images survives on targets chosen without reference to the outcome.

## Scan 8: group B, five age-selected images

`raw/openvas/2026-09-08_openvas_B_group-b-old-images.xml`

| | |
|---|---|
| Targets | `172.18.0.110-114`: wordpress:4.7, httpd:2.4.29, mysql:5.5, tomcat:8.0, nginx:1.10 |
| Selected on | **age alone**, which is independent of whether a vulnerability was ever exploited |
| Scanner | OpenVAS 23.50.0, `Full and fast`, port list `TCP 1-65535 (match Nessus)` |
| Alive test | Consider Alive |
| Authentication | none |
| Duration | **10 min 21 s**, 21:01:58 to 21:12:19 UTC |
| Result | 306 findings across 5 hosts, 61.2 per host |

The filename carries the UTC date the scanner recorded. In local time the scan ran early on
9 September; the machines run UTC while the team works GMT+7, as `lab_setting.md` notes.

## The result

| | group A, chosen for notoriety | group B, chosen by age |
|---|---|---|
| Hosts | 1 | 5 |
| Findings | 56 | 306 |
| **No CVE, all findings** | **64.3%** | **22.9%** |
| **No CVE, excluding Log** | **29.6%** | **6.1%** |
| Touching KEV | 1.8% | 2.6% |
| Critical / High | 4 / 6 | 53 / 73 |

**The gap is roughly five times smaller on targets that were not selected for being
famous.** This is the opposite of what the project assumed. Group B was described in
Deliverable 1 as the group that "approximates a real report", and the expectation was that
it would show a comparable or larger gap. It shows 6.1% where group A shows 29.6%.

**The contribution survives, but the number that supports it changes.** The severe findings
without a CVE are still there and are still severe:

```
Critical 10.0  Nginx End of Life (EOL) Detection                 172.18.0.114
Critical 10.0  Operating System (OS) End of Life (EOL) Detection 172.18.0.110
Critical 10.0  PHP End of Life (EOL) Detection                   172.18.0.110
High      7.5  WordPress Multiple Vulnerabilities (May 2017)     172.18.0.110
```

Across the whole corpus, findings with no CVE that are not Log level rise from 43 to **58**.

## What must change in how this is reported

**6.1% is the figure to lead with, not 64.3% and not the 36 to 93% range quoted before.**
Group B is the only group selected independently of the outcome, and Log-level detections
are excluded because they are observations rather than weaknesses. Every earlier figure
either included Log, or came from targets picked for being famous, or both.

**Both groups should be reported together, because the difference is itself the result.**
Contribution 1 promises a measurement of the CVE coverage gap "across target environments
chosen so that the measurement is not distorted by the way vulnerable test environments are
usually assembled". A five-fold difference between a fame-selected and an age-selected group
is exactly that measurement, and it is more interesting than either number alone.

## The comparison is not yet balanced

Group A is **one container**; group B is five. The registered plan was five against five.
Until four more vulhub targets are scanned, the group A side rests on a single ActiveMQ
container and its 56 findings, so the five-fold ratio should be treated as an indication
rather than a measurement. Adding those four is the next lab task.

---

# Gate 1 completed at five hosts against five, 9 Sep 2026

The entry above reported a five-fold difference between the groups. **That figure was
computed with one host on the group A side and is superseded by what follows.** Four more
vulhub targets have been scanned, and the gap is smaller than a single container suggested.

## Scan 9: group A, four vulhub targets

`raw/openvas/2026-09-09_openvas_A_group-a-vulhub.xml`

| | |
|---|---|
| Targets | `172.18.0.101-104`: drupal 8.5.0, struts2 2.3.30, couchdb 2.1.0, redis 4.0.14 |
| Selected on | **notoriety**, which is the bias this group exists to expose |
| Configuration | identical to Scan 8 and to the 18 Aug ActiveMQ scan |
| Duration | **11 min 17 s**, 05:42:38 to 05:53:55 |
| Result | 160 findings across 4 hosts |

Combined with the ActiveMQ scan of 18 August, which used the same configuration, group A is
now five hosts and 216 findings.

## The corrected result

| | group A, chosen for notoriety | group B, chosen by age |
|---|---|---|
| Hosts | 5 | 5 |
| Findings | 216 (43.2 per host) | 306 (61.2 per host) |
| **No CVE, excluding Log** | **12.9%** | **6.1%** |
| Touching KEV | 2.8% | 2.6% |
| Critical / High | 25 / 44 | 53 / 73 |

**The ratio is 2.1, not 5.** Adding four hosts halved group A's figure, from 29.6% to 12.9%.

## Why the number moved, per host

```
group A                          group B
  activemq   29.6%                 tomcat     33.3%   (3 non-Log findings only)
  struts2    21.1%                 nginx      14.3%
  redis       8.0%                 wordpress   7.1%
  couchdb     5.6%                 httpd       2.6%
  drupal      4.7%                 mysql       2.0%
```

**ActiveMQ is an outlier, not a representative of its group.** Every CVE coverage figure this
project published before today rested on that one container, and drupal, a deliberately
vulnerable target selected for fame, sits *below* wordpress in group B.

**Spread within each group exceeds the difference between them**, 4.7 to 29.6 against 2.0 to
33.3. Tomcat's 33.3% is one finding out of three that are not Log level and carries no
weight. Five hosts per group is not enough to say whether a 2.1 ratio is a property of the
selection method or an accident of which ten images were picked. That is a limit on the
claim, not a reason to withhold the number.

## What survives unchanged

Thirty-two findings across the two groups carry no CVE and are not Log level, and the most
severe are still scored 10.0:

```
Critical 10.0  activemq   Apache ActiveMQ Web Console Default / No Credentials
Critical 10.0  struts2    Eclipse Jetty End of Life Detection
Critical 10.0  drupal     Operating System End of Life Detection
Critical 10.0  nginx      Nginx End of Life Detection
```

They appear in **both** groups rather than clustering on ActiveMQ, so the contribution holds:
a method keyed on the CVE identifier is undefined on findings that include the most severe
ones present. The honest range to quote is **6% to 13%**, not the 30% to 64% quoted so far.

## A correction to the entry above

That entry attributed the `2026-09-08` filename to the machines running UTC while the team
works GMT+7. **This machine is set to UTC throughout**, host, container and all, so local and
UTC dates are the same and the filename simply records the day the scan ran. The note in
`lab_setting.md` about adding seven hours does not describe the current configuration.

---

# Does the text carry signal? A floor, measured 9 Sep 2026

The Classification stage rests on an untested assumption: that the wording of a scanner check
predicts the weakness well enough to be worth learning. `signal_check.py` puts a floor under
it with multinomial naive Bayes over token counts, written in plain Python because the
machine has no scikit-learn. It is deliberately the weakest reasonable model: whatever the
real one achieves, it should beat this.

543 findings across 11 hosts carry a label once Log-level detections are excluded.

| Features | Accuracy | Against baseline |
|---|---|---|
| `nvt_family` alone | 54.5% | **-9.8** |
| finding title text | 71.3% | +7.0 |
| **text and family** | **73.5%** | **+9.2** |

Baseline is 64.3%, always predicting `remoteExploit/privEscalation`. Evaluation is
leave-one-host-out with the vocabulary refitted on each fold, because findings on one machine
are strongly correlated and a random split would train and test on the same Apache install.

## A measurement of mine that was wrong

An earlier entry reports `nvt_family` reaching 69% against a 62% baseline. **That was
measured in sample:** the family distribution was computed on the same rows it was scored
against, so it could not lose. Evaluated out of fold it reaches 54.5%, which is **worse than
guessing the majority class**. Family alone carries no transferable signal at all; it looked
like it did only because the test was wrong.

## Where the accuracy actually comes from

```
remoteExploit/privEscalation   323/349   92.6%
localExploit/privEscalation     35/96    36.5%
remoteExploit/dos               40/86    46.5%
localExploit/dos                 1/12     8.3%
```

**The headline 73.5% is mostly the majority class being predicted well.** Every other class
is at or below chance for a four-way problem. `localExploit/dos` is right once in twelve.
Reporting 73.5% without this breakdown would misrepresent what the model does.

## What this does and does not settle

**Settled:** the title text carries some signal, +7.0 points on its own, and `nvt_family`
carries none that survives a host split.

**Not settled:** whether a stage can be built on it. Naive Bayes with token counts is a floor,
not an attempt. Class weighting, TF-IDF, and the numeric fields not yet used at all, `port`,
`severity`, `qod` and `solution_type`, should all help, and `dos` against `privEscalation` in
particular looks like something severity and port ought to separate.

The threshold to decide against: **if a tuned model with class weighting and the numeric
fields cannot clear the baseline by roughly 20 points, the stage does not stand up on this
data and the design has to change rather than the model.**

## The tuned attempt, and a threshold I set against the wrong metric

`signal_check2.py`, same data, same leave-one-host-out protocol, with the four things the
floor lacked: TF-IDF instead of raw counts, class weighting, the numeric fields, and gradient
boosting. sklearn's HistGradientBoosting stands in for XGBoost, which is not installed.

| Model | Accuracy | **Macro-F1** | F1 over baseline |
|---|---|---|---|
| text only, logistic regression | 78.3% | 57.1% | +37.6 |
| text, categorical and numeric | 72.0% | 55.2% | +35.7 |
| categorical and numeric, no text | 56.0% | 43.1% | +23.6 |
| **gradient boosting, all features** | 77.3% | **59.2%** | **+39.7** |

Baseline is accuracy 64.3% but **macro-F1 19.6%**, because always predicting the largest
class scores zero on the other three.

**The threshold registered in the entry above was stated as "roughly 20 points over
baseline" and the script applied it to accuracy, which gives +13.1 and reads as a failure.
That is the wrong metric, and the same file says so two paragraphs earlier:** accuracy here
mostly measures how imbalanced the data is, macro-F1 is what Deliverable 2 commits to
reporting, and against macro-F1 the result is +39.7. The verdict is that the stage stands
up. The lesson is that a threshold is only as good as the metric attached to it, and this one
was written without attaching it.

## Where the model now succeeds and fails

```
                              precision  recall     F1   support
localExploit/dos                  0.400   0.167  0.235        12
localExploit/privEscalation       0.723   0.625  0.670        96
remoteExploit/dos                 0.696   0.558  0.619        86
remoteExploit/privEscalation      0.803   0.888  0.844       349
```

Three of four classes clear 0.6, against the floor where every minority class was at or below
chance. `localExploit/dos` remains poor at 12 examples, which is a property of the corpus
rather than of the model.

## An expectation that was wrong

Adding `severity`, `port`, `qod` and the categorical fields to logistic regression **lowered**
accuracy from 78.3% to 72.0%. The prediction was that severity would separate `dos` from
`privEscalation` and port would separate local from remote. For a linear model the one-hot
family encoding appears to swamp the text instead, and family was already shown not to
transfer across hosts. Gradient boosting with the same inputs reaches the best macro-F1,
which is what selecting features internally is for, and is the behaviour that motivated
choosing that family in the design.

## Three defects in that evaluation, and the corrected result

The +39.7 above was measured on a corpus with three problems, all of which inflated it.

**One host was 75% of the data.** `target-b1` contributed 407 of 543 labelled rows, so the
pooled metric was largely a measurement of that machine.

**35% of rows were duplicates.** `target-b1` appears in three reports: unauthenticated, again
after patching, and once with credentials. The same finding on the same host repeats across
them, and a repeated row is not an independent observation.

**Four hosts contributed a single finding each.** Under leave-one-host-out, a fold holding one
sample scores macro-F1 of 100% for guessing once. Nine of eleven folds scored exactly 100%
for that reason, and the two folds with real data scored 52.6% and 33.3%.

The fix is deduplication on (host, finding name), and excluding the credentialed scan, which
is a different population from the unauthenticated scans group A and group B consist of.

| | All reports, deduplicated | Unauthenticated only |
|---|---|---|
| Labelled findings | 355 | **170** |
| Largest host's share | 64% | **26%** |
| Accuracy | 76.3% | **86.5%** |
| **Macro-F1** | 58.0% | **62.0%** |
| F1 over baseline | +38.5 | **+40.9** |

**Removing half the rows improved every number**, because what was removed was one machine
repeated rather than additional evidence.

```
                              precision  recall     F1   support
localExploit/dos                  0.000   0.000  0.000         1
localExploit/privEscalation       0.677   0.955  0.792        22
remoteExploit/dos                 0.783   0.783  0.783        23
remoteExploit/privEscalation      0.939   0.871  0.904       124
```

## What this supports, and what it does not

**Supported.** The Classification stage stands up on this data: macro-F1 62.0% against a
baseline of 21.1%, well past the threshold registered before the run. Gradient boosting beats
logistic regression and beats every feature set without text, which confirms two things
Deliverable 2 asserts: the finding title carries real signal, and a boosted tree suits this
shape of data.

**Not supported.** Any claim about magnitude. 170 findings across 11 hosts is small; four of
those hosts contribute fewer than five findings each and their folds measure nothing;
`localExploit/dos` has one example in the entire corpus. The honest statement is that the
stage is viable, not that it achieves 62%.

**The corpus, not the model, is now the limit.** Adding hosts raises the number of usable
folds, which is what would turn this indication into a measurement.

---

# 12 September 2026: what a remediation action is, and what it costs

**The question.** The D2 feedback asked what the remediation budget is measured in. The
paper said "cost per action" and "pick within budget" with no unit and no source, which is
not a cost model. Two things had to be settled before anything could be written: what one
action is, and where its cost comes from.

**The unit.** Actions, not money and not person-hours. Money and hours are properties of the
organisation doing the work, cannot be observed in this laboratory, and would have to be
invented, which is the design this project has ruled out from the start. An action count is
exact and reproducible from the reports.

**Defining the action took three attempts, and the two failures are the useful part.**

| key | actions | findings each | verdict |
|---|---|---|---|
| host + exact remediation text | 333 | 1.22 | over-counts |
| host + port + remediation, versions normalised | 132 | 3.07 | under-counts |
| host + port + product + remediation, versions normalised | 183 | 2.21 | adopted |

Exact text over-counts because Greenbone writes "Update to version 2.4.30 or later" and
"Update to version 2.4.41 or later" as separate remediations for one upgrade of one
component. Normalising the version numbers fixes that and introduces a worse error: without
the product in the key, the largest single action merged **42 findings across Apache HTTP
Server, PHP and WordPress on one port**, which is three upgrades presented as one.
Under-counting is the more dangerous direction, because it makes a budget look as though it
reaches further than it does. The product is recovered from the leading words of the check
title, before the first version or comparison operator.

**The cost.** From `solution_type`, which Greenbone publishes per check and is therefore a
statement about remediation effort made outside this team. Three tiers: patch available
(`VendorFix`), configuration change (`Mitigation`, `Workaround`), no fix available
(`WillNotFix`, `NoneAvailable`). An action takes the cheapest tier any of its findings
admits. All 183 actions received a tier: 137, 36 and 10 respectively. **The weights between
the tiers are a declared parameter, not a measurement**, and any result must be reported
across a sweep of them. This is the same discipline as the attack graph's environment
description: declared, visible in the output, and never presented as observed.

```bash
cd ~/data
python3 fix_actions.py
python3 fix_actions.py --by-host
```

**Result, on 405 deduplicated non-Log findings across 11 hosts.** 183 actions, 2.21 findings
each. The work is heavily concentrated: **the 10 largest actions are 5.5% of the plan and
clear 48.4% of the findings**, and the largest is one Apache upgrade closing 30. Per host the
ratio varies from 1.00 to 6.38, and the two extremes are informative: `172.18.0.112` is one
MySQL image where 51 findings are 8 actions, while `172.18.0.102` is a Struts image where 19
findings are 18 separate ones.

**What this settles.** Ordering findings and ordering actions are different problems. A
ranked list of findings is not a remediation plan, because one upgrade closes many rows at
once, and that is now measured rather than asserted.

**What it does not settle.** The tier weights, which are ours. Whether the product string
parsed out of a check title is reliable across scanners; it has only been checked against
OpenVAS titles. Nessus remediation text has not been examined at all, and the cross-tool
merge would have to reconcile two vendors' wording of the same fix.

**A parser change this implies.** `processed/findings_*.csv` carries `solution_type` but not
the remediation text, so `fix_actions.py` has to read the raw XML. Adding a `solution` column
to `parse_openvas.py` would remove that dependency. Not done, because regenerating the
processed CSVs is a state change and every measurement recorded above was taken from the
current ones.

---

# 28-29 September 2026: the pipeline runs end to end, and three measures fail on the way

The first day the project produced a risk score rather than a measurement about its data.
Four scripts were written, three of them measure something that had never been measured
here, and two designs that had been on paper since D1 turned out not to work. The failures
are recorded in as much detail as the successes, because each was found by a check that was
registered in advance and each changes what Deliverable 3 can claim.

## Label snapshots were 40% short, and every earlier number ran on the shortfall

`epss_lookup.csv` and `cwe_map.json` were built on 8 September, before the group A and
group B scans existed. Measured before refreshing:

| | before | after |
|---|---|---|
| corpus CVEs with an EPSS score | 680 of 1140 | 1135 of 1140 |
| corpus CVEs with a CWE or CVSS vector | 681 of 1140 | 1131 of 1140 |
| findings usable to train the surrogate | 170 | 375 |

455 of the 460 missing EPSS scores were already present in the snapshot file on disk. The
refresh cost one command and no download. **This is the stale-input failure the manifest
discipline was introduced to catch, and it had already happened before the manifest
existed.** After the refresh, every finding that cites a CVE has a score: the 35 findings
without one are exactly the findings with no CVE at all.

## The likelihood head: the surrogate does not beat the severity column

`likelihood.py`. EPSS where a published score exists, a gradient boosting regressor on
log10(EPSS) where it does not. Leave-one-host-out, every transform fitted inside the fold.

```bash
cd ~/ThreatRank_Experiment/data
python3 likelihood.py
```

| model | Spearman | note |
|---|---|---|
| surrogate, host split | 0.698 | inflated, see below |
| surrogate, CVE split | 0.418 | the honest number |
| predict the median | 0.000 | |
| severity alone | 0.492 | **beats the surrogate** |

**Registered before the run: the surrogate must clear Spearman 0.3 and beat both baselines.
It cleared the threshold and failed the baseline.** On this corpus a boosted model over the
title, the family, the solution type and six numeric fields orders findings no better than
the one number the scanner already prints.

The verdict function originally checked only the threshold and announced success. That is
the same defect as the "+20 points" threshold registered in September without naming a
metric, committed twice in one month, and it is now checked in code.

## Leave-one-host-out was not holding anything out

Measured directly, per held-out host, against the union of the training folds:

| held-out host | its CVEs | also in training |
|---|---|---|
| 172.18.0.101 | 47 | 47, 100% |
| 172.18.0.111 | 48 | 48, 100% |
| 172.18.0.102 | 11 | 11, 100% |

**Seven of eleven hosts share 100% of their CVEs, and 100% of their finding titles, with the
training folds.** The model sees `Apache HTTP Server < 2.4.49` and its EPSS target on
another machine during training and then predicts it on the held-out one. Grouping instead
by the CVE that supplied the target closes that route, and the gap between the two splits,
0.698 against 0.418, is the size of the memorisation.

The gap widened with more data: it was 0.199 on the stale snapshot and 0.280 after the
refresh. **A host-split number on this corpus improves as the corpus grows without the
method improving at all.** Both splits are now reported and the CVE split is the headline.

## Three hosts, three segments, and multi-hop fires for the first time

`topology_lab3.json` declares a web, application and database tier over three hosts already
scanned, with the attacker reaching only the web tier and the goal at the database.

```
internet --tcp:80--> vmWeb (.110)  --tcp:80--> vmApp (.111)  --tcp:3306--> vmDb (.112)
goal: execCode(vmDb, _)
```

The reachability is declared, not enforced: all three containers sit on one Docker bridge
and the scanner reaches all of them, because otherwise there would be no findings. Scan
reachability and attacker reachability are different questions and the file says so.

Result: 387 vertices, 736 arcs, and both `execCode(vmDb,mysql)` and `execCode(vmDb,root)`
derived. **Rule 5, multi-hop access, matched something other than the `hacl(H,H,_,_)`
self-loop for the first time in this project.** The full chain appears:
`execCode(vmWeb,'www-data')`, `execCode(vmWeb,root)`, `execCode(vmApp,'www-data')`,
`execCode(vmApp,root)`, `execCode(vmDb,mysql)`, `execCode(vmDb,root)`.

## Two defects in the adapter, both of which inflated the graph

**Log-level rows were entering as vulnerabilities.** `findings_to_mulval.py` filtered
nothing. Service and product detections are not weaknesses and every other measurement in
this project excludes them; 60 were entering the three-host graph, 32 of them with no CVE,
which is why the adapter counted 44 CVE-less findings where `consequence.py` counted 12.
Fixed: the graph fell from 547 vertices to 477 and the two counts now agree.

**Every finding was emitted as `privEscalation`.** `consequence_for()` returned a constant,
marked PROVISIONAL since it was written. With the refreshed CVSS data it now reads the
published vector:

```
 173  remoteExploit/privEscalation
  44  remoteExploit/dos            <- was granting code execution it cannot grant
  11  localExploit/privEscalation
   1  localExploit/dos
 217 from the published vector, 12 assumed
```

The graph fell again to 387 vertices. The 44 denial-of-service findings now derive nothing,
which is correct.

## The consequence head: two measures failed before one worked

**C = 1/d, derivation distance to the goal.** Takes exactly one value per host: 0.5 on the
database tier, 0.167 on the application tier, 0.1 on the web tier, and nothing distinguishes
findings on the same machine. Multiplying likelihood by a per-host constant sorts hosts.
Precision at five fell from 0.60 to 0.00 and the first KEV finding moved from rank 3 to rank
11, because every MySQL finding was boosted fivefold over every web finding and not one
MySQL finding on this lab has ever been observed being exploited.

**C from a counterfactual: remove the fix, does the goal survive?** Implemented per
remediation action, since removing one of 126 interchangeable Apache CVEs changes nothing
while upgrading Apache removes all of them. Result: **zero of 47 actions cut the goal, and
every action removed 0.000 of the attacker's reachable facts.**

The reason is structural and is the most important measurement of the day:

```
LEAF 190   AND 188   OR 9
```

**The graph's 188 rules derive nine distinct facts**: code execution at two privilege levels
on each of three hosts, and network access to each. Every finding that leads anywhere leads
to one of those nine, so no per-finding ordering can be recovered from the structure, and
no single fix changes what is reachable.

**C is therefore an indicator, not a magnitude.** It is 1 when the goal is derivable from
the finding and 0 when it is not, which keeps R = L x C exactly as the advisor asked for it
while using only what was measured. Distance was our invention; reachability is the graph's
own answer. On this lab 45 of 229 findings score zero.

## End to end, and the evaluation scope that was wrong

`risk.py`. Graded against CISA KEV, which is the label and is never a feature.

**Scoped to the 217 findings that carry a CVE**, the only scope KEV can grade:

| ordering | P@5 | P@10 | P@20 | first KEV |
|---|---|---|---|---|
| R = L x C | 1.00 | 0.60 | 0.30 | 1 |
| L alone | 1.00 | 0.60 | 0.30 | 1 |
| severity | 0.60 | 0.40 | 0.20 | 1 |
| EPSS only | 1.00 | 0.60 | 0.30 | 1 |

**Over the whole list including the 12 findings with no CVE**, the same method scores 0.60
at P@5 rather than 1.00.

**A finding with no CVE can never appear in KEV.** It is keyed by CVE. Every such finding is
therefore a guaranteed negative, and any method that ranks them low gains precision for
free. Measured: choosing the learned surrogate over the severity surrogate raised P@5 from
0.60 to 1.00, not because it predicts better, but because it assigns lower scores to the
twelve findings that cannot be positives. **A KEV metric over a mixed list rewards
suppressing exactly the findings this project exists to score.** The scoped table is the one
to report and the mixed one is for contrast only.

## What can honestly be claimed

Among findings that carry a CVE, ThreatRank equals EPSS, the strongest published baseline,
and beats the scanner's own severity ordering: P@5 of 1.00 against 0.60, P@10 of 0.60
against 0.40. **It does not beat EPSS there, and it adds nothing to EPSS there, because on
that subset L is EPSS.** That has to be written plainly.

Outside that subset EPSS scores nothing at all, and coverage needs no label:

```
EPSS can score      217/229  94.8%
ThreatRank scores   229/229  100%
```

## The twelve, which are four different things

Grouped by the fix action that closes them, **eight of the twelve are the only finding in
their action**, and four share an action with CVE-bearing findings:

| finding | severity | alone in its action |
|---|---|---|
| Operating System (OS) End of Life | 10.0 | yes |
| PHP End of Life | 10.0 | yes |
| PHP Heap Use-After-Free (Sep 2019) | 6.8 | yes |
| Unprotected Web App / Device Installers | 5.0 | yes |
| WordPress Unspecified Vulnerability (May 2023) | 5.0 | yes |
| TCP Timestamps Information Disclosure (x3) | 2.6 | yes |
| WordPress Multiple Vulnerabilities (May 2017) | 7.5 | no, with 34 CVEs |
| PHP Multiple Vulnerabilities (Sep 2019) | 6.8 | no, with 43 CVEs |
| PHP < 7.3.30 Security Update | 5.0 | no, with 43 CVEs |
| PHP < 7.3.28 IMAP Header Injection | 5.0 | no, with 43 CVEs |

**The four that share an action add no coverage in practice.** Upgrading PHP on that host is
already required by 43 CVEs, so a CVE-only pipeline fixes them by accident. **The eight that
stand alone are the real claim**: if the system cannot see them, that work is not scheduled
at all.

The claim to make in Deliverable 3 is therefore about actions, not rows. It is a smaller
number than 12 of 229 and a much harder one to argue with.

A check that was expected to shrink the twelve did not: the six vendor-advisory findings
carry **no CVE reference of any kind**, only vendor URLs such as
`php.net/ChangeLog-7.php#7.3.30` and `bugs.php.net/78363`. Greenbone wrote these checks from
changelogs, not from NVD. They are genuinely uncatalogued rather than a reporting artefact,
which was the opposite of the working assumption.

## A yardstick for end-of-life findings that needs no judgement

The scanner reports the end-of-life date itself, read from the vendor:

```
Debian GNU/Linux 8    EOL 2020-06-30   cpe:/o:debian:debian_linux:8
PHP 5.6.30            EOL 2018-12-31   cpe:/a:php:php:5.6.30
```

Measured on 172.18.0.110: of 106 PHP CVEs on that host, **70 were published after PHP 5.6
stopped receiving fixes**. Eleven of those carry an EPSS score above 0.1 and the highest is
0.9999.

```
importance of an end-of-life finding
  = CVEs of that product on that host published after the vendor's EOL date
```

Every input is external: the EOL date from the vendor through the scanner, the publication
date from NVD, the score from FIRST. Nothing here is a parameter this project can tune.

**The end-of-life finding carries no CVE and EPSS cannot score it, yet it is the single
condition that makes seventy scored vulnerabilities on that host unfixable.** A pipeline
that scores only CVE-bearing findings sees the seventy and misses the one thing holding
them in place.

Limitation: the count is of CVEs the scanner found on that host, not of every CVE ever
published for PHP 5.6. The true figure is larger. The narrower count is preferred here
because it is confirmed present on the machine rather than merely applicable to it.

## 29 September 2026: the end-of-life yardstick, measured

`eol_lock.py`. The end-of-life dates are arguments rather than constants because the scanner
reports them in its description text, which the parser does not carry into the processed
tables, and a value observed at scan time is stated rather than reconstructed later.

```bash
cd ~/ThreatRank_Experiment/data
python3 eol_lock.py --host 172.18.0.110 \
  --eol php=2018-12-31 --eol os=2020-06-30 \
  --findings processed/findings_openvas_b2.csv
```

**Result on 172.18.0.110**, which runs PHP 5.6.30 on Debian 8:

| held in place by | CVEs | above 0.1 EPSS | max EPSS |
|---|---|---|---|
| PHP end of life alone, from 2018-12-31 | 21 | 4 | 0.9978 |
| operating system end of life alone, from 2020-06-30 | 78 | 28 | 1.0000 |
| both at once | 49 | 7 | 0.9999 |
| **union, nothing counted twice** | **148** | **39** | **1.0000** |

**148 of the 307 CVEs on this host, 48.2%, were published after the software carrying them
stopped receiving fixes.** The host is locked twice over: the operating system's end of life
covers every package from its own date, the PHP end of life covers PHP from an earlier one,
and 49 CVEs are held by both. Summing the two counts would report those 49 twice, so the
output partitions.

**Every CVE on this host that appears in CISA KEV is in the locked set. All four of them,
with none left patchable.** Three carry an EPSS above 0.999.

```
CVE-2021-40438   EPSS 1.0000   2021-09-16   KEV
CVE-2024-4577    EPSS 0.9999   2024-06-09   KEV
CVE-2024-38475   EPSS 0.9996   2024-07-01   KEV
CVE-2019-11043   EPSS 0.9978   2019-10-28   KEV
```

The two findings that produce this carry no CVE. EPSS cannot score them, KEV cannot list
them, and a pipeline keyed on CVE identifiers never sees the condition that makes the rest
unfixable.

**An overclaim caught in the script's own output.** The first version of this ended with
"none of this is scored by EPSS or listed by KEV", which the table above disproves on the
same screen: those CVEs carry scores near 1.0 and four are in KEV. What carries no score is
the end-of-life finding itself. The corrected claim is stronger as well as true, because it
is about vulnerabilities everyone has already scored highly rather than about ones nobody
noticed. The wrong sentence is recorded in a comment in `eol_lock.py` so it is not written
back.

**Every input is external.** The end-of-life date comes from the vendor through the
scanner, the publication date from NVD, the score from FIRST and the exploitation status
from CISA. There is no parameter here this project can tune, which is the reason for
preferring this measure to anything the team would have to judge.

**Limitation.** The count is of CVEs the scanner found on that host, not of every CVE ever
published for PHP 5.6 or Debian 8. The true figure is larger. The narrower count is used
because it is confirmed present on the machine rather than merely applicable to it.

## Where the twelve uncatalogued findings now stand

| group | count | how it is judged |
|---|---|---|
| share a fix action with CVE-bearing findings | 4 | no judgement needed: the action is already required, so they are closed either way |
| end of life | 2 | the measure above |
| TCP Timestamps Information Disclosure | 3 | undecided, and the question is whether they belong in scope at all |
| PHP Heap Use-After-Free, Unprotected Installers, WordPress May 2023 | 3 | **no external yardstick. To be stated as a limitation** |

Five yardsticks were considered and rejected, and the reasons are worth keeping. Priors per
CWE class depend on the CWE classifier, which this corpus already showed does not work.
SSVC is an external framework but its decision points still need someone to fill in.
Agreement between two scanners is external and would work, but these three hosts carry
OpenVAS only. Exploit databases do not cover end-of-life or configuration findings. The
attack graph is ours, so using it to grade our own scores is circular.

A check that was expected to shrink the twelve did not. The six vendor-advisory findings
carry no CVE reference of any kind, only vendor URLs such as `bugs.php.net/78363`.
Greenbone wrote those checks from changelogs rather than from NVD, so they are genuinely
uncatalogued rather than a gap in our parsing, which was the opposite of the assumption
going in.

---

# 29 September 2026, later: the feature that was being thrown away at the parser

Everything above was measured on findings represented by their check title alone. The title
names a product and a version range and almost never says what the weakness allows, which
is why two stages that had to infer exactly that were failing. The scanner does say it, in
a field the parser never read.

## Where the text was

Greenbone packs each check's write-up into one pipe-separated string in `<nvt><tags>`:
`cvss_base_vector=...|summary=...|insight=...|impact=...|affected=...`. Because none of
those is an element, an earlier check for `<impact>` in the raw XML returned zero matches
and the conclusion drawn was that no impact text existed. It existed; the check looked for
the wrong shape.

```
TCP Timestamps    impact = the uptime of the remote host can sometimes be computed
Apache < 2.4.49   insight = NULL pointer dereference, buffer overflow, mod_proxy SSRF
```

A title cannot separate those two. That text can.

## One wrong field before the right one

The first attempt read the result's own `<description>`, which is **detection evidence**,
not a description of the weakness: `Installed version: 2.4.10 Fixed version: 2.4.49` for a
version check and packet counters for the timestamp check. It contributed version numbers
and port numbers and no meaning.

| text given to the models | classifier macro-F1 |
|---|---|
| title only | 57.4% |
| title plus the result's detection evidence | **50.6%** |
| title plus the NVT summary, impact and insight | **59.0%** |

The middle row is worth keeping: adding text made the model worse, and the reason was that
the text was the wrong text.

## The likelihood surrogate now passes both of its registered conditions

Registered before the first run: clear Spearman 0.3 **and** beat the baselines.

| | title only | with the write-up |
|---|---|---|
| surrogate, host split | 0.698 | 0.722 |
| **surrogate, CVE split** | **0.418** | **0.624** |
| severity alone | 0.492 | 0.492 |
| predict the median | 0.000 | 0.000 |

**0.624 against 0.492. The surrogate beats the severity column for the first time**, and the
earlier verdict that it was not justified is superseded rather than corrected: it was true
of the features it had.

The gap between the two splits fell from 0.280 to 0.098. That gap is the part of the score
that came from recognising a title seen on another host, so its narrowing says the model
stopped memorising product names and started reading what the check says. `severity alone`
uses no text and did not move, which makes it a fixed reference across both runs.

MAE on EPSS fell from 0.2625 to 0.2072.

## The classifier improved and still cannot do its job, for a reason features cannot fix

Same text, macro-F1 from 57.4% to 59.0%, and `remoteExploit/dos` recall from 0.600 to 0.707.
**Every one of the 29 findings with no published vector is still predicted
`privEscalation`.**

The reason is not the features and not the sample size. MulVAL's vocabulary offers
`privEscalation` and `dos`, and for a finding whose entire impact is that an attacker can
compute the host's uptime, **neither is correct**. The right answer is that it grants
nothing, and that class does not exist. Forcing a choice between two wrong answers
guarantees a wrong answer however good the features become.

Following that through: for findings that carry a CVE, NVD publishes the properties and
nothing needs predicting. For findings that do not, the model cannot produce them and the
label space does not contain the right answer. **As a supplier of range and consequence the
Weakness Classification stage has no job it can do**, which is a finding about the
architecture rather than about the model, and it needs the advisor's involvement because
the stage appears in both the figure and Section III.

## End to end, with the surrogate now justified on its own evidence

Using `--surrogate model` because it beats severity on Spearman under the CVE split, **not**
because it improves P@k. Choosing it on P@k would repeat the bias recorded yesterday, where
a KEV metric pays a method for ranking down the findings that can never be KEV positives.

| ordering | P@5 | P@10 | P@20 | first KEV |
|---|---|---|---|---|
| R = L x C | 1.00 | 0.60 | 0.30 | 1 |
| L alone | 1.00 | 0.60 | 0.30 | 1 |
| severity | 0.60 | 0.40 | 0.20 | 1 |
| EPSS only | 1.00 | 0.60 | 0.30 | 1 |

The scoped and whole-list tables are now identical. With the severity surrogate they were
not: the whole list scored 0.60 at P@5 against 1.00 scoped, and that gap was
`severity / 10` placing uncatalogued findings four times too high and crowding the top.

## Where the uncatalogued findings actually land

The obvious way to score well on a KEV metric is to push every CVE-less finding to the
bottom. That is not what happened:

```
rank  81 of 229  L=0.2029  Operating System (OS) End of Life
rank  86 of 229  L=0.1743  PHP End of Life
rank  96 of 229  L=0.1223  Unprotected Web App / Device Installers
rank  98 of 229  L=0.1041  TCP Timestamps Information Disclosure
rank 144 of 229  L=0.0231  PHP Heap Use-After-Free (Sep 2019)
```

They sit between the 35th and the 63rd percentile, spread across sixty ranks rather than
bunched, and ordered plausibly: the two end-of-life conditions above the specific PHP
updates. The gain at P@5 therefore comes from findings with genuinely high EPSS rising, not
from these being buried.

**The one that is wrong is visible in the same table.** `TCP Timestamps` sits at rank 98
with `C = 1.0`, which says the graph can derive database compromise from the disclosure of
a host's uptime. It reaches that rank because of the assumed property, not because of
anything measured, and it is the clearest argument for not emitting findings with no
published vector as `vulExists` facts at all.

## Status of the two axes

```
likelihood   surrogate clears both registered conditions      demonstrated
consequence  assumed for findings with no published vector    not demonstrated
```

One axis works and the other does not, and the reason the second does not is understood
rather than suspected.

## What this invalidates above, and what it does not

`processed/findings_*.csv` were regenerated with two new columns. Row counts are unchanged
in all six files, so the corpus is the same corpus.

| earlier result | status |
|---|---|
| surrogate 0.418, loses to severity | **superseded**: 0.624, wins |
| classifier predicts privEscalation for nearly all | still true, macro-F1 now 59.0% |
| graph 387 vertices, 45 findings at C = 0 | unchanged; the graph reads CVSS, not text |
| end-of-life holds 148 of 307 CVEs | unchanged; publication dates, not text |
| KEV cannot grade findings with no CVE | unchanged; a property of KEV |

The superseded line is left in place above. It was the correct result for the features that
existed when it was measured, and replacing it would hide that the improvement came from a
parser change rather than from a better model.

## 29 September 2026: what to do with a finding nothing describes

Three answers were implemented and two were reverted. The question is narrow and the
consequences are not: what range and consequence does a finding get when NVD publishes no
CVSS vector for it? On the whole corpus that is 35 findings of 410.

**Drop them.** Implemented, run, reverted within the hour. The graph fell from 387 vertices
to 363 and the count of CVE-less findings in it fell to zero, which by itself ends the claim
that uncatalogued findings are first-class objects on this axis. Worse, the list of what
leaves the plan reads:

```
sev 10.0  Apache ActiveMQ Web Console Default / No Credentials
sev 10.0  Operating System (OS) End of Life        x2
sev 10.0  Jetty End of Life                        x2
sev 10.0  Nginx End of Life
sev 10.0  PHP End of Life
sev  7.5  Redis Server No Password
sev  6.4  MQTT Broker Does Not Require Authentication
```

A remediation plan that does not mention a Redis server running without a password, or an
ActiveMQ console reachable with default credentials, is wrong in a way a practitioner sees
in one glance. Those are also two of the three examples the advisor named when identifying
the finding-centric model as the project's core contribution.

**Predict them.** Covered above: 28 of 29 rows received the same pair the constant would
have given, and the correct answer for several is absent from MulVAL's vocabulary.

**Keep the constant and make it visible.** Adopted. Every assumed fact is now marked in
`input.P`:

```prolog
vulProperty('oid_...80091', localExploit, privEscalation).   /* ASSUMED: no published vector */
```

and the counts appear in the adapter's output as `published: 217, assumed: 12`.

The cost is not hidden. `TCP Timestamps Information Disclosure` sits at rank 98 of 229 with
a consequence of 1.0, which says the graph derives database compromise from the disclosure
of a host's uptime. That is false and it is the price of not dropping the findings that
matter. What makes it tolerable is measured rather than argued: removing every assumed fact
leaves the goal derivable and loses none of the nine facts the graph derives, so **no
conclusion drawn from the graph rests on the assumption. Only the position of those twelve
findings in the plan does.**

**This is an open problem, not a solved one.** The right answer needs a third consequence in
the vocabulary, meaning a finding that grants nothing, and MulVAL has no such term. That is
a change to the rule base rather than to this project's code, and it should be described in
Deliverable 3 as the limitation it is.

## 29 September 2026: what the classification stage is for, settled

The advisor's answer to what the stage should produce was a category to look at rather than
an input to a score, and then, asked what the category is for: **to know what to do**. That
second answer changes the taxonomy entirely, and in the project's favour.

### CWE was the wrong axis for this question

A CWE says what kind of weakness a finding is in theory. It does not say what anyone has to
do about it: `Improper Neutralization` and `Improper Access Control` can both be closed by
the same package upgrade. Measured on the corpus anyway, since the work was already done:

| taxonomy | classes | largest share | singletons |
|---|---|---|---|
| CWE as NVD assigns | 129 | 6.8% | 39 |
| CWE pillar, MITRE view 1000 | 10 | **58%** | 0 |

Neither serves a reader. The first is too dispersed to summarise, the second puts more than
half of everything into `Improper Control of a Resource Through its Lifetime`, which is not
a sentence anyone triages by.

`cwe_pillars.py` and `cwe_pillars.json` are kept regardless. The extraction is 23 KB from an
18 MB catalogue, pinned at version 4.20, and it answers a different and still useful
question about what kinds of weakness the corpus contains. The catalogue itself is
gitignored: four attributes of it are read and the rest is prose.

**A gap in NVD, not in this project, surfaced while measuring.** Of 410 findings, 76 have no
CWE: 35 carry no CVE at all, and **39 carry a CVE for which NVD publishes no weakness type**,
recording `NVD-CWE-noinfo` instead. Those 39 have a CVSS vector and an EPSS score and no
statement of what kind of flaw they are.

### The action type is already in the schema

What a reader needs in order to know what to do is the kind of work, and Greenbone states it
per check:

| | | |
|---|---|---|
| 358 | 87.3% | `VendorFix`, a patch exists |
| 33 | 8.0% | `Mitigation`, configuration change |
| 10 | 2.4% | `WillNotFix` |
| 5 | 1.2% | blank, **all five from Nessus** |
| 3 | 0.7% | `Workaround` |
| 1 | 0.2% | `NoneAvailable` |

**98.8% is covered with no model at all**, and the one gap is Nessus, which publishes no
equivalent taxonomy.

This also unifies two things that were separate. The cost model already tiers findings by
`solution_type`: patch available, configuration change, no fix available. The category a
reader sees and the category the budget is computed from are now the same category, rather
than two schemes that would each need explaining.

### What is left for the classifier, and why it is a better job than the last two

Predicting the action type for rows where the scanner supplies none. Today that is five
rows; it grows with every Nessus scan added, so running Nessus on the nine hosts that have
only OpenVAS changes the size of the job.

Unlike the two targets already abandoned, this one is well posed. `(range, consequence)`
failed because the correct answer for some findings is absent from MulVAL's vocabulary. CWE
failed because 129 classes over 410 rows leaves 39 singletons. **Here 405 rows carry a label
written by the scanner, the classes number three, and the rows needing prediction come from
a different tool rather than from a different kind of finding** — which is a distribution
shift that more data can actually close.

It is not measured yet, and it should not be until there is enough Nessus data to measure it
on.

---

# 29 September 2026: Nessus on nine hosts, and what two tools actually agree about

Cross-tool merge had been designed, written into Section III and defended to the advisor
without ever being exercised, because two of eleven hosts had been scanned by both tools.
Nine now have.

## Getting there found two faults, one of them dangerous

**The targets were not running.** The first Nessus scan of group A finished in five seconds
and reported zero findings, with status `completed` rather than `failed`. All nine `tr-*`
containers had exited two days earlier when the machine restarted and none had a restart
policy. Nothing in the scan report says the hosts were down; only the elapsed time and a
host count of zero do.

Had a subset been down rather than all nine, the run would have looked ordinary and the
corpus would have been quietly short. Fixed for good with
`docker update --restart unless-stopped tr-*`, which needs no recreate and leaves the
addresses alone, and recorded in `lab_setting.md`.

**The port field made the two tools unmatchable.** `fetch_nessus.py` wrote the API's display
string through unchanged:

```
openvas   80/tcp
nessus    80 / tcp / www
```

so no Nessus row could ever match an OpenVAS row on `(host, port, product)`. Measured before
the fix: **47 CVEs shared between the tools and zero shared products.** That reads as two
scanners that agree about nothing, and it was one field in our own schema. Port 0 now
becomes `general/<protocol>` to match how OpenVAS marks a finding with no listening port,
and the description and solution columns are now populated for Nessus too.

## What the tools agree about, on nine hosts scanned the same day over the same port range

```
view           openvas nessus   both  ov only  ne only  overlap
by CVE             598     76     47      551       29     7.5%
by product         106     35      3      103       32     2.2%
by host              9      9      9        0        0    100.0%
```

**Agreement is low by any measure and the reason is substantive rather than cosmetic.** On
172.18.0.101, port 80:

```
OpenVAS   31 findings   apache http server
Nessus    19 findings   php
```

Both tools examined the same service on the same machine. One identified the web server and
its version, the other identified the language runtime behind it, and **neither reported
what the other found**. A plan built from OpenVAS alone says upgrade Apache; a plan built
from Nessus alone says upgrade PHP. Both are required.

Per host, and the last row is the one that matters:

| host | OpenVAS | Nessus |
|---|---|---|
| 172.18.0.110 wordpress | 140 | 18 |
| 172.18.0.112 mysql | 51 | 2 |
| 172.18.0.101 drupal | 43 | 24 |
| **172.18.0.113 tomcat** | **3** | **6** |

If OpenVAS led everywhere the finding would be that one tool is more verbose. **One host
where Nessus leads makes it a different claim: a single tool misses real work**, which is
the argument for accepting more than one scanner in the first place.

## Two limits on that number, both of which have to be reported

**The product key is extracted from the check title, and titles are vendor-specific.**
`product_of` fragments one OpenVAS product into several keys: `apache http server` alongside
`apache http server 'mod_auth_digest'` and eight more variants. That inflates the OpenVAS
product count and depresses the overlap, so **2.2% is a floor rather than an estimate**.

The principled fix would be a vendor-neutral identifier, and it is not available: OpenVAS
emits CPE strings, **the Nessus API returns `cpe: None` for every plugin checked**. Matching
therefore stays on titles, and the number stays a floor.

**Nessus found far less overall**, 68 non-Log findings against 343. Fewer is not worse
without a false-positive measurement beside it, and this project has one for OpenVAS only,
on one host. No claim about which tool is more accurate is available from these counts.

## What this settles for the paper

The advisor's second comment asked what happens when two tools report the same weakness. The
answer given was a design, merge before scoring, argued rather than shown. It can now be
shown: **the same weakness, in the sense of the same product on the same host and port,
happens three times in 138 actions.** Merging matters far less for deduplication than the
design implied, and far more for coverage than it claimed, because the overwhelming majority
of what each tool reports is invisible to the other.

---

# 30 September 2026: the prioritisation stage, and what a second label does to its conclusions

The project is named for prioritisation and had never produced a plan. Every stage upstream
was measured; the stage that turns scores into a list of jobs existed only in the design.
That is now built, and building it changed several conclusions, twice.

## What a plan is here

A ranked list of 229 findings is not a plan. One Apache upgrade closes thirty of them, so a
list naming those thirty separately spends thirty slots on one job. Findings are grouped
into actions, `(host, port, product)`, and the plan is a list of actions ordered by value
per unit cost, taken greedily until a budget is spent.

    value    the risk removed, summed over the findings the action closes
    cost     1 for a vendor patch, w_m for a configuration change, w_n for a replacement

Budgets are quoted as a fraction of the cost of doing everything. On the three-tier lab that
total is 68 units, so 5% is about three patches out of 47 jobs: roughly what a small team
has.

## The cost weights turn out not to matter, and that is the useful answer

Nothing external states what a configuration change costs relative to a patch, so the
weights are ours. Holding the plan at six actions and sweeping them:

```
weights 1,1,1    7 of 7 known-exploited, 186 findings, cost 6.0
weights 1,2,5    7 of 7 known-exploited, 186 findings, cost 6.0
weights 1,3,10   7 of 7 known-exploited, 186 findings, cost 6.0
weights 1,5,20   7 of 7 known-exploited, 186 findings, cost 6.0
```

**The same six actions every time**, because the six highest-value actions are all vendor
patches and cost 1 under every weighting. The invented parameter never binds on the part of
the plan anyone would actually do.

An earlier version of this sweep held the budget at a *fraction* of the total, and the total
is computed from the weights, so changing them changed the absolute budget and the sweep
appeared to show a large effect. That was a confound in our own measurement, not a result.

## What the consequence term is for, and where we were measuring for it

Graded on CISA KEV and stopped at a tenth of the budget, `R = L x C` was identical to EPSS
in every cell. The reason was not that C does nothing. It was that the budget never reached
the work C excludes:

```
budget spent on unreachable work, of 15 cost units
                 25%   50%   100%
R = L x C          0     0     15
EPSS               3    11     15
severity           1     9     15
most findings      1    10     15
```

At half the budget an EPSS-ordered plan spends 11 of its 34 units — **a third of the
budget** — on actions whose findings cannot reach the attacker's goal. Reachability is
MulVAL's answer from the topology, not ours from the score, so this is not the score being
graded against itself.

**The filter is safe on the external label**: of the known-exploited findings, none sit in
work the graph calls unreachable.

Grouping cuts the size of the prize, and that has to be said. 45 findings carry C = 0, but
only 11 sit in actions where *every* member is unreachable. The other 34 share an action
with reachable findings and get fixed as a side effect, so the work actually skippable is 11
findings and 15 of 68 cost units.

## Moving the goal moves the plan

The goal is a declaration of what is worth defending, and a reviewer will ask what happens
if it changes. Re-running under three goals:

| goal | top of plan | unreachable actions | cost skippable |
|---|---|---|---|
| `execCode(vmDb,_)` | includes mysql on .112 at rank 4 | 11 of 47 | 15 of 68 |
| `execCode(vmApp,_)` | .112 drops out entirely | 15 | 21 |
| `execCode(vmWeb,_)` | only .110 in the top five | 19 | 27 |

The plan's composition changes, and the narrower the goal the more work is excluded: under
the web goal **40% of all remediation work is irrelevant to what was declared valuable.**

This also produced the clearest instance yet of a bias in our own metric. Under the web
goal, `R = L x C` closes 4 of 7 known-exploited findings at a 5% budget where EPSS closes 7
— because three of them sit on .111, which cannot reach the web host. The pipeline is
right and the label cannot see it: **KEV is goal-agnostic, so it penalises any method that
correctly narrows scope.** This is the second such instance, after its blindness to findings
that carry no CVE.

## A second catalogue, and conclusions that reverse under it

CISA KEV marks seven findings on the three-tier lab. Seven positives cannot separate six
orderings, and indeed every ordering closed all seven by a tenth of the budget.

VulnCheck KEV (5,375 CVEs, snapshot 2026-09-30) marks far more of the same corpus:

```
distinct CVEs in the corpus      CISA 17   VulnCheck 58
findings marked, openvas_b2      CISA  8   VulnCheck 33
172.18.0.110                     CISA  4   VulnCheck 23
```

The additions are the lab's own software: Apache HTTP Server, WordPress, PHP, CouchDB. CISA
KEV is scoped to what US federal agencies must remediate, which is a compliance list rather
than a complete record of observed exploitation.

With 32 positives the orderings separate — **and two findings from the CISA-graded run
reverse**:

```
known-exploited closed     5%    graded on CISA    graded on VulnCheck
R = L x C                            5                   19
EPSS                                 7                   15
ungrouped R                          7                   15
```

Under the registered label, `R = L x C` loses to EPSS at a 5% budget and grouping into
actions buys nothing. Under the wider one, it wins and grouping helps. **This is a sign
flip, not merely a gain in resolution, and both readings have to be reported.**

CISA KEV remains the registered label. It was fixed before any of these results existed and
swapping it now, having seen that the first one is thin, is how a result stops being
publishable whichever catalogue is better. The honest statement is that the registered label
is underpowered at seven positives, that the wider label resolves the comparison, and that
the two disagree in direction at small budgets.

One mechanism is plausible and **not yet tested**: VulnCheck marks many Apache and WordPress
findings, which concentrate in the large actions `R` buys first, so the advantage may come
from a property of the label rather than from better prediction. That has to be checked
before the advantage is claimed.

At larger budgets EPSS leads again (31 against 29 at half the budget) for the goal-agnostic
reason above.

Attribution: VulnCheck asks for prominent attribution in return for free use, and for the
data to be labelled VulnCheck KEV wherever it appears. The paper names it in the text.

## Against the baseline anyone actually has

The list a scanner hands over is findings sorted by its own severity. Against that, on the
registered label:

```
risk removed at a 5% budget      R = L x C  57%      severity-sorted findings  1%
risk removed at a 10% budget                86%                                57%
```

That comparison does not depend on which catalogue grades it, and it is the one the paper
should lead with.

## Two faults found in our own measurement

**The budget grid hid the effect it was meant to show.** Stopping at 10% reported R as
identical to EPSS; the divergence lives at 25–50%.

**Counting findings closed makes the naive baseline win by construction.** "Do the job that
closes the most findings" optimises that metric directly, and it led at 5% (128 against 92)
while removing far less risk (41% against 57%). Risk removed is the quantity the pipeline
exists to reduce, and findings closed is reported beside it rather than instead of it.

---

# 30 September 2026, later: a vendor-neutral key for the correlation stage

Actions were keyed on a product parsed out of the scanner's check title. Reading the generated
plan showed what that costs: rows 6, 7 and 8 repeated rows 1, 3 and 5 under different names,
so the plan told an analyst to patch Apache twice. Across two tools it was worse — 3 of 138
product keys matched over nine hosts, a number that reads as two scanners agreeing about
almost nothing.

NVD publishes the products each CVE affects, and both scanners cite CVE identifiers, so that
list is a key neither vendor wrote. `fetch_labels.py` now captures it; 1,058 of 1,165 corpus
CVEs name at least one product, and the remaining 107 fall back to the title.

## Three rules, each added after looking at what the previous version produced

**Applications outrank operating systems.** NVD lists the platform beside the application. The
first version counted both equally and produced a remediation group called
`debian:debian_linux` on port 80 holding 26 Apache findings. Nobody can do that job.

**A product the title names beats one it does not.** NetApp ships MySQL inside several
products, so every MySQL CVE lists each of them; counting alone gave
`netapp:active_iq_unified_manager` eleven findings on the MySQL host. NVD is authoritative
about which products a CVE touches and silent about which one the scanner looked at; the title
says exactly that and is unreliable alone. Used together each supplies what the other lacks.

**An operating system key must be confirmed by the title.** `CVE-1999-0524`, the ICMP timestamp
disclosure, lists fourteen platforms, and the check reporting it is called "ICMP Timestamp
Reply Information Disclosure" — which names no platform. Falling back to the most-cited entry
filed six Linux hosts under `apple:mac_os_x`.

A CVE naming more than twenty products is also ignored as generic, the mirror of the rule
already applied to a finding citing too many CVEs. 47 CVEs in the cache exceed it.

## What the key does to the grouping

```
groups by title    55
groups by product  35        11 keyed on NVD, 24 on the title with no usable CVE
```

## And what it does to the headline agreement number

```
by CVE                        7.5%
by product, parsed titles     2.2%
by product, NVD, first pass  18.4%   <- wrong
by product, NVD, corrected    4.3%
```

**The 18.4% was the spurious `apple:mac_os_x` group appearing on six of nine Linux hosts.** Six
of the fourteen "agreed" products were that one entry. With the OS-confirmation rule the answer
is 4.3%: `apache:couchdb` on .103, `php` on .110, `f5:nginx` on .114, and a fourth entry that is
`php` counted twice because some PHP findings cite no CVE and keep the title key.

**The claim survived the attempt to discredit it.** We suspected 2.2% was an artefact of our own
regex, built a key that does not use the regex, and the answer came back at 4.3%. The
disagreement between the two scanners is real.

## What is still not connected

`prioritise.py` still groups on parsed titles and has only ever been run on one scanner's
output. **Every prioritisation number recorded in this file is from OpenVAS alone**, and the
duplicate rows in the generated plan are still there. Wiring the correlation key into
`build_actions`, and running the pipeline over both scanners' findings for the same hosts, is
the next change.

## Figures are now generated, not transcribed

`make_figures.py` calls `prioritise.score()` and `prioritise.orderings()` — the same functions
the printed tables come from — and writes nine figures as vector PDF plus the tables as LaTeX,
Markdown and text. A figure built by copying numbers out of a terminal is correct exactly once.

Two faults surfaced while drawing them. Legends placed inside a 3.4-inch panel sat on top of
the curves and ran past the figure edge; they are below the axes now. And the cross-tool figure
counted raw rows where `tool_agreement.py` deduplicates on `(host, check name)`, putting 18
findings on .103 against the table's 10 — two numbers for one quantity, in a paper that would
have carried both.

---

# 30 September 2026, evening: testing the transfer the surrogate depends on

The likelihood surrogate exists for findings that carry no CVE, and every number reported for
it until now was measured on findings that carry one. The gap was recorded as a limitation
with no way to close it, because no published probability exists for the other side.

## The test first proposed measures nothing

Hide a finding's CVE, score it through the surrogate, compare against the EPSS we hid. The
feature vector is text, family, solution type, threat, severity, QoD and port: **not one input
is derived from a CVE**. Hiding the identifier changes nothing, and the surrogate has always
been blind to it. Leakage was never the risk, so ablation cannot be the test.

## What the risk actually is, measured

Covariate shift. The two populations differ, and the difference is specific:

```
                     with EPSS    without
findings                   363         48
nvt_family, unseen           -         6%
solution_type, unseen        -         0%
threat, unseen               -         0%
severity, median           7.3        6.1
qod, median               30.0       15.0
```

Findings without a CVE are the ones the scanner is least sure of. They share almost all of
their families and every solution type and threat level, so the shift is real but narrow.

## Simulating the shift instead of assuming it

A classifier is fitted to separate the two populations using the same features the surrogate
uses and no target. The CVE-bearing findings it judges most CVE-*less* are held out; the
surrogate trains on the remainder and is scored against published EPSS on that deliberately
unrepresentative quarter.

```
evaluation                          Spearman      n
CVE-grouped split, the headline        0.609     363
shifted hold-out, most CVE-like        0.626      91
random hold-out, same size             0.728      91
leave-one-family-out                   0.482     363   (8 families)
train high QoD, test low QoD           0.701      44
```

**Transfer holds.** On the findings that look least like its training data the surrogate
reaches 0.626, against a severity baseline of 0.492 and a registered threshold of 0.30.

**The shift has a price, and the random hold-out is what proves it is the shift.** A random
quarter of the same size scores 0.728; the shifted quarter scores 0.626. The 0.10 difference
is the cost of the covariate shift rather than of a smaller test set, which is exactly what
that control exists to separate.

**QoD is not the problem.** Training on high-QoD findings and testing on low-QoD ones gives
0.701, above the headline. The halved QoD of the unscored population is not what hurts.

**An unseen family is.** Leave-one-family-out gives 0.482, which is the severity baseline to
within noise: faced with a check family it has never seen, the surrogate is worth nothing over
sorting by severity. On this corpus only 6% of the unscored findings sit in an unseen family,
so the exposure is small — but eight families is a thin basis, and expanding the lab will add
more. This has to be re-measured on the larger corpus, and it is the one number that could
undermine the coverage claim.

## What can now be written, and what still cannot

Can: *under a simulated covariate shift matching the unscored population, the surrogate
reaches Spearman 0.626, above the severity baseline of 0.492.*

Cannot: *the estimate is correct for findings with no CVE.* Nothing available shows that, and
the script prints the disclaimer under its own results so a future reading cannot mistake one
for the other.

## A corpus difference to settle before writing

This run used all four processed files, 411 findings, and the headline CVE-grouped split came
out at 0.609. The 0.624 recorded earlier is `findings_openvas_b2.csv` alone. Both are correct
for their corpus and the paper must pick one; the four-file corpus is the better choice, being
the larger and the one the cross-tool results already use.

## One number, three values, and the guard that stops it happening again

The transfer run above and the figure generator both compute a CVE-grouped split, and they
disagreed: 0.552 in the surrogate table, 0.609 in the transfer table, sitting adjacent in the
same generated document under near-identical headings. A third value, 0.624, is recorded
earlier in this file.

None is wrong. They are three corpora. `make_figures.py` evaluated the surrogate over whatever
was passed as `--findings`, which is the three-host subset the attack graph is built for;
`transfer.py` read the whole nine-host corpus; and the 0.624 came from `likelihood.py` reading
its own default set.

**The corpus is now fixed for both.** The prioritisation figures stay lab-specific, because
there is one graph and one goal, but every likelihood number comes from `--corpus`. Over the
nine-host corpus the CVE-grouped split is **0.609**, and that is the figure to use.

`make_figures.py` now compares its own surrogate result against the one in `transfer.json` and
prints a warning naming both if they differ by more than 0.005. This is the same fault as the
per-host counts that read 18 in a figure and 10 in a table earlier the same day; the
difference is that this one cannot recur silently.

---

# 30 September 2026, late: learning to rank, and the classification stage rebuilt

Two questions were open. Whether a ranking objective would beat the pointwise regressor, which
the paper's index terms had been promising since D2 without any code behind them. And whether
machine learning earns its place here at all, given that it served 35 of 410 findings and the
pipeline is otherwise lookups, a graph and a knapsack.

## XGBoost, installed without a package manager

No pip on this machine and no sudo. A PyPI wheel is a zip file, so xgboost 3.4.1 was
downloaded and unpacked into `~/.local/lib/python3.12/site-packages`. Recorded in
`lab_setting.md`: `rank_objective.py` will not run elsewhere without it.

Reading its documentation settled a question the code had never asked. **Learning to rank
assumes documents belong to queries and are ordered within one, and nothing in this pipeline
had a query.** Findings were ranked in a single global heap. The host is the natural query --
an analyst asks what to fix on a machine, and the plan is worked a machine at a time -- and
choosing it is itself a finding about the evaluation.

## The objective does not help, and the metric decides who wins

Four models, same features, same folds, `rank:ndcg` with the host as `qid`:

```
model                     Spearman   NDCG@5   NDCG@10
pointwise, boosted tree     0.609     0.616    0.680
pointwise, linear           0.453     0.522    0.574
pairwise, linear            0.432     0.523    0.586
LambdaMART, rank:ndcg       0.493     0.648    0.699
severity alone              0.446     0.695    0.710
random ordering               --      ~0.42      --
```

LambdaMART behaves exactly as designed: **+0.032 on the metric it optimises, −0.116 on the one
it does not.** Neither ranker beats the pointwise tree overall, so learning to rank stays out
of the pipeline and enters the paper as one row and a paragraph.

**The uncomfortable line is the last model.** On NDCG@5 within a host -- the metric that
matches how the plan is consumed -- the scanner's own severity beats everything we built. A
random ordering scores about 0.42 and no host is degenerate, so the metric discriminates and
the result is real.

This contradicts nothing already claimed. The 57%-against-1% comparison is over actions across
the whole plan; this is findings within one host. Different unit, different scope. But it does
close off any claim that our likelihood orders better than severity, and the four claims chosen
for the paper never depended on one.

**A hypothesis about why, tested and wrong.** Severity is a comparative signal by nature while
the model's predictions cluster, so within-host comparative features -- severity rank on the
host, gap from the host mean, the product's share of the host's findings -- should have helped.
They made everything worse: NDCG@5 for the boosted tree fell from 0.616 to 0.534. The likely
reason is that the target is global and those features are local, and a rank of 0.9 on one host
does not mean what it means on another. They were removed.

## The classification stage, on a target that works

Two earlier targets failed, and the reasons designed the third. CWE: 129 classes over 410
findings, 39 singletons. `(range, consequence)` as MulVAL categories: **we defined that answer
set ourselves and left out the case where a finding grants nothing**, so the classifier
answered `privEscalation` 28 times in 29.

NVD's CVSS impact metrics avoid both. They are NIST's rather than ours, and `NONE` is a
populated, legitimate answer, so "this grants nothing" becomes something the model may say.
Registered before the run: macro-F1 must beat the majority-class answer by 0.05.

```
                  macro-F1   majority   accuracy   majority
confidentiality      0.427     0.153      0.595      0.443
integrity            0.399     0.163      0.595      0.485
availability         0.450     0.162      0.701      0.480
```

**All three pass, at 2.6 to 2.8 times the baseline on macro-F1.** The attack vector is
deliberately not predicted: 85% of this corpus is `NETWORK`, so a model that always says
NETWORK scores 85% and has learned nothing.

Both terms of `R = L x C` now have a learned fallback, each trained on a label published by
someone else. What that changes on this corpus is small -- the assumed values it replaces were
measured to affect 0 of 9 derived facts -- and the honest claim is about the design rather than
the numbers.

**A defect found in our own labels.** `PARTIAL` appears with three examples and F1 0.00. It is
CVSS v2 vocabulary sitting in a v3 label space, because `cvss_of` falls back to v2 when no v3
vector exists. Mixing two vocabularies in one target penalises the model and the baseline
alike, and it has to be fixed before these numbers are reported.

## The models cross from one scanner to the other

Everything above is learned from OpenVAS: its titles, families, `solution_type`, QoD. The plan
covers both scanners, so a model that works on only one leaves a hole where the coverage claim
is strongest. Trained on OpenVAS, tested on Nessus findings, both graded against NVD:

```
field             within OV  to Nessus  shared only  majority
confidentiality       0.429      0.460        0.460     0.141
integrity             0.476      0.545        0.545     0.222
availability          0.463      0.554        0.542     0.206
```

**It carries across**, under conditions harsher than expected: 70% of the Nessus findings are
in families the OpenVAS side never shows, and `solution_type` and QoD are empty on all 56 of
them. The signal is in the text, not in the OpenVAS-only fields -- the third column, which
removes those fields from training as well, matches the second almost exactly.

The direction of the difference is not claimed. n = 56, and the two columns are different test
sets; the defensible statement is that transfer holds and nothing is lost.

## A graph a person can read

MulVAL's output is 387 vertices and 736 arcs, which is why attack-graph papers so often show a
toy example instead of the graph they analysed. The structure is 190 input facts, 188 rule
applications and **nine conclusions**, and only the nine carry meaning. Condensing
`OR -> AND -> OR` into a direct edge gives a nine-node chain, laid out by distance from the
goal, with the count of input facts feeding each step:

```
netAccess(vmWeb,tcp,80)        2 input facts
execCode(vmWeb,'www-data')   240
netAccess(vmApp,tcp,80)        2
execCode(vmApp,'www-data')    46
netAccess(vmDb,tcp,3306)       2
execCode(vmDb,mysql)          58   <- the goal
```

Six steps across three tiers, derived rather than drawn, and the evidence is not spread evenly:
240 findings support code execution on the web host and three support the escalation to root.

## What is now next

The training set is 375 findings from eleven hosts running about nine products, so its
effective size is closer to the number of products than to the number of rows -- which is what
leave-one-family-out at 0.482 has been saying. **The OpenVAS NVT feed holds 80,555 checks that
carry both a description and a CVE**, and the text of a check exists whether or not it ever
matched a host. Since the models cross scanners, a model trained on that feed would serve both.
Writing a NASL parser is the next piece of work.

## The design decision this settles

Everything the models learn is a mapping from a scanner's wording to a value some catalogue
publishes. Two places that mapping could be learned from, and only one of them survives
contact with how the model is used.

**Not from NVD's own text.** NVD carries a description for every CVE and there are hundreds of
thousands of them, so training on that pairing is tempting. It is also useless here: at
inference the findings that need an estimate are precisely the ones with no CVE, so there is
no NVD description to feed the model. It would be trained on text written by CNAs and used on
text written by a scanner vendor.

**From the scanner's own corpus of checks.** A check carries its description and its CVE
references whether or not it ever matched a host, so the OpenVAS feed alone holds 80,555
labelled examples against the 375 the scans produced. The input distribution is then the one
the model actually meets.

NVD stays exactly where it already is -- supplying the label, never the input.

**This makes the method scanner-agnostic by construction rather than by luck.** The pipeline
learns the vocabulary of whichever scanner it is given, from that scanner's own check corpus,
and the claim in the paper becomes a statement about the procedure instead of about OpenVAS.
The cross-scanner measurement above supports it from the other side: a model trained on one
tool's wording already works on another's, so an operator who cannot read their scanner's
plugin source -- Nessus Essentials does not expose it -- can use a model trained on one that
is open. That limitation has to be stated: "retrain on your own scanner's corpus" is easy for
OpenVAS and impossible for a closed feed.

---

# 30 September 2026, night: training from the scanner's feed instead of from our own scans

The impact classifier learned from 375 findings drawn from eleven hosts running about nine
products, and its weakness was measured rather than suspected: against a check family it had
never seen it scored 0.482, which is the severity baseline. The obvious answer is more data,
and the obvious source is wrong.

## Not NVD's own text, and the reason is the inference condition

NVD publishes a description for every CVE and there are hundreds of thousands of them. At
inference the findings needing an estimate are exactly the ones with **no CVE**, so no NVD
description exists to feed the model; it would be trained on prose written by CNAs and used on
prose written by a scanner vendor. NVD stays where it already was, supplying the label.

## The scanner's own plugin corpus

A check carries its title, its description and its CVE references whether or not it ever
matched a host. Parsing the OpenVAS feed gives 80,555 checks across **47 families** against the
8 the scans show, in the same schema `parse_openvas.py` writes, so every downstream script
reads them unchanged.

Two caches were built to label them. `fetch_nvd_bulk.py` pulls NVD's yearly feeds -- the 1.1
feeds now answer 403, so the 2.0 layout is the only one -- giving 298,973 CVEs with a published
vector in about fifteen minutes, against the ten hours the per-CVE API would need.
`slim_labels.py` then reduces that to the four fields a classifier reads, 259 MB to 32 MB,
because loading the full file as a dictionary exhausted this machine's memory and killed two
runs before any model was fitted.

**A bug the reduction exposed.** `cvss_of` preferred CVSS 4.0 and then looked for 3.x field
names, so 38,732 CVEs silently lost their impact metrics. It never raised an error; it appeared
as a "no impact metrics" count in the slimming step. Fixed by preferring 3.1 -- the largest
group, and the vocabulary the corpus cache already speaks -- and reading 4.0's own field names
where it is the only vector present.

## The comparison, with the leakage filter that matters

The test set is always our own findings, because those are what the pipeline scores. Feed rows
whose OID or name matches a finding in the test set are removed first: training on the check
that produced a finding and testing on that finding is memorisation with extra steps.

```
scan findings with a v3+ vector : 366
feed checks, sampled            : 10,719
  removed as seen in the scans  : 55
  left for training             : 10,664
  families, scans 9 against feed 34

field             scan only  feed only     both  majority
confidentiality       0.553      0.638    0.921     0.178
integrity             0.539      0.576    0.948     0.146
availability          0.499      0.640    0.971     0.220
```

**The feed trains a better model than our own scans do, on every field**, and the gap is not
marginal on two of the three. `both` is fitted on data that includes the test rows and is an
upper bound rather than a score; it is printed because the distance between it and `feed only`
says how much the scan rows carry that the feed does not.

This was not the expected result. 57% of the feed is distribution security advisories -- Fedora,
Debian, SuSE package updates -- which are a different kind of check from the remote service
tests that fire against these hosts, and a corpus can be two hundred times larger and still be
about something else. It is about the right thing.

**The sample was 20,000 rows, not the full 80,555.** The preprocessing forces a dense matrix,
`HistGradientBoostingClassifier` cannot take a sparse one, and 80,555 by 3,000 in float64 does
not fit beside everything else in 4 GB. The full-corpus run needs either more memory or a
learner that accepts sparse input.

## Separating the library from the objective

An earlier reading of the ranking table treated a gap as "sklearn beats xgboost". It conflated
two variables, since a scikit-learn *regressor* was being compared with an xgboost *ranker*.
Adding `XGBRegressor` on the same target, folds and features separates them:

```
model                     Spearman   NDCG@5   NDCG@10
pointwise, sklearn HistGB   0.609     0.616    0.680
pointwise, XGBRegressor     0.545     0.598    0.671
LambdaMART, rank:ndcg       0.493     0.648    0.699
severity alone              0.446     0.695    0.710

library alone     spearman -0.064   ndcg@5 -0.017
objective alone   spearman -0.116   ndcg@5 +0.032
```

scikit-learn does win on both metrics with the objective held constant, so the earlier
conclusion stands -- **at about half the size it was stated at**. The objective is the larger
variable, and hyperparameters are not exactly equivalent across the two libraries, so the
library figure is an observation rather than a benchmark.

The within-host comparative features were still switched on in the first version of this run,
which is why its `boosted tree` row read 0.603 and 0.534 instead of 0.609 and 0.616. They
default off now; the flag survives so the negative result can be reproduced.

## What this changes

`impact.py` should train on the feed and keep the scans for evaluation. The same test has not
been run for `likelihood.py`, whose leave-one-family-out figure of 0.482 is the same complaint
in the same words, and there is now a method that answers it.

## The same experiment for the likelihood surrogate, and a filter that flattered it

The impact classifier trained better on the feed than on our scans, so the surrogate with the
identical complaint -- leave-one-family-out at the severity baseline -- got the identical test.
It was run twice, and the first run was wrong in a way worth recording.

**First run, and why its result was an artefact.** `epss_lookup.csv` holds 1,135 CVEs: exactly
those our findings cite. That is the right file for scoring a scan and the wrong one for
training on a check corpus, because a feed check citing any other CVE supplies no row. Of
20,000 sampled checks only 503 had a target, and the surrogate trained on 447 of them scored
**0.642 against the scan corpus's 0.609**.

That looked like the impact result repeating. It was not. The 447 rows were not a sample of
the feed; they were the checks whose CVEs happened to be in our own corpus, so training on them
was training on corpus-adjacent data. The filter selected the answer.

**Second run, on the full snapshot.** The same pinned file, `epss_scores-2026-09-08.csv.gz`,
read whole rather than filtered: 369,023 scores instead of 1,135, and 19,909 feed checks
trainable across 44 families instead of 447 across 19.

```
training set                        Spearman
scan only, CVE-grouped split          0.567
scan only, leave-one-family-out       0.406
feed only, tested on the scans        0.535
severity alone                        0.439
```

**Forty times the training data scores lower than the accidental subset did**, which is the
clearest possible demonstration that the first number came from the filter. With the whole feed
in play the distribution advisories and unrelated software arrive too, and relevance falls
faster than volume rises.

The scan-only rows moved as well, from 0.609 to 0.567, because the evaluation set grew from
363 findings to 375 once every scan finding could find a target. **Numbers are comparable
within a run and not across these two**, which is worth stating before anyone lines the two
tables up side by side.

**What the second run actually says**, read only against itself:

- the feed does **not** train a better surrogate on the in-corpus split, 0.535 against 0.567
- it does beat leave-one-family-out, 0.535 against 0.406, which is the condition the
  experiment was run to address
- it beats severity, 0.535 against 0.439

So training on the feed buys robustness to unseen software rather than accuracy on familiar
software. That is a different claim from the impact result, and the two should be reported
separately rather than summarised as "feed training is better".

The impact experiment is not exposed to the same fault: `nvd_impact.json` is built from NVD's
own yearly feeds and covers 260,026 CVEs regardless of what our scans cite, so its training
rows were never selected by proximity to the corpus.

---

# 1 October 2026: correlation wired into the plan, and the two changes separated

`correlate.py` had produced NVD-keyed groups since 30 September and nothing consumed them:
`prioritise.py` still grouped on a product parsed from the check title and had only ever been
run over one scanner's output. Every prioritisation number recorded before this entry is from
OpenVAS alone, grouped on prose.

## A stale line, and the fourth instance of one fault

The first merged run printed `untiered actions: 3 of 29` and, four lines later, `actions: 50`.
One quantity, two values. `score()` returned NVD-grouped actions and a leftover
`actions = build_actions(kept)` below it rebuilt them from titles, so every table in that run
used the old grouping while the diagnostic used the new one.

This is the fourth time today that one number has been computed in two places: findings per
host read 18 in a figure and 10 in a table, the CVE-grouped split had three values from three
corpora, and the surrogate appeared twice in one generated document at 0.552 and 0.609.
**Three of the four were caught only because two values happened to be printed close enough
together to be seen side by side**, and this one would have been invisible without the
`untiered` line added minutes earlier for an unrelated reason.

## Separating the grouping change from the second scanner

The obvious comparison changes two things at once. A third run holds the scanner fixed:

```
                         findings  actions  per action  cost  KEV
A  OpenVAS, title keys      229       47       4.87      68    7
B  OpenVAS, NVD keys        229       26       8.81      38    7
C  both, NVD keys           239       29       8.24      44    8
```

**A to B is the grouping alone: 21 of 47 jobs disappear with the finding count unchanged.**
Those were never separate jobs -- `php` beside `php 5.x`, an Apache upgrade beside the same
upgrade named after one of its CVEs -- and the plan had been telling an analyst to do each
twice. Total cost falls from 68 units to 38 because 21 of them did not exist.

**B to C is the second scanner alone: 10 Nessus findings, 3 new jobs, 1 more known-exploited
finding.** Seven of the ten fell into work OpenVAS had already found.

## A claim that needed its scope narrowing

Before this ran, the expectation recorded here was that merging would add a great deal, since
product-level agreement between the two tools is 4.3%. It added 12%, three jobs in twenty-six.

Both numbers are right and they answer different questions. The 4.3% is measured over nine
hosts at the level of distinct products; the three jobs are what a second scanner adds to a
three-host lab where it found ten findings in total. **The coverage claim has to say which it
means**, and the paper should not let a reader carry the 4.3% into an expectation about how
much larger a merged plan gets.

## Something to fix before these tables are read together

Budget columns are a percentage of the cost of doing everything, and that total moved from 68
units to 38 when the grouping changed. `5%` in one table is 3.4 units and in another 2.2, so
the columns line up on the page and do not mean the same thing. The tables need the absolute
budget beside the percentage before any two of them are printed side by side.

---

# 1 October 2026: group C, and the objection it exists to answer

Every target in this project was chosen to be vulnerable. Group A is vulhub, whose images ship
broken on purpose; group B is official images old enough to have accumulated CVEs. The first
question any reader asks is whether a pipeline that ranks work on such a corpus would say
anything sensible about a machine nobody had sabotaged.

Group C is the same five products as group B at their current versions -- `nginx:1.27`,
`tomcat:11`, `mysql:8.4`, `httpd:2.4`, `wordpress:latest` -- so image age is the only variable
between the two. Same network, same scanners, same configuration, same plugin set.

```
group                        hosts  OpenVAS  Nessus  total  per host  KEV
A  vulhub, deliberately broken   4      105      35    140      35.0    8
B  official images, old          5      246      33    279      55.8   11
C  official images, current      5       13      13     26       5.2    0
```

**Eleven times fewer findings per host than group B, and no known-exploited vulnerability at
all.** The pipeline is not shouting at everything it is pointed at.

## What the thirteen actually are

Ten of OpenVAS's thirteen are TCP and ICMP timestamp disclosures appearing identically on all
five hosts: properties of the network stack rather than of any software we chose. Three are
real, and the largest is worth the paper's attention:

```
172.18.0.120   Critical  10.0   Nginx End of Life (EOL) Detection
172.18.0.123   Medium     5.8   HTTP Debugging Methods (TRACE/TRACK) Enabled
172.18.0.120   Low        3.7   Nginx 0.7.22 - 1.29.0 Information Disclosure
```

**`nginx:1.27`, chosen as the current release, is already end of life.** It scores 10.0 with no
CVE attached, which is exactly the case the end-of-life measurement was built for: a component
can be unsupportable without any catalogue entry saying so, and a CVE-keyed prioritiser has
nothing to say about it.

## Agreement rises when the hosts are clean, and the tools still differ

Nessus returned thirteen findings too, against OpenVAS's thirteen -- where on group B it
returned 33 against 246. With less to find, the two converge, which makes sense: what remains
is stack-level behaviour both tools test for.

They still do not see the same things.

```
OpenVAS only   Nginx End of Life                    10.0
Nessus only    IP Forwarding Enabled                 6.5   on all five hosts
Nessus only    Apache Tomcat Default Files           5.3
Nessus only    nginx SSL upstream (a different CVE)  5.9
```

**The coverage claim survives on clean hosts.** Even at thirteen findings a single tool misses
work the other reports, and the largest finding on either side is visible to only one of them.

`IP Forwarding Enabled` on every host is a property of containers sharing the host kernel
rather than of the images, and it is worth watching where it lands in the attack graph: a host
that forwards traffic is a structural fact about reachability, not a software flaw.

## Recording the settings, since two of them have broken a comparison before

```
OpenVAS   23.50.0, Full and fast, port list `TCP 1-65535 (match Nessus)`, alive test
          `Consider Alive`, export filter `apply_overrides=0 min_qod=0 first=1
          sort-reverse=severity rows=1000`
Nessus    10.12.3, Basic Network Scan, plugin set 202609290639
```

The port list and the alive test are the two that have invalidated a comparison in this project
before, and the export filter is the third: GVM's default `min_qod=70` drops most of the
corpus, since almost every finding here sits at 30. Everything is exported and filtered during
analysis instead.

The Nessus plugin set matches groups A and B. The console has been offering an upgrade since
yesterday and it stays unapplied until this round is closed, because a different plugin set
between groups would confound image age with check coverage -- the one variable group C exists
to isolate.

---

# Dropped from the paper, kept here (30 September 2026)

The rule for what goes in the paper: an approach appears only if it beats the baseline
that would replace it. The three below do not, so they are cut from the paper and recorded
here instead, each with how it was measured, what judged it, and what it lost to, so that a
later attempt knows the road has been walked and where it ended. Cutting them from the paper
does not lose the finding; it moves it to the notebook where a failed approach belongs.

## Ranking findings within a single host

- **What.** Order the findings on one host by the model's risk, rather than only ordering the
  remediation actions.
- **How measured.** NDCG@5 with the host as the query group, out of fold.
- **Judge.** NDCG@5 against the finding's published EPSS as the relevance grade, and global
  Spearman as the cross-host control.
- **Baseline.** The scanner's own severity ordering.
- **Result.** Severity reaches NDCG@5 0.70 within a host against the model's 0.62. The model
  wins the global ordering, 0.61 to severity's 0.45, so the two metrics disagree about which is
  better.
- **Verdict.** The baseline wins the within-host question, so no within-host ranking claim is
  made. The plan is consumed a host at a time, which is why this was worth testing; the answer
  is that severity is enough at that scale and the model earns its keep only across hosts.

## Learning to rank (LambdaMART)

- **What.** Replace the greedy risk ordering with a learned ranker, on the likelihood axis where
  the label is continuous and plentiful.
- **How measured.** GroupKFold by host, NDCG@5 within a host and global rank correlation.
- **Judge.** The same two metrics as above.
- **Baseline.** The non-learned ordering it was meant to improve.
- **Result.** NDCG@5 within a host improves by 0.03; global rank correlation degrades by 0.12.
  The behaviour of a model optimising one metric and being graded on another.
- **Verdict.** Not adopted. A ranking objective matched to how a plan is consumed -- a host at a
  time, under a budget -- is the open question; the obvious LambdaMART formulation is not it.
  Needs a purpose-built objective, not an off-the-shelf ranker, if revisited.

## The impact classifier's downstream effect

- **What.** Not a failed experiment -- the classifier beats its baseline (2.4 to 2.8x the
  majority class on macro-F1) and stays in the paper as Experiment 2. Recorded here is only the
  caveat that was cut from the paper's limitations.
- **Result.** On this corpus, removing the classifier changes no conclusion the graph reaches.
  It reduces the findings whose impact is an assumed constant from 12 to 2, and every estimate
  that reached the graph agreed with the constant it replaced.
- **Verdict.** Keep it -- it buys that fewer values are taken on trust -- but on a corpus this
  small its downstream effect is invisible. Worth re-measuring on the expanded lab, where the
  uncatalogued findings it serves are more numerous.

## Cut-set test: does a plan disconnect the goal (dropped 30 September 2026)

- **What.** After a plan is applied, is the attacker still able to reach the goal? Remove the
  vulExists facts the plan remediates, re-run MulVAL, and check whether the goal is still derived.
  Swept the budget in 2 per cent steps, 4 to 60 per cent.
- **How measured.** `graph_cut.py`. Monotonic for all six orderings, none reconnecting a goal
  once cut.
- **Judge.** The engine's own re-derivation on the surviving facts. No score involved.
- **Baseline.** The same orderings the budget experiment uses.
- **Result.** Cheapest budget that disconnects `execCode(vmDb,_)`:
  grouped severity 18%, most-findings 18%, severity list 20%, **ThreatRank 26%**, published
  exploit prediction 34%, risk-sorted list 40%.
- **Verdict.** ThreatRank is fourth of six. Disconnecting a tier needs every finding behind both
  its conclusions closed (25 at the app tier, 111 at the web tier), so an ordering that
  concentrates on large jobs covers a tier sooner than one spreading across the highest-risk
  jobs. Removing exposure and severing a path are different objectives; our score optimises the
  first. It beats published exploit prediction (26 vs 34) but loses to the naive baselines.
- **Kept for.** The one idea worth carrying forward: a cut-set-aware selector that picks for
  complete coverage of a conclusion rather than for summed risk. The test also showed the graph
  can contradict our own ordering on a question no selector can see, i.e. it is an independent
  referee -- worth remembering if the graph's validity is ever challenged. Dropped from the paper
  because, as a result, it is a loss with no baseline win.

---

# Exploitable chain for walking the graph (1 October 2026)

To close the one open row of the graph validation -- whether a derived chain is actually
walkable to code execution -- a dedicated three-tier chain of vulhub services is declared,
without disturbing the group-A/B/C corpus the main graph is built on. Additive, not a
replacement.

```
vmWeb  172.18.0.102  Struts2 2.3.30 showcase, 8080   CVE-2017-5638 (S2-045)
vmApp  172.18.0.103  CouchDB 2.1.0, 5984             CVE-2017-12635 / -12636
vmDb   172.18.0.104  Redis 4.0.14, 6379, no auth     goal: execCode(vmDb,_)
```

Checked against the running containers on this date (scan-time state, recorded before any
exploitation):
- **Reachability**: a socket opened along each declared edge connects -- internet->vmWeb:8080,
  vmWeb->vmApp:5984, vmApp->vmDb:6379.
- **Service accounts** (`/proc/*/status`): the Struts2 JVM and the CouchDB beam.smp run as uid 0
  (root); redis-server as uid 999 (redis). The topology declares these.
- All three services answer (HTTP 200, the CouchDB welcome banner, a redis PONG).

Topology in `topology_lab4.json`. Software names there are provisional until .102-.104 are
rescanned, because MulVAL matches vulExists to networkServiceInfo on the software string.

**Next, in order:** (1) rescan .102-.104 with OpenVAS and Nessus into `processed/findings_*_d.csv`;
(2) reconcile the topology software names with what the scanners report; (3) build the graph and
confirm it derives execCode(vmDb,_); (4) walk each hop against the live service following vulhub's
published proof of concept, recording whether code execution is obtained, and grade the graph's
exploitability row against that.

## Exploitable chain: OpenVAS scan and graph (1 October 2026)

OpenVAS scanned .102-.104 into `2026-10-01_openvas_chain_d.xml`, parsed to
`processed/findings_openvas_d.csv`: 105 findings, 35 per host, 58 with a CVE, 2 touching KEV.

\textbf{The scanner did not detect Struts2 S2-045 (CVE-2017-5638).} On .102 it reported the Jetty
server that hosts the Struts2 showcase and its CVEs, not the Struts2 application vulnerability that
is actually the entry exploit. The app and database tiers fared better: CouchDB CVE-2017-12635 and
-12636 were both detected on .103, and several Redis RCE CVEs on .104. This is itself a result:
version-based detection of the server missed the application-layer exploit on the web tier.

The graph built from this scan (`mulval/cases/lab4`) nonetheless derives the full chain and reaches
the goal: execCode(vmWeb,root) -> netAccess(vmApp) -> execCode(vmApp,root) -> netAccess(vmDb) ->
execCode(vmDb,redis) and execCode(vmDb,root). The web-tier conclusion rests on the Jetty/tomcat
findings rather than on Struts2, so the graph predicts execCode(vmWeb) is reachable by a different
vulnerability than the one that will actually be walked.

**The graph's prediction, to be validated by walking it:** the attacker reaches code execution on
the database host through the three tiers. Scan state recorded before any exploitation; the walk
comes next.

## Multi-scanner on the chain: the two scanners are complementary (1 October 2026)

Nessus fetched via the API (scan 25, 51 findings) into `processed/findings_nessus_d.csv`.
\textbf{Nessus detected Struts2 S2-045 (CVE-2017-5638) on .102, which OpenVAS missed}, while
OpenVAS detected CouchDB CVE-2017-12635/-12636 on .103, which Nessus missed. Neither scanner alone
carries the whole chain's entry; together they do.

The graph rebuilt from both scanners (mulval/cases/lab4) reaches the goal and now contains
CVE-2017-5638 as a web-tier vulExists -- the vulnerability that is actually the entry exploit. So
the merged graph's prediction rests on the real exploit, not only on the Jetty server behind it.
This is a concrete instance of the multi-scanner coverage argument: a plan built from either tool
alone would miss a different hop's entry.

## Chain walk result (1 October 2026)

Walked the lab4 chain against the live services, each by vulhub's published PoC with a
non-destructive check (recorded in figures/chain_walk.json):

```
hop 1  vmWeb  Struts2 S2-045    WALKED   OGNL eval (233*233 header), JVM as root
hop 2  vmApp  CouchDB 12635+12636  WALKED  (after creating system dbs) unauth admin takeover -> query_servers RCE -> uid=0(root)
hop 3  vmDb   Redis unauth      WALKED   CONFIG/INFO + marker write/read/delete = full control
```

Two of three predicted hops execute code. The declared chain breaks at the application tier, where
CouchDB is flagged vulnerable by version but not exploitable as deployed -- the validation
discriminating, the opposite case to Struts2 (missed by OpenVAS, walks). The goal is reached anyway
by a shorter path: the bridge is flat (vmWeb reaches vmDb:6379 directly) and Redis needs no auth, so
a web foothold reaches the database in one more hop than the chain models. Same direction as the
lab3 finding that the declared topology restricts the real network.

Paper updated: the exploitability row of tab:truth, the attack-graph Result, and the limitation.


## Chain walk: 3/3 after completing CouchDB's standard setup (1 October 2026)

Hop 2 walked once CouchDB's system databases (_users, _replicator, _global_changes) were created,
which the vulhub env intends (its initd container had not run, so _users was absent and the
exploit returned 404 -- a deployment state a version-based scanner cannot see). With that in place:
CVE-2017-12635 created an admin with no credentials (duplicate-roles PUT, HTTP 201), and
CVE-2017-12636 ran `id` as that admin via query_servers on node nonode@nohost, returning
uid=0(root). All attack artifacts (the admin user, the test db, the query_servers config, the
output file) were removed afterwards.

Final: all three predicted hops execute code as root; the chain internet->web->app->db is
confirmed end to end. The goal is also reachable by a shorter path on the flat bridge. The paper's
exploitability row, the attack-graph Result, and the limitation are updated to 3/3.

## Full-paper audit (1 October 2026)

Checked every reported number against the data and the LaTeX structure. Two errors fixed:
tab:corpus group A (105/35.0/8 -> 97/33.0/7, so the groups sum to 437 and KEV to 18), and the
likelihood surrogate's severity baseline (0.45 -> 0.44 in the abstract and the coverage result, to
match tab:models, the figure, and the recorded 0.439).

**One decision left for review, not resolved here.** The method (Section III, Algorithm 1)
describes correlation keying on the NVD affected product, but every evaluation count -- 47 actions
and 68 units on the graph corpus, 138 jobs on the two-scanner corpus, the goal-sensitivity shares --
is produced with the parsed-title grouping (prioritise.py / make_figures default, nvd=None).
Grouping by NVD product instead gives 26 actions and 92 jobs. The gap matters most for the
two-scanner "138 jobs", where cross-scanner merging is the claimed benefit. Resolve by either
re-running the evaluation with --correlate and updating the numbers, or stating in the paper that
the reported numbers use the title grouping with NVD-product correlation as the described
capability. Left for P'Ohm.

Everything else verified consistent (graph 357/175/173/9, models, budget table cells, agreement
4.4%/6-of-9, classifier 217/10/2, remoteClient 15, goal sensitivity 25/34/43, walk 3/3). No
duplicate labels, orphan refs or citations; all figure files present. Not compiled -- no LaTeX on
this VM.

## Nuclei as an active validator, and what it actually caught (3 October 2026)

Exploring a third tool after P'Ohm asked for a scanner beyond OpenVAS and Nessus. Nuclei v3.11.1
(templates pulled fresh), run against the chain targets as a default template scan:

```
http://172.18.0.102:8080   (Struts2 showcase)
http://172.18.0.103:5984   (CouchDB)
172.18.0.104:6379          (Redis)
```

**What it caught, exactly** (scratch `nuclei_chain.jsonl`):

| Target | Nuclei finding |
|---|---|
| .102:8080 Struts2 | **nothing of substance** -- `cookies-without-httponly`, `cookies-without-secure` (info) only; **no S2-045** |
| .103:5984 CouchDB | `CVE-2017-12635` (critical) + `couchdb-default-login` (high) |
| .104:6379 Redis | **nothing** |

**So nuclei actively confirmed 1 of the 3 walked hops (CouchDB RCE), not 2.** An earlier note of
mine said 2/3; that was wrong. The Redis hop was confirmed by `walk_chain.py --redis` (our own
RESP PING/CONFIG/marker), **not** by nuclei -- do not attribute Redis to nuclei.

**Why it caught so little, and why that is not a false-positive story:**

- *Struts2 missed.* The S2-045 template fires only when its OGNL payload hits the exact vulnerable
  action and the command output is echoed back. The template probed broad paths, not the showcase
  action the vulhub PoC targets, so it never triggered. The vulnerability is real -- we walked it to
  a root shell. The template's condition simply was not met.
- *Redis missed.* Nuclei is HTTP-centric; its non-HTTP (`network`) templates are few and did not
  fire against `:6379` in the default run. Redis unauth is trivially real (confirmed by our walk).

Active templates only fire on an exact, safe-to-test trigger that a template exists for. **"Nuclei
found fewer" means its template conditions were not met, not that the host is not vulnerable** --
here it would have mislabelled 2 of 3 genuinely exploitable hops as clean. This is the same caution
as the version-scanner over-report, in the opposite direction, and it is why nuclei **cannot stand
in for a version-based third VA scanner**: it is a narrow active corroborator, not a comprehensive
network VA tool.

Group B (`nuclei_groupb.jsonl`, .110-.112): 40 findings, **0 with a CVE** -- WordPress/Apache/MySQL
fingerprints, missing security headers, one `wp-config-setup` (high). Confirms the same point: on
ordinary old images with no actively-testable exploit path, active scanning returns effectively no
CVE-level findings while the version scanners report hundreds. Not comparable units.

**For the paper / P'Ohm:** if nuclei is included at all, it is an *independent active confirmation*
of the CouchDB RCE on the chain, nothing more. Do not report its finding count beside OpenVAS/Nessus
counts as if they measure the same thing, and do not use 2/3. The 2-vs-3-scanner question is still
P'Ohm's to decide.

## Nuclei now confirms all three hops -- why it took calibration (4 October 2026)

Follow-up to the 3 October note. The 1-of-3 result above was a tooling gap, not a property of the
hosts (we had already walked all three to root). After calibrating the run, nuclei actively
confirms **3 of 3** hops. Evidence: `raw/nuclei/2026-10-04_nuclei_chain_3of3.jsonl`.

| Target | Template | Severity | What the response proved |
|---|---|---|---|
| .102:8080 Struts2 | `s2-045-lab` (custom) | critical | body returned `uid=0(root) gid=0(root) groups=0(root)` |
| .103:5984 CouchDB | `CVE-2017-12635` (stock) | critical | admin-user write accepted (unchanged from before) |
| .104:6379 Redis | `exposed-redis` (stock, network/tcp) | high | `INFO` returned `redis_version:4.0.14`, no auth |

**What had to change, hop by hop:**

- *Redis* was missed only because the earlier run used HTTP templates; the matching template
  (`network/exposures/exposed-redis.yaml`) is a `tcp` template and was simply not in the set. Adding
  the network template -- no payload change -- makes it fire. Nothing exotic.
- *Struts2* needed a **lab-calibrated template**, `nuclei_templates/s2-045-lab.yaml`. The stock
  `http/cves/2017/CVE-2017-5638.yaml` fails here for two independent reasons we verified by hand:
  (1) it sends **GET /**, but the Jakarta Multipart parser -- the S2-045 sink -- only runs on a
  **POST**, so the root page just returns the static upload form and the OGNL never evaluates;
  (2) its OGNL is the 2.5.x `DEFAULT_MEMBER_ACCESS` variant, while this showcase is **Struts 2.3.x**
  and needs the classic `_memberAccess`-clearing payload. The custom template POSTs the 2.3.x
  payload running a read-only `id` and matches the root uid. (The OGNL expression `233*233` -> the
  `vulhub: 54289` response header was the first by-hand proof that evaluation fired.)

**What this does and does not change for the argument:**

- It *confirms* the earlier caution rather than reversing it: a stock active scanner missed a
  genuinely exploitable, KEV-listed RCE out of the box, and only a target-specific template (or the
  right protocol templates) surfaced it. "Active found fewer" was a **template/coverage** fact, exactly
  as claimed -- here we closed the gap by hand on three known hosts.
- It does **not** turn nuclei into a comprehensive VA scanner. The 3/3 came from knowing the three
  vulnerabilities in advance and hand-selecting/writing templates for them; that is confirmation of a
  known chain, not discovery. A hand-tuned 3/3 must not be reported as if nuclei would have found
  these unaided, and still does not stand in for a version-based third VA peer.

**For the paper / P'Ohm:** the honest framing is now "active validation independently reproduced
all three hops of the walked chain, once calibrated per host" -- an *exploitability corroboration*
of the attack graph, strongest where it matters (the chain). The custom Struts2 template is a
reusable lab artifact (`nuclei_templates/s2-045-lab.yaml`). Still do not place nuclei's finding
counts beside OpenVAS/Nessus breadth as if they are the same unit.

## Qualys Community Edition as a third version-based VA scanner (6 October 2026)

Added Qualys CE as a candidate **third version-based peer** (the kind P'Ohm asked for -- unlike
nuclei, which is an active validator, not a comprehensive VA scanner). Raw result:
`raw/qualys/Scan_Results_thamm3yn_20261006_scan_1791230681_65501.xml`; parsed to
`raw/qualys/qualys_findings_parsed.csv`. Scanner 15.3.4-1, signatures 2.6.710-3, profile
`tr-fullports`, duration 40:04, 3/3 hosts alive.

**Result: Qualys confirmed all three chain hops in one unauthenticated scan** -- the only single
scanner that has:

| Hop | QID | Severity | CVE |
|---|---|---|---|
| .102 Struts2 S2-045 | 11771 | critical | CVE-2017-5638 |
| .103 CouchDB | 20056 | high | CVE-2017-12635, -12636 |
| .104 Redis unauthenticated | 19994 | critical | (config; no CVE) |

Breadth: **36 confirmed/potential vulns + 51 info** across the three hosts (.102 = 7 vulns, .103 =
16, .104 = 13), including many extra Jetty, CouchDB and Redis CVEs beyond the chain. This beats the
per-scanner coverage recorded earlier (OpenVAS caught CouchDB not Struts2; Nessus caught Struts2 not
CouchDB; nuclei needed per-host calibration). As a version-based peer, Qualys is the strongest single
tool on this chain.

**Version-inference over-report (same caution as OpenVAS/Nessus):** Redis (4.0.14) was tagged with
CVEs dated 2024/2025/2026 (e.g. CVE-2026-66373, CVE-2025-32023) inferred from the version banner, not
actively confirmed. This is exactly the version-scanner behaviour the project already documents -- do
not treat Qualys's banner-derived CVEs as confirmed-exploitable; the only hop we proved exploitable by
walking is still the three in the chain.

### Deployment notes (reproducibility) -- two real gotchas

1. **Appliance = a KVM VM, not a container.** Qualys CE offers no container scanner; every appliance
   image (incl. "Red Hat OpenShift") is a full VM (`qVSA...qcow2` + libvirt XML, `<domain type='kvm'>`,
   2 GB/1 vCPU, **x86_64** -- the shipped XML wrongly says `arch='i686'`, which fails to boot; must set
   `x86_64`). Host had no nested virt: the lab runs inside **VMware Workstation**, and enabling
   "Virtualize Intel VT-x/EPT" failed with `hv.capable=0` until **Hyper-V + VBS/Memory Integrity were
   disabled on the Windows host** (`bcdedit /set hypervisorlaunchtype off` + DeviceGuard/HVCI regkeys +
   reboot). Then `/dev/kvm` appeared and the appliance ran under libvirt, its virtio NIC bridged onto
   the Docker bridge `br-a39259a11c8c` at a static `172.18.0.200/16` (gw .1), reaching Qualys cloud via
   the lab VM's existing NAT. Code 21018473258074.

2. **Default scan found "3 hosts alive, 0 vulns" -- not a block, a port-list gap.** First scan with
   "Qualys Recommended" finished in 46 s with zero findings. Target logs showed **0 connections from
   .200**, but a netns bridge-peer test (172.18.0.201 on the same bridge) reached .102:8080 / .103:5984
   / .104:6379 fine -- so the L2 path was never the problem. The default profile simply did not probe
   the services' non-standard ports. Fix: custom profile `tr-fullports` with **TCP Ports = Full +
   Perform 3-way Handshake**, Vulnerability Detection = Complete, authentication OFF (clean unauth). The
   re-scan then hit the services (Struts2 got ~4.4k HTTP requests) and returned the 36 findings above.
   Lesson for any scanner here: services on non-standard ports need an explicit full/added-port list.

**Cloud / isolation tradeoff (for P'Ohm, unchanged and now concrete):** Qualys is cloud-based -- the
appliance phones home and the lab findings are stored in Qualys' cloud (90-day retention). OpenVAS and
Nessus run fully local; Qualys does not. The hosts are disposable vulhub containers with no sensitive
data, so this is acceptable, but it means we **cannot claim all scanners ran under identical fully
offline conditions** -- this must be disclosed if Qualys is used in the paper. Whether to include
Qualys as the third scanner is still P'Ohm's call; the data now exists to support it if he says yes.

## What more scanners actually buy: two measurements (6 October 2026)

P'Ohm's "add a third scanner" raised a concrete question -- does the scanner count make
ThreatRank *better*? Two experiments, both reusing the existing pipeline unchanged. Scripts:
`scanner_count.py` (ML metric) and `risk.py` per scanner (ranking). Qualys findings were brought
into the canonical schema by `parse_qualys.py` (-> `processed/findings_qualys_b2.csv` for lab3,
`findings_qualys_d.csv` for lab4).

### (1) Scanner count does NOT improve the likelihood surrogate -- a flat, honest null

`scanner_count.py` trains the exploit-likelihood surrogate on the identical CVE-grouped split as
the fig_ml_baseline headline, varying only the scanners whose findings train it, with the test
population held fixed (OpenVAS CVE-bearing findings) so Spearman is comparable.

| training scanners | Spearman | fold mean +- sd |
|---|---|---|
| OpenVAS | 0.618 | 0.612 +- 0.084 |
| + Nessus | 0.630 | 0.622 +- 0.095 |

Delta +0.012, far inside the fold sd. **Adding a scanner adds coverage, not per-CVE prediction
skill.** A "scanner count -> ML metric" bar chart would be flat and is not worth making; the result
belongs in Limitations as one honest line. (Qualys would almost certainly be flat here too, so it was
not scanned onto the whole ML corpus for this purpose.)

### (2) The method's advantage over severity is scanner-robust -- this IS worth reporting

`risk.py` ranks each scanner's findings by R = L x C and grades the top of the list against CISA KEV
(the project's own label), beside the severity baseline a defender would use instead. Run per scanner
on the two labs that have an attack graph.

**lab3 (.110-.112):**

| scanner | graded CVE findings | KEV | R=LxC P@5 | severity P@5 | R first-KEV | severity first-KEV |
|---|---|---|---|---|---|---|
| OpenVAS | 217 | 7 | **1.00** | 0.60 | 1 | 1 |
| Nessus | 10 | 1 | 0.20 | 0.20 | 1 | 1 |
| Qualys | 57 | 3 | **0.40** | **0.00** | **1** | **21** |

**lab4 (.102-.104):** R first-KEV vs severity first-KEV -- OpenVAS 2 vs 4; Qualys **2 vs 10**
(Qualys P@5 0.20 vs severity 0.00). Nessus too sparse to grade on both labs.

**Reading:** on both dense scanners (OpenVAS and Qualys), R = L x C beats the severity baseline, so
the method's value is not an artifact of one scanner. The Qualys result is the sharpest: sorting
Qualys output by its own severity buries the first known-exploited finding at rank 21, while R lifts
it to rank 1. That gap *is* the paper's motivation made concrete -- Qualys assigns high severity to
the version-inferred CVEs it over-reports (the 2024-2026 Redis banner CVEs and similar), so severity
ordering reads far down the list before reaching something actually exploited, whereas EPSS x
reachability does not.

**METHOD NOTE / CAVEAT -- must be written next to any figure built from this:** the attack-graph
(consequence) model is built once from the lab topology (the reference input is OpenVAS) and every
scanner's findings are mapped onto that single fixed graph. `risk.py`'s `emitted` filter therefore
drops a finding whose (host, CVE) is not a fact in that graph, which is why Qualys is graded on 57 of
its 128 CVE-bearing lab3 findings (its over-reported, non-reachable extras fall out). Within each
scanner the R-vs-severity comparison is on the *same* kept set, so that comparison is fair; what the
single shared graph does not do is give Qualys-only CVEs a consequence of their own. For maximum rigor
the graph could be rebuilt per scanner (needs XSB); the lab's 9-fact graph is topology-driven, so the
qualitative conclusion (R beats severity on each dense scanner) is not expected to change. Nessus is
too sparse (10 CVE findings on lab3) to support any per-scanner claim and is reported as such, not
hidden.

**For the paper / P'Ohm:** the valuable figure is (2) -- "R = L x C beats severity independent of
scanner (OpenVAS and Qualys), while the raw finding lists differ ~4-20x" -- not a scanner-count curve.
Pair it with the null result (1) as a one-line honest limitation. Decision on including Qualys at all
remains P'Ohm's.
