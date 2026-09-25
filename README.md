# Threat Intelligence Automation Tool

A CLI Python tool that analyzes a PCAP file, aggregates raw observations into
behavioral events, runs a rule-based detection engine over those events
(DNS, HTTP, file, and now TCP-level network/scan/exfiltration/beaconing
behavior), correlates them with feed-aware threat-intelligence results,
reconstructs multi-stage incidents, and produces an analyst-investigation
Markdown report (plus an optional machine-readable JSON export).

## Pipeline (v3)

```
RAW OBSERVATIONS -> BEHAVIORAL EVENTS -> DETECTION SIGNALS -> CORRELATED FINDINGS -> INCIDENTS -> REPORT
 (packets, DNS,       (aggregator.py +      (detector.py:         (correlator.py:        (correlator.py:    (reporter.py,
  HTTP, files)         network_events.py:    DNS/HTTP/File/         endpoint + time-       findings grouped    json_export.py)
                       grouped by client/     Network/Beacon         window chains,         by shared
                       domain/host/hash/       rules on events,      5-dim capped risk       endpoint into
                       flow)                   MITRE-annotated)       score, dedup)           one narrative)
```

Repeated observations are aggregated into one `BehavioralEvent` **before**
any detection rule runs -- this is what stops "one detection per packet" and
"one finding per IOC" from happening. Findings for the same endpoint are then
grouped into one **Incident** with a combined narrative, kill-chain view, and
MITRE mapping, rather than being reported as unrelated findings.

## Architecture

```
                 ┌─────────────┐
   PCAP file --> │ pcap_parser │  packets (+ TCP flags), DNS (+ rcode/txid),
                 └──────┬──────┘  HTTP (+ status/content-type), files (+ timestamp)
                        v
                 ┌─────────────┐
                 │ ioc_extractor│  unique IPs / domains / URLs / hashes
                 └──────┬──────┘
                        v
                 ┌───────────────────────────┐
                 │ aggregator + network_events│  DNSBehavior / HTTPBehavior / FileBehavior /
                 └──────────────┬─────────────┘  ConnectionAttempt / ScanCandidate, with
                                v                  occurrence counts, timing, per-occurrence
                                                   timestamps (for beaconing stats)
                 ┌───────────────────────────┐
                 │          detector          │  DetectionSignals: DNS-00x / HTTP-00x /
                 └──────────────┬─────────────┘  FILE-001 / NET-00x / BEACON-001,
                                v                  MITRE-annotated, allowlist-suppressed
      ┌─────────────────────────┼─────────────────────────┐
      v                         v                         v
 ┌─────────┐              ┌───────────┐              ┌─────────┐
 │AbuseIPDB│              │VirusTotal │              │ URLhaus │   feeds/ (cached, timed out,
 └────┬────┘              └─────┬─────┘              └────┬────┘   fail independently)
      └─────────────────────────┼─────────────────────────┘
                                 v
                 ┌───────────────┐
                 │ ti_interpreter │  feed-specific CLEAN/UNKNOWN/WEAK_REPUTATION/
                 └───────┬───────┘  SUSPICIOUS/MALICIOUS states, not raw pass/fail
                         v
                 ┌───────────────┐
                 │   correlator   │  endpoint + time-window chains -> Findings (5-dim
                 └───────┬───────┘  capped risk, evidence-family caps, dedup) -> Incidents
                         v
                 ┌───────────────────────┐
                 │ reporter / json_export │  reports/security_report.md (analyst
                 └───────────────────────┘  investigation report) + optional JSON
```

`ioc_scoring.py` gives every extracted IOC a data-driven significance tier
(insignificant / noteworthy / suspicious / high-priority), separate from
whether it became a Finding. `coverage.py` runs a detection-coverage
self-test per capture. `mitre_mapping.py` and `kill_chain.py` annotate
signals/findings with MITRE ATT&CK techniques and tactic stages.

## Detection rules implemented

| Rule | Title | Notes |
|---|---|---|
| DNS-001 | Excessive DNS Frequency | one signal per (client, domain), not per query |
| DNS-002 | High NXDOMAIN Ratio | requires a minimum occurrence count first |
| DNS-003 | Potential Algorithmically Generated Domain | multi-signal (`analyzer/dga.py`): length, entropy, digit/vowel ratio, char diversity, dictionary-word offset, hyphen structure, subdomain depth, TLD (weak, ≤5/100), NXDOMAIN/volume corroboration |
| DNS-004 | Rare External Domain | Informational; never promotes a finding alone |
| DNS-005 | Suspicious Newly Observed Domain | local domain-history baseline (`cache/domain_history.json`) |
| DNS-006 | DNS Tunneling Indicators | needs enough unique subdomains under one apex **and** (long avg. label length **or** high TXT/NULL ratio) |
| DNS-007 | Excessive Unique Subdomains | grouped by public-suffix-aware apex domain across all clients |
| DNS-008 | Potential Fast-Flux Behavior | cross-client view of distinct resolved IPs within a short window |
| HTTP-001 / HTTP-002 | Suspicious Executable / Script Download | escalated to High only when paired with a suspicious User-Agent |
| HTTP-003 | Suspicious User-Agent | aggregated per (client, server, UA); Low severity standalone, always |
| HTTP-004 | Rare External Host | Informational; never promotes a finding alone |
| HTTP-005 | Suspicious Download Source | executable/script download **and** a rare, unallowlisted destination |
| HTTP-006 | Executable / MIME Mismatch | declared Content-Type (from the paired HTTP response) vs. extension/signature |
| HTTP-007 | Repeated Payload Retrieval | standalone -- fires for *any* repeatedly-fetched path |
| HTTP-008 | Suspicious Request Pattern (SQLi/traversal/cmd-injection/XSS/LFI-RFI) | pattern must recur across ≥3 distinct requests to the same host -- a single match never fires |
| FILE-001 | Suspicious File Signature | aggregated by SHA256; escalates with repeated transfers |
| NET-001 | Port Scanning | one source, many distinct destination ports, low success ratio |
| NET-002 | Host Scanning | one source, many distinct destination IPs, low success ratio |
| NET-003 | Repeated Connection Attempts to Authentication Service | repeated attempts to an SSH/FTP/RDP/SQL/SMB-like port; never claims credentials were actually attempted (no protocol decoding) |
| NET-004 | Possible Data Exfiltration | asymmetric high-volume outbound traffic to an external destination |
| BEACON-001 | Possible Beaconing Behavior | regular-interval repeated connections (low coefficient of variation) |

Every rule in the original brief, plus network reconnaissance, exfiltration,
web-attack-pattern, and beaconing detection, is implemented and tested.
`Informational`-severity weak/rarity/novelty signals (DNS-004, DNS-005,
HTTP-004) never promote a finding on their own -- exactly like a
`WEAK_REPUTATION` TI result -- they only contribute to a finding's Behavior
score once something more substantial is already present.

Every `DetectionSignal` that matches an allowlist entry (`config/allowlist.yaml`)
is still generated and kept (with `suppressed=True` and a reason) -- visible
in the report's tuning appendix, never reaching correlation or risk scoring.

## What is deliberately NOT implemented, and why

- **TLS/JA3 fingerprinting, certificate inspection.** This parser has no TLS
  layer parser; faking certificate fields would violate "never fabricate
  fields that are unavailable." Adding a real TLS ClientHello/certificate
  parser is a scoped follow-on, not a quick addition.
- **Protocol-level credential brute-force (SSH/FTP/RDP/SMB decoding).**
  NET-003 detects the connection-level *pattern* (repeated attempts to an
  auth-like port) but explicitly never claims a credential was attempted --
  that would require decoding those protocols, which this parser doesn't do.
- **MITRE ATT&CK techniques beyond `analyzer/mitre_mapping.py`'s table.**
  Only rules whose detected behavior genuinely matches a technique's
  definition are mapped; nothing is assigned because the names sound related.

`analyzer/coverage.py`'s Detection Coverage Self-Test (report Section 11)
lists these explicitly as "Not implemented" rather than omitting them.

## Threat-intelligence interpretation

`analyzer/ti_interpreter.py` maps each feed's own scoring model onto a shared
vocabulary -- `CLEAN` / `UNKNOWN` / `WEAK_REPUTATION` / `SUSPICIOUS` /
`MALICIOUS` -- using per-feed, configurable thresholds. Only
`SUSPICIOUS`/`MALICIOUS` are "meaningful" -- `CLEAN`/`WEAK_REPUTATION`/
"no record found" never create a finding on their own.

## Correlation, risk scoring & incident reconstruction

`analyzer/correlator.py` groups behavioral events by **source endpoint**,
linking DNS -> HTTP -> file stages, and separately folding in
Network/Behavioral (scan/exfil/beacon) signals for that same endpoint into
exactly one of its candidates -- never duplicated across multiple findings
for the same endpoint. A Finding is only created once a chain has a
*substantive* (non-Informational, non-suppressed) detection signal or a
meaningful TI assessment attached.

Risk score is five capped dimensions summing to at most 100 (Reputation 30,
Behavior 30, Payload 20, Network context 10, Asset context 10). Within
Behavior, each evidence **family** (DNS/HTTP/File/Network/Behavioral) is
itself capped before summing (`risk.category_caps`) -- so three DNS rules
firing for one beaconing domain don't each contribute full independent
weight; this is the "evidence independence" requirement. A finding with no
TI and no payload evidence is capped at **Medium** severity regardless of
the arithmetic total. Confidence is computed independently of severity.

`build_incidents()` then groups Findings sharing an endpoint into one
**Incident**, with:
- a combined **narrative** ("10.2.28.88 is associated with N correlated
  findings: ... chronologically: ..."),
- a **kill-chain view** (`analyzer/kill_chain.py`) listing only the tactic
  stages actually supported by fired rules, in canonical order,
- a **MITRE ATT&CK** technique list (`analyzer/mitre_mapping.py`),
- and, per finding, an explicit **"what we know"** breakdown into
  *established* (directly observed), *strongly indicated* (multiple
  independent signals), *possible* (plausible, unconfirmed), and *not
  established* (explicitly not provable from this capture) -- plus a list of
  **suggested next investigation questions**.

## Configuration

- `config/detection_config.yaml` -- every threshold: DGA, DNS/HTTP rules, TI
  feeds, network/scan/exfil, beaconing, risk weights, severity bands,
  evidence-family category caps, asset-criticality weights, correlation
  windows. Falls back to the same defaults in `analyzer/config.py`.
- `config/allowlist.yaml` -- known-legitimate domains/IPs/User-Agents.
- `config/assets.yaml` -- optional IP -> hostname/role/criticality inventory.
  Unmapped IPs always report "Asset role: Unknown".
- `cache/domain_history.json` -- local, self-maintained baseline of
  previously-seen domains (DNS-005). Auto-created; reset with
  `--no-domain-history` or by deleting the file.
- `.env` -- API keys (`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`,
  `URLHAUS_AUTH_KEY`), copied from `.env.example`.

## Installation

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python main.py --pcap pcaps/sample.pcap --output reports/security_report.md
```

| Flag | Description |
|---|---|
| `--pcap` | Path to the input PCAP (required) |
| `--output` | Output Markdown path (default: `reports/security_report.md`) |
| `--no-ti` | Skip threat-intelligence lookups (offline run) |
| `--config` | Path to detection/risk config |
| `--allowlist` | Path to allowlist config |
| `--assets` | Path to asset inventory config |
| `--domain-history` | Path to the DNS-005 local history file |
| `--no-domain-history` | Disable DNS-005 and its history file entirely |
| `--json-output PATH` | Also write a machine-readable JSON report (findings, incidents, detections, IOC profiles, TI assessments, timeline) for SIEM/automation ingestion |
| `--fail-on-high` | Exit with status 2 if any finding reaches High/Critical severity (for CI pipelines) |
| `--verbose` | Verbose logging, including per-stage counters |

## Report structure

`reports/security_report.md` (13 sections): Executive Summary; Investigation
Scope; **Incidents & Key Findings** (grouped, with MITRE/kill-chain/"what we
know"/analyst questions); Investigation Recommendations; Attack Timeline
(behavioral, not per-packet); Attack Chain / Kill-Chain View; Entity/
Infrastructure Summary (internal vs. external); Threat Intelligence Summary;
Technical Evidence (drill-down tables incl. TCP connection attempts);
IOC Inventory; **Detection Coverage Self-Test**; **Unclassified/Observed
Traffic**; Appendix (raw TI incl. no-record lookups, suppressed signals,
per-rule tuning report, observability stats, limitations, references).

Evidence is stated once per finding and referenced by finding ID elsewhere
(e.g. the timeline's "Related finding" column) rather than repeated
block-for-block. `--json-output` produces the same data machine-readably.

## Testing

```bash
python -m pytest tests/
```

85 tests, including: every detection rule (DNS-001 through 008, HTTP-001
through 008, FILE-001, NET-001 through 004, BEACON-001) with both a
true-positive and an expected-non-detection case (e.g. a handful of SYN
retries ending in a normal connection is NOT flagged as brute force; a
single SQLi-looking query string is NOT flagged, only recurrence is); DGA
scoring; behavioral aggregation incl. precise DNS transaction-ID pairing and
public-suffix-aware apex-domain grouping (`.co.ke`/`.co.uk` businesses don't
get merged together); TI interpretation; evidence-family risk capping;
correlation (multi-stage chains collapse into one Finding, unrelated
endpoints never merge, weak signals alone never become a Finding);
**incident reconstruction** (findings sharing an endpoint group into one
Incident; unrelated endpoints stay separate); and report generation at 0
findings and at 500+ raw observations.

A full end-to-end run was also validated against hand-crafted, realistic
PCAPs built with Scapy -- exercising the real `pcap_parser.py` path (DNS
transaction IDs, TCP flags, HTTP request/response pairing, raw payload
bytes) rather than the synthetic dataclasses the unit tests use, including a
multi-stage scenario (DGA domain + malware download + port scan, all from
one endpoint) that correctly produced ONE incident with a five-stage
kill-chain view (Reconnaissance -> Discovery -> Initial Access -> Execution
-> Command and Control) instead of three unrelated findings. Testing against
a real capture from malware-traffic-analysis.net was not possible in this
environment (no outbound network access to that domain); the hand-built
PCAPs are the closest available substitute.

## Known limitations

- TLS/JA3 fingerprinting and protocol-level SSH/FTP/RDP/SMB decoding are not
  implemented (see "What is deliberately NOT implemented" above).
- Fast-flux (DNS-008) and port/host scanning (NET-001/002) have no
  ASN/geolocation diversity signal; they rely on distinct-IP/port counts and
  timing alone, which legitimate anycast/load-balanced services can also
  trigger.
- NET-004 (exfiltration) is a byte-volume/asymmetry heuristic only -- no
  payload content inspection.
- HTTP-008 (web attack patterns) matches request structure only -- no
  response/outcome inspection, so success is never established from it alone.
- DNS-005's baseline is local to this tool's own history, not a commercial
  passive-DNS feed -- starts empty, improves with use.
- DNS response pairing uses the DNS transaction ID when available (exact);
  falls back to a domain-keyed merge across clients only when no matching
  outstanding query exists in the same capture.
- Apex-domain grouping (`analyzer/public_suffixes.py`) is a curated
  multi-label-suffix list (covers `.co.ke`, `.co.uk`, `.co.za`, `.com.au`,
  and similar), not the full ~9000-entry Mozilla Public Suffix List --
  extend via `dns.custom_public_suffixes` in config if needed.
- Asset criticality only affects scoring/reporting for IPs present in
  `config/assets.yaml`; there is no automatic asset-discovery mechanism.
- Encrypted (TLS) traffic cannot be inspected beyond metadata.
- The risk score is a project-defined prioritization aid, not an
  industry-standard rating; a single indicator match is never proof of
  compromise on its own.

## Security considerations

- API keys are read only from environment variables via `.env` (git-ignored)
  -- never hardcoded, logged, or written into the report.
- Per-feed response caching (`cache/`) avoids redundant lookups.
- All HTTP requests to feeds use explicit timeouts; a failed feed is reported
  as unavailable and never blocks the rest of the pipeline, nor is it ever
  treated as a "clean" TI result.
- PCAPs are treated as untrusted input: parsing is defensive and every layer
  access is guarded against missing fields.
