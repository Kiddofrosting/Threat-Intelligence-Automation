# Threat Intelligence Automation Tool

A CLI Python tool that analyzes a PCAP file, aggregates raw observations into
behavioral events, runs a rule-based detection engine over those events,
correlates them with feed-aware threat-intelligence results, and produces an
analyst-first Markdown security report.

## Pipeline (v2)

```
RAW OBSERVATIONS  ->  BEHAVIORAL EVENTS  ->  DETECTION SIGNALS  ->  CORRELATED FINDINGS  ->  REPORT
 (DNS/HTTP/file        (aggregator.py:         (detector.py:          (correlator.py:          (reporter.py)
  packets)              grouped by client/      DNS/HTTP/File           endpoint + time-
                        domain/host/hash)        rules on events)        window chains,
                                                                          risk scoring,
                                                                          dedup)
```

Repeated observations (the same DNS query fired 20 times, the same file
transferred 3 times) are aggregated into one `BehavioralEvent` **before** any
detection rule runs — this is what stops "one detection per packet" and "one
finding per IOC" from happening. See `analyzer/aggregator.py`.

## Architecture

```
                 ┌─────────────┐
   PCAP file --> │ pcap_parser │  packets, DNS, HTTP, file payloads (+ DNS rcode,
                 └──────┬──────┘  file timestamps)
                        v
                 ┌─────────────┐
                 │ ioc_extractor│  unique IPs / domains / URLs / hashes
                 └──────┬──────┘
                        v
                 ┌─────────────┐
                 │  aggregator  │  BehavioralEvents: DNSBehavior / HTTPBehavior /
                 └──────┬──────┘  FileBehavior, with occurrence counts + timing
                        v
                 ┌─────────────┐
                 │   detector   │  DetectionSignals (DNS-00x / HTTP-00x / FILE-001),
                 └──────┬──────┘  multi-signal DGA scoring, allowlist suppression
                        v
      ┌─────────────────┼─────────────────┐
      v                 v                 v
 ┌─────────┐      ┌───────────┐      ┌─────────┐
 │AbuseIPDB│      │VirusTotal │      │ URLhaus │   feeds/ (cached, timed out,
 └────┬────┘      └─────┬─────┘      └────┬────┘   fail independently)
      └─────────────────┼─────────────────┘
                         v
                 ┌───────────────┐
                 │ ti_interpreter │  feed-specific CLEAN/UNKNOWN/WEAK_REPUTATION/
                 └───────┬───────┘  SUSPICIOUS/MALICIOUS states, not raw pass/fail
                         v
                 ┌───────────────┐
                 │   correlator   │  endpoint + time-window chains -> Findings,
                 └───────┬───────┘  5-dimension capped risk score, deduplication
                         v
                 ┌─────────────┐
                 │   reporter   │  reports/security_report.md (analyst-first)
                 └─────────────┘
```

`ioc_scoring.py` runs alongside the correlator to give every extracted IOC a
data-driven significance tier (insignificant / noteworthy / suspicious /
high-priority) for the IOC Inventory section — this is separate from whether
an IOC became a Finding.

## Detection rules implemented

| Rule | Title | Notes |
|---|---|---|
| DNS-001 | Excessive DNS Frequency | one signal per (client, domain), not per query |
| DNS-002 | High NXDOMAIN Ratio | requires a minimum occurrence count first |
| DNS-003 | Potential Algorithmically Generated Domain | multi-signal (`analyzer/dga.py`): length, entropy, digit/vowel ratio, char diversity, dictionary-word offset, hyphen structure, subdomain depth, TLD (weak, ≤5/100), NXDOMAIN/volume corroboration |
| DNS-007 | Excessive Unique Subdomains | grouped by apex domain across all clients |
| HTTP-001 / HTTP-002 | Suspicious Executable / Script Download | escalated to High severity only when paired with a suspicious User-Agent on the same request |
| HTTP-003 | Suspicious User-Agent | aggregated per (client, server, UA); Low severity standalone, always |
| HTTP-004 | Rare External Host | Informational weak signal only |
| FILE-001 | Suspicious File Signature | aggregated by SHA256; escalates with repeated transfers |

DNS-004/005/006/008 and HTTP-005/006/007 from the original brief are not yet
implemented as separate rules — HTTP-007's intent (repeated payload
retrieval) is folded into HTTP-001/002/FILE-001's occurrence tracking rather
than a standalone rule. Real, working rules were prioritized over stub
rules; see "Known limitations" below for what to add next.

Every `DetectionSignal` that matches an allowlist entry (`config/allowlist.yaml`)
is still generated and kept (with `suppressed=True` and a reason) — it shows
up in the report's tuning appendix but never reaches correlation or risk
scoring. Nothing is silently deleted.

## Threat-intelligence interpretation

`analyzer/ti_interpreter.py` maps each feed's own scoring model onto a shared
vocabulary — `CLEAN` / `UNKNOWN` / `WEAK_REPUTATION` / `SUSPICIOUS` /
`MALICIOUS` — using per-feed, configurable thresholds
(`config/detection_config.yaml`, `ti:` section):

- **AbuseIPDB** — confidence score + report count + recency of last report.
- **VirusTotal** — malicious/suspicious vendor counts relative to the total
  vendor pool (a single hit out of 90 is `WEAK_REPUTATION`, not malicious).
- **URLhaus** — presence of a record, its status (online/offline), and age.

Only `SUSPICIOUS`/`MALICIOUS` assessments are "meaningful" — a `CLEAN` or
`WEAK_REPUTATION` result, or "no record found", never creates a finding on
its own.

## Correlation & risk scoring

`analyzer/correlator.py` groups behavioral events by **source endpoint**,
linking a DNS event to the HTTP event(s) that resolved/queried the same
domain, and those to any file transfer to/from the same destination. A
Finding is only created once a chain has a non-suppressed detection signal or
a meaningful TI assessment attached — an IOC with neither still appears in
the IOC Inventory but never in Key Findings.

Risk score is five capped dimensions that sum to at most 100:

| Dimension | Max | Driven by |
|---|---|---|
| Reputation | 30 | TI assessment weights (`ti_interpreter.STATE_WEIGHT`) |
| Behavior | 30 | non-suppressed local detection signal scores |
| Payload | 20 | recognized file signature, escalated if TI/local detection corroborates it |
| Network context | 10 | how many stages of the DNS→HTTP→File chain are present |
| Asset context | 10 | always 0 here — no asset inventory is available; every finding says so explicitly |

A finding with no TI and no payload evidence (local heuristics only) is
capped at **Medium** severity regardless of the arithmetic total
(`config/detection_config.yaml` → `risk.caps.behavior_only_max_severity`).
Confidence is computed independently of severity, from evidence diversity
(how many of Reputation/Behavior/Payload actually contributed).

Findings that resolve to the same endpoint + indicator set are deduplicated
(occurrence counts, evidence and time ranges merged) before the final
severity-sorted list is numbered.

## Configuration

- `config/detection_config.yaml` — every threshold (DGA thresholds, DNS/HTTP
  rule thresholds, TI feed thresholds, risk weights, severity bands,
  correlation windows). Falls back to the same defaults in
  `analyzer/config.py` if missing/invalid.
- `config/allowlist.yaml` — known-legitimate domains/IPs/User-Agents/internal
  hosts. Falls back to `analyzer/allowlist.py`'s defaults (major CDN/cloud
  providers) if missing/invalid.
- `.env` — API keys (`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`,
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
| `--config` | Path to detection/risk config (default: `config/detection_config.yaml`) |
| `--allowlist` | Path to allowlist config (default: `config/allowlist.yaml`) |
| `--verbose` | Verbose logging, including per-stage counters |

## Report structure

`reports/security_report.md`:

1. **Executive Summary** — status, counts, findings-by-severity.
2. **Key Findings** — correlated findings only, each with severity,
   confidence (independent of severity), risk score, evidence and TI.
3. **Investigation Recommendations** — specific to each finding, not generic.
4. **Attack / Behavior Story** — DNS → HTTP → File chain diagrams where the
   evidence supports one.
5. **Technical Evidence** — aggregated DNS/HTTP/file behavioral tables and a
   behavioral (not per-packet) investigation timeline.
6. **IOC Inventory** — every extracted indicator with its significance tier;
   explicitly does not imply every listed IOC is malicious.
7. **Appendix** — TI summary counts, full raw TI results (including no-record
   lookups), suppressed/low-confidence signals, a per-rule tuning report
   (trigger/suppression/finding counts, average confidence and score),
   pipeline observability counters, limitations, references.

Evidence is stated once per finding and referenced by finding ID elsewhere
(e.g. the investigation timeline's "Related finding" column) rather than
repeated block-for-block.

## Testing

```bash
python -m pytest tests/
```

41 tests cover: IP/UA/extension classification, hashing/signatures, IOC
dedup, DGA scoring (dictionary words lower the score, TLD alone stays weak,
high-entropy low-vowel labels score high), behavioral aggregation (repeated
DNS/HTTP/file observations collapse into one event with the right occurrence
count), detection suppression (legitimate CDN domains, low-confidence DGA
capped below High severity), TI interpretation (AbuseIPDB 0 confidence is
`CLEAN` not malicious, a single VirusTotal hit out of many is
`WEAK_REPUTATION`, URLhaus no-record is `UNKNOWN`), correlation (DNS + HTTP +
file + TI collapse into one Finding, unrelated IOCs never merge, weak TI
alone never becomes a Finding, local-heuristics-only findings are capped
below Critical), and report generation (valid with zero findings, valid with
500 raw observations aggregating into 5 domains, executive summary present).

## Known limitations

- DNS response data (resolved IPs, response codes) has no transaction ID to
  key on at this layer, so it is merged into every client bucket sharing the
  same (domain, query type) — documented in the report's own Limitations
  section.
- Apex-domain grouping (DNS-007) is a last-two-labels approximation, not a
  public-suffix-list lookup — not authoritative for domains like `.co.uk`.
- Asset criticality/role is never available in this environment and is
  always reported as "Unknown" rather than guessed.
- DNS-004/005/006/008 and standalone HTTP-005/006/007 rules from the original
  brief are not yet separate rules (see "Detection rules implemented" above).
- Fast-flux and DNS-tunneling detection are not implemented as dedicated
  rules; DNS-007 (excessive unique subdomains) is the closest proxy today.
- Encrypted (TLS) traffic cannot be inspected beyond metadata.
- The risk score is a project-defined prioritization aid, not an
  industry-standard rating; a single indicator match is never proof of
  compromise on its own.

## Security considerations

- API keys are read only from environment variables via `.env` (git-ignored)
  — never hardcoded, logged, or written into the report.
- Per-feed response caching (`cache/`) avoids redundant lookups.
- All HTTP requests to feeds use explicit timeouts; a failed feed is reported
  as unavailable and never blocks the rest of the pipeline, nor is it ever
  treated as a "clean" TI result.
- PCAPs are treated as untrusted input: parsing is defensive and every layer
  access is guarded against missing fields.
