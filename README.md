# Threat Intelligence Automation Tool

A CLI Python tool that analyzes a PCAP file, extracts indicators of compromise,
correlates them against three threat-intelligence feeds, and produces a
Markdown security report (`security_report.md`) — built for the Threat
Intelligence Automation interview project.

## Deliverables in this repository

| Deliverable | Location |
|---|---|
| Python script | `main.py` + `analyzer/`, `feeds/`, `utils/` |
| PCAP file | `pcaps/sample.pcap` (small synthetic demo capture — swap in a real sample from malware-traffic-analysis.net for the actual assignment run) |
| Generated security report | `reports/security_report.md` (pre-generated from `pcaps/sample.pcap`) |
| README (execution instructions) | this file |
| GitHub link | push this folder to a repo and share the link |

## Project Overview

Given a packet capture, the tool:

1. Parses network, DNS, HTTP and (best-effort) file-transfer metadata.
2. Extracts a de-duplicated set of IOCs (IPs, domains, URLs, hashes).
3. Runs a local rule-based detection engine over the traffic (log-based /
   PCAP-based threat detection).
4. Correlates IOCs against **AbuseIPDB**, **VirusTotal** and **URLhaus**.
5. Correlates PCAP evidence + local detections + TI results into
   structured findings with a transparent risk score.
6. Builds a chronological investigation timeline.
7. Generates `reports/security_report.md`.

Nothing in the pipeline fabricates results — a field or feed that has no
data says so explicitly ("Not available in supplied PCAP." /
"Threat intelligence lookup unavailable.").

## Architecture

```
                 ┌─────────────┐
   PCAP file --> │ pcap_parser │  packets, DNS, HTTP, file payloads
                 └──────┬──────┘
                        v
                 ┌─────────────┐
                 │ ioc_extractor│  unique IPs / domains / URLs / hashes
                 └──────┬──────┘
                        v
                 ┌─────────────┐
                 │   detector   │  local rule-based findings
                 └──────┬──────┘
                        v
      ┌─────────────────┼─────────────────┐
      v                 v                 v
 ┌─────────┐      ┌───────────┐      ┌─────────┐
 │AbuseIPDB│      │VirusTotal │      │ URLhaus │   feeds/ (cached, timed out,
 └────┬────┘      └─────┬─────┘      └────┬────┘   fail independently)
      └─────────────────┼─────────────────┘
                         v
                 ┌─────────────┐
                 │  correlator  │  findings + risk score + timeline
                 └──────┬──────┘
                        v
                 ┌─────────────┐
                 │   reporter   │  reports/security_report.md
                 └─────────────┘
```

## Features

- Scapy-based PCAP parsing: TCP/UDP/DNS/HTTP metadata, graceful handling
  of missing layers.
- Suspicious User-Agent, suspicious HTTP download, suspicious/DGA-like
  DNS, and file-signature detections, each with a stated reason and a
  classification (Informational / Suspicious / High-confidence suspicious).
- Three threat-intelligence integrations with per-feed JSON disk caching
  and independent failure handling (one feed going down never stops the run).
- Correlation engine that ties PCAP evidence, local detections and TI
  results together into one finding per IOC, with a transparent,
  project-defined 0–100 risk score.
- Chronological investigation timeline built from packet timestamps.
- Markdown security report matching the assignment brief: Introduction,
  Scope and Objective, Findings and Recommendations (network analysis,
  threat detection, TI correlation, correlated findings, timeline,
  recommendations), References, Conclusion.
- CLI progress output at every pipeline stage.

## Installation

```bash
python -m venv venv

# Linux/macOS
source venv/bin/activate
# Windows
venv\Scripts\activate

pip install -r requirements.txt
```

## Configuration

Copy `.env.example` to `.env` and fill in your own API keys:

```
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
URLHAUS_AUTH_KEY=
```

`.env` is git-ignored. URLhaus's basic lookup API works without a key;
`URLHAUS_AUTH_KEY` is only needed for the higher rate-limit tier.

## Usage

```bash
python main.py --pcap pcaps/sample.pcap --output reports/security_report.md
```

Optional flags:

| Flag        | Description                                   |
|-------------|------------------------------------------------|
| `--pcap`    | Path to the input PCAP (required)              |
| `--output`  | Output Markdown path (default: `reports/security_report.md`) |
| `--no-ti`   | Skip threat-intelligence lookups (offline run) |
| `--verbose` | Verbose logging                                |

For the real interview submission, replace `pcaps/sample.pcap` with a
sample downloaded from
[malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/).

## Threat Intelligence Sources

| Feed       | Used for                          | URL |
|------------|-------------------------------------|-----|
| AbuseIPDB  | IP reputation / abuse confidence   | https://www.abuseipdb.com |
| VirusTotal | IPs, domains, URLs, file hashes    | https://www.virustotal.com |
| URLhaus    | Malicious URLs / malware infra     | https://urlhaus.abuse.ch |

Only indicator types relevant to each feed are submitted — see
`FEED_APPLICABLE_TYPES` in `main.py`.

## Detection Logic

| Category                     | Trigger |
|-------------------------------|---------|
| Suspicious User-Agent          | UA matches curl/wget/python-requests/PowerShell/certutil/etc. |
| Suspicious HTTP Download        | Requested path ends in an executable/script extension |
| Suspicious DNS Query            | Domain uses a TLD disproportionately linked to abuse |
| Possible DGA-like Domain        | Long, low-vowel-density label (heuristic, not a verdict) |
| File Transfer Observed          | Raw TCP payload reassembled with a recognizable file signature |

Local detections never claim "Confirmed malicious" on their own — that
label is reserved for findings backed by threat-intelligence evidence.

## Risk Scoring

A simple, transparent, **project-defined** score (not an industry
standard), built from weighted signals: a TI match, multiple
independent TI matches, high-confidence TI results, suspicious
User-Agent, suspicious download, suspicious DNS, and file signatures.

| Score  | Band |
|--------|------|
| 0–19   | Informational |
| 20–39  | Low |
| 40–69  | Medium |
| 70–89  | High |
| 90+    | Critical |

The score assists prioritization; it is not proof of compromise.

## Example Output

```
[+] Loading PCAP
[+] Extracting network metadata
    842 packets parsed
[+] Extracting IOCs
    17 unique IOC(s) extracted
[+] Running detections
    4 local detection(s) generated
[+] Querying AbuseIPDB
    AbuseIPDB: 2 match(es)
[+] Querying VirusTotal
    VirusTotal: 1 match(es)
[+] Querying URLhaus
    URLhaus: 1 match(es)
[+] Correlating findings
    3 correlated finding(s)
[+] Generating Markdown report
[+] Analysis complete — report written to reports/security_report.md
```

## Security Report

`reports/security_report.md` follows the assignment brief exactly:

- **Introduction**
- **Scope and Objective**
- **Findings and Recommendations** — network analysis (protocols, top
  IPs/ports, DNS, HTTP, files), threat detection (log-based/PCAP-based),
  threat-intelligence correlation, correlated findings with risk scores,
  investigation timeline, and recommendations
- **References** — the threat-intelligence feeds used
- **Conclusion** — plus stated limitations

## Limitations

- Encrypted (TLS) traffic cannot be inspected beyond metadata.
- Fields absent from the PCAP are reported as unavailable, never guessed.
- TI feeds are rate-limited and may be unavailable at scan time; the
  report states this explicitly rather than hiding it.
- File reconstruction is best-effort and only works for unencrypted,
  fully-captured transfers.
- The risk score is a prioritization aid, not proof of compromise.

## Security Considerations

- API keys are read only from environment variables via `.env`
  (git-ignored) — never hardcoded, logged, or written into the report.
- Per-feed response caching (`cache/`) avoids redundant lookups for
  repeated IOCs and reduces API usage.
- All HTTP requests to feeds use explicit timeouts; a failed or
  unreachable feed is reported as unavailable and never blocks the rest
  of the pipeline.
- PCAPs are treated as untrusted input: parsing is defensive and every
  layer access is guarded against missing fields.
- Detections are explicitly classified (Informational → Confirmed
  malicious) to avoid overstating confidence and generating false
  positives.

## Testing

```bash
python -m pytest tests/
```

Covers private/public IP classification, suspicious User-Agent and
extension detection, hashing, IOC de-duplication, and risk-band scoring.
