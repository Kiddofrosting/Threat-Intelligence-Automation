# Threat Intelligence & Network Security Analysis Report

- **PCAP file:** `pcaps/sample2.pcap`
- **Analysis date:** 2026-09-24 23:36 UTC
- **Tool:** Threat Intelligence Automation Tool v3.0.0
- **Analyst:** SOC Analyst

---

## 1. Executive Summary

**Status:** LOW-SEVERITY ACTIVITY OBSERVED

- **What happened:** 1 incident(s) covering 13 correlated finding(s) were identified.
- **Host(s) involved:** 172.16.1.66
- **Behavior categories observed:** Behavioral, DNS Behavior, Network Connection, Threat Intelligence
- **Strongest evidence:** F-001 (Suspicious Connection to ip-api.com), risk score 37/100, confidence Medium.
- **What cannot be established from this capture:** No independent threat-intelligence evidence corroborates this domain; the DGA classification rests on lexical/behavioral heuristics alone.

- Packets analyzed: 11562
- Unique source IPs: 40
- Unique destination IPs: 45
- Unique public IP indicators: 38
- Unique domains: 48
- IOCs extracted: 88
- Detection signals raised: 53 (51 active, 2 suppressed by allowlist)
- Correlated findings: 13 grouped into 1 incident(s)

**Findings by severity**

| Severity | Count |
|---|---|
| Low | 5 |
| Informational | 8 |


## 2. Investigation Scope

| Item | Value |
|---|---|
| PCAP analyzed | pcaps/sample2.pcap |
| Capture duration | 585.7 seconds |
| Packet count | 11562 |
| Protocols observed | UDP (243), IP-PROTO-2 (9), Ether (31), TCP (11276), IP-PROTO-1 (3) |
| Internal hosts observed | 7 |
| External hosts observed | 38 |

Limitations affecting this analysis are detailed in full in Section 13.6; in brief: encrypted traffic is not inspected beyond metadata, TLS/JA3 fingerprinting and protocol-level (SSH/FTP/RDP/SMB) credential decoding are not implemented, and the risk score is a project-defined prioritization aid, not proof of compromise.

## 3. Incidents & Key Findings

Findings are grouped into incidents by shared endpoint. Only correlated, evidence-backed findings appear here -- an indicator observed with no corroborating evidence appears only in the IOC Inventory (Section 10).

### INC-001 — Multi-stage activity involving 172.16.1.66

- **Severity:** Low &nbsp;|&nbsp; **Confidence:** High &nbsp;|&nbsp; **Risk score:** 37/100
- **Affected endpoint(s):** 172.16.1.66
- **Time window:** 02:38:48 – 02:44:23
- **Kill-chain stages observed:** Discovery → Command and Control
- **MITRE ATT&CK technique(s):** T1568.002 — Dynamic Resolution: Domain Generation Algorithms

**Narrative:** 172.16.1.66 is associated with 13 correlated findings in this capture: Potential DGA Domain Activity — wireshark-ws-dc.wiresharkworkshop.online, Potential DGA Domain Activity — desktop-skbr25f.local, Potential DGA Domain Activity — wiresharkworkshop.online, Suspicious Network Activity, Potential DGA Domain Activity — _kerberos._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online, Potential DGA Domain Activity — desktop-skbr25f.wiresharkworkshop.online, Potential DGA Domain Activity — wiresharkworkshop.online, Threat Intelligence Match, Threat Intelligence Match, Suspicious Connection to ip-api.com, Potential DGA Domain Activity — autodiscover-s.outlook.com, Potential DGA Domain Activity — autodiscover.wiresharkworkshop.online, Potential DGA Domain Activity — img-s-msn-com.akamaized.net. Chronologically: 02:38:48 — Potential DGA Domain Activity — wireshark-ws-dc.wiresharkworkshop.online (severity Informational, F-009); 02:38:48 — Potential DGA Domain Activity — desktop-skbr25f.local (severity Informational, F-007); 02:38:49 — Potential DGA Domain Activity — wiresharkworkshop.online (severity Low, F-004); 02:38:49 — Suspicious Network Activity (severity Informational, F-006); 02:38:53 — Potential DGA Domain Activity — _kerberos._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online (severity Informational, F-013); 02:38:53 — Potential DGA Domain Activity — desktop-skbr25f.wiresharkworkshop.online (severity Informational, F-008); 02:38:53 — Potential DGA Domain Activity — wiresharkworkshop.online (severity Low, F-005); 02:39:52 — Threat Intelligence Match (severity Low, F-002); 02:39:53 — Threat Intelligence Match (severity Low, F-003); 02:40:06 — Suspicious Connection to ip-api.com (severity Low, F-001); 02:42:13 — Potential DGA Domain Activity — autodiscover-s.outlook.com (severity Informational, F-012); 02:42:15 — Potential DGA Domain Activity — autodiscover.wiresharkworkshop.online (severity Informational, F-010); 02:44:17 — Potential DGA Domain Activity — img-s-msn-com.akamaized.net (severity Informational, F-011).

#### F-009 — Potential DGA Domain Activity — wireshark-ws-dc.wiresharkworkshop.online

- Severity: Informational | Confidence: Low | Risk score: 13/100
- Category: DNS Behavior
- Destinations: 172.16.1.4 | Domain(s): wireshark-ws-dc.wiresharkworkshop.online
- Detection rule(s): DNS-003, DNS-004

**Evidence:**
- DGA heuristic score: 55/100 (confidence: Medium)
- wireshark-ws-dc.wiresharkworkshop.online was queried only 2 time(s) across the entire capture.

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

**What we know:**
- _Established:_ 172.16.1.66 issued 2 DNS quer(y/ies) for wireshark-ws-dc.wiresharkworkshop.online, directly observed in the capture.
- _Strongly indicated:_ Multi-signal heuristic scoring (entropy, digit/vowel ratio, dictionary-word absence) is consistent with algorithmic domain generation.

**Suggested next questions:**
- Did 172.16.1.66 communicate with this infrastructure prior to this capture?
- Has 172.16.1.66 shown similar behavior at other times, or authenticated to other systems?

#### F-007 — Potential DGA Domain Activity — desktop-skbr25f.local

- Severity: Informational | Confidence: Low | Risk score: 14/100
- Category: DNS Behavior
- Destinations: N/A | Domain(s): desktop-skbr25f.local
- Detection rule(s): DNS-003, DNS-004

**Evidence:**
- DGA heuristic score: 60/100 (confidence: Medium)
- desktop-skbr25f.local was queried only 1 time(s) across the entire capture.

**Threat intelligence:**
- No meaningful threat-intelligence match.

**What we know:**
- _Established:_ 172.16.1.66 issued 1 DNS quer(y/ies) for desktop-skbr25f.local, directly observed in the capture.
- _Strongly indicated:_ Multi-signal heuristic scoring (entropy, digit/vowel ratio, dictionary-word absence) is consistent with algorithmic domain generation.
- _Not established:_ No independent threat-intelligence evidence corroborates this domain; the DGA classification rests on lexical/behavioral heuristics alone.

**Suggested next questions:**
- Did 172.16.1.66 communicate with this infrastructure prior to this capture?
- Has 172.16.1.66 shown similar behavior at other times, or authenticated to other systems?

#### F-004 — Potential DGA Domain Activity — wiresharkworkshop.online

- Severity: Low | Confidence: Medium | Risk score: 20/100
- Category: DNS Behavior
- Destinations: 172.16.1.4 | Domain(s): wiresharkworkshop.online
- Detection rule(s): DNS-003, DNS-004, DNS-007

**Evidence:**
- DGA heuristic score: 31/100 (confidence: Low)
- wiresharkworkshop.online was queried only 2 time(s) across the entire capture.
- 10 unique subdomains observed under wiresharkworkshop.online across 1 source(s): _gc._tcp.default-first-site-name._sites.wiresharkworkshop.online, _kerberos._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online, _ldap._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online, _ldap._tcp.default-first-site-name._sites.wireshark-ws-dc.wiresharkworkshop.online, _ldap._tcp.default-first-site-name._sites.wiresharkworkshop.online, _ldap._tcp.wireshark-ws-dc.wiresharkworkshop.online, autodiscover.wiresharkworkshop.online, desktop-skbr25f.wiresharkworkshop.online, wireshark-ws-dc.wiresharkworkshop.online, wpad.wiresharkworkshop.online

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 2 suspicious. Interpreted as Weak Reputation.

**What we know:**
- _Established:_ 172.16.1.66 issued 1 DNS quer(y/ies) for wiresharkworkshop.online, directly observed in the capture.
- _Strongly indicated:_ Multi-signal heuristic scoring (entropy, digit/vowel ratio, dictionary-word absence) is consistent with algorithmic domain generation.

**Suggested next questions:**
- Did 172.16.1.66 communicate with this infrastructure prior to this capture?
- Has 172.16.1.66 shown similar behavior at other times, or authenticated to other systems?

#### F-006 — Suspicious Network Activity

- Severity: Informational | Confidence: Low | Risk score: 14/100
- Category: Behavioral
- Destinations: N/A | Domain(s): wpad.wiresharkworkshop.online
- Detection rule(s): DNS-001, DNS-002

**Evidence:**
- 172.16.1.66 queried wpad.wiresharkworkshop.online (A) 8 time(s) between 02:38:49 and 02:44:23.
- 8/8 queries for wpad.wiresharkworkshop.online from 172.16.1.66 resolved NXDOMAIN (100%).

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

**What we know:**
- _Established:_ 172.16.1.66 issued 8 DNS quer(y/ies) for wpad.wiresharkworkshop.online, directly observed in the capture.

**Suggested next questions:**
- Did 172.16.1.66 communicate with this infrastructure prior to this capture?
- Has 172.16.1.66 shown similar behavior at other times, or authenticated to other systems?

#### F-013 — Potential DGA Domain Activity — _kerberos._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online

- Severity: Informational | Confidence: Low | Risk score: 8/100
- Category: DNS Behavior
- Destinations: N/A | Domain(s): _kerberos._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online
- Detection rule(s): DNS-003, DNS-004

**Evidence:**
- DGA heuristic score: 32/100 (confidence: Low)
- _kerberos._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online was queried only 1 time(s) across the entire capture.

**Threat intelligence:**
- No meaningful threat-intelligence match.

**What we know:**
- _Established:_ 172.16.1.66 issued 1 DNS quer(y/ies) for _kerberos._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online, directly observed in the capture.
- _Strongly indicated:_ Multi-signal heuristic scoring (entropy, digit/vowel ratio, dictionary-word absence) is consistent with algorithmic domain generation.
- _Not established:_ No independent threat-intelligence evidence corroborates this domain; the DGA classification rests on lexical/behavioral heuristics alone.

**Suggested next questions:**
- Did 172.16.1.66 communicate with this infrastructure prior to this capture?
- Has 172.16.1.66 shown similar behavior at other times, or authenticated to other systems?

#### F-008 — Potential DGA Domain Activity — desktop-skbr25f.wiresharkworkshop.online

- Severity: Informational | Confidence: Low | Risk score: 14/100
- Category: DNS Behavior
- Destinations: N/A | Domain(s): desktop-skbr25f.wiresharkworkshop.online
- Detection rule(s): DNS-003, DNS-004

**Evidence:**
- DGA heuristic score: 62/100 (confidence: Medium)
- desktop-skbr25f.wiresharkworkshop.online was queried only 1 time(s) across the entire capture.

**Threat intelligence:**
- No meaningful threat-intelligence match.

**What we know:**
- _Established:_ 172.16.1.66 issued 1 DNS quer(y/ies) for desktop-skbr25f.wiresharkworkshop.online, directly observed in the capture.
- _Strongly indicated:_ Multi-signal heuristic scoring (entropy, digit/vowel ratio, dictionary-word absence) is consistent with algorithmic domain generation.
- _Not established:_ No independent threat-intelligence evidence corroborates this domain; the DGA classification rests on lexical/behavioral heuristics alone.

**Suggested next questions:**
- Did 172.16.1.66 communicate with this infrastructure prior to this capture?
- Has 172.16.1.66 shown similar behavior at other times, or authenticated to other systems?

#### F-005 — Potential DGA Domain Activity — wiresharkworkshop.online

- Severity: Low | Confidence: Medium | Risk score: 20/100
- Category: DNS Behavior
- Destinations: . | Domain(s): wiresharkworkshop.online
- Detection rule(s): DNS-003, DNS-004, DNS-007

**Evidence:**
- DGA heuristic score: 31/100 (confidence: Low)
- wiresharkworkshop.online was queried only 2 time(s) across the entire capture.
- 10 unique subdomains observed under wiresharkworkshop.online across 1 source(s): _gc._tcp.default-first-site-name._sites.wiresharkworkshop.online, _kerberos._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online, _ldap._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online, _ldap._tcp.default-first-site-name._sites.wireshark-ws-dc.wiresharkworkshop.online, _ldap._tcp.default-first-site-name._sites.wiresharkworkshop.online, _ldap._tcp.wireshark-ws-dc.wiresharkworkshop.online, autodiscover.wiresharkworkshop.online, desktop-skbr25f.wiresharkworkshop.online, wireshark-ws-dc.wiresharkworkshop.online, wpad.wiresharkworkshop.online

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 2 suspicious. Interpreted as Weak Reputation.

**What we know:**
- _Established:_ 172.16.1.66 issued 1 DNS quer(y/ies) for wiresharkworkshop.online, directly observed in the capture.
- _Strongly indicated:_ Multi-signal heuristic scoring (entropy, digit/vowel ratio, dictionary-word absence) is consistent with algorithmic domain generation.

**Suggested next questions:**
- Did 172.16.1.66 communicate with this infrastructure prior to this capture?
- Has 172.16.1.66 shown similar behavior at other times, or authenticated to other systems?

#### F-002 — Threat Intelligence Match

- Severity: Low | Confidence: High | Risk score: 32/100
- Category: Threat Intelligence
- Destinations: 140.82.113.3 | Domain(s): github.com
- Detection rule(s): DNS-004

**Evidence:**
- github.com was queried only 1 time(s) across the entire capture.

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.
- URLhaus record found (status: online, threat: malware_download). Interpreted as Malicious.
- AbuseIPDB abuse confidence 0/100 from 1 report(s), last reported 43d ago. Interpreted as Weak Reputation.
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

**What we know:**
- _Established:_ 172.16.1.66 issued 1 DNS quer(y/ies) for github.com, directly observed in the capture.
- _Strongly indicated:_ Independent local-detection and threat-intelligence evidence point to the same conclusion.

**Suggested next questions:**
- Did 172.16.1.66 communicate with this infrastructure prior to this capture?
- Has 172.16.1.66 shown similar behavior at other times, or authenticated to other systems?

#### F-003 — Threat Intelligence Match

- Severity: Low | Confidence: High | Risk score: 32/100
- Category: Threat Intelligence
- Destinations: 185.199.110.133 | Domain(s): objects.githubusercontent.com
- Detection rule(s): DNS-004

**Evidence:**
- objects.githubusercontent.com was queried only 1 time(s) across the entire capture.

**Threat intelligence:**
- AbuseIPDB abuse confidence 26/100 from 9 report(s), last reported 6d ago. Interpreted as Suspicious.
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.
- URLhaus record found (status: offline, threat: malware_download). Interpreted as Malicious.

**What we know:**
- _Established:_ 172.16.1.66 issued 1 DNS quer(y/ies) for objects.githubusercontent.com, directly observed in the capture.
- _Strongly indicated:_ Independent local-detection and threat-intelligence evidence point to the same conclusion.

**Suggested next questions:**
- Did 172.16.1.66 communicate with this infrastructure prior to this capture?
- Has 172.16.1.66 shown similar behavior at other times, or authenticated to other systems?

#### F-001 — Suspicious Connection to ip-api.com

- Severity: Low | Confidence: Medium | Risk score: 37/100
- Category: Network Connection
- Destinations: 208.95.112.1 | Domain(s): ip-api.com
- Detection rule(s): DNS-004, HTTP-004

**Evidence:**
- ip-api.com was queried only 1 time(s) across the entire capture.
- ip-api.com was contacted only 1 time(s) across the entire capture.

**Threat intelligence:**
- AbuseIPDB abuse confidence 33/100 from 12 report(s), last reported 7d ago. Interpreted as Suspicious.
- VirusTotal: 1/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Weak Reputation.
- VirusTotal: 1/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Weak Reputation.

**What we know:**
- _Established:_ 172.16.1.66 issued 1 DNS quer(y/ies) for ip-api.com, directly observed in the capture. 172.16.1.66 sent 1 HTTP request(s) to ip-api.com (208.95.112.1), directly observed in the capture.

**Suggested next questions:**
- Did 172.16.1.66 communicate with this infrastructure prior to this capture?
- Has 172.16.1.66 shown similar behavior at other times, or authenticated to other systems?

#### F-012 — Potential DGA Domain Activity — autodiscover-s.outlook.com

- Severity: Informational | Confidence: Low | Risk score: 9/100
- Category: DNS Behavior
- Destinations: outlook.office365.com. | Domain(s): autodiscover-s.outlook.com
- Detection rule(s): DNS-003, DNS-004

**Evidence:**
- DGA heuristic score: 39/100 (confidence: Low)
- autodiscover-s.outlook.com was queried only 1 time(s) across the entire capture.

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

**What we know:**
- _Established:_ 172.16.1.66 issued 1 DNS quer(y/ies) for autodiscover-s.outlook.com, directly observed in the capture.
- _Strongly indicated:_ Multi-signal heuristic scoring (entropy, digit/vowel ratio, dictionary-word absence) is consistent with algorithmic domain generation.

**Suggested next questions:**
- Did 172.16.1.66 communicate with this infrastructure prior to this capture?
- Has 172.16.1.66 shown similar behavior at other times, or authenticated to other systems?

#### F-010 — Potential DGA Domain Activity — autodiscover.wiresharkworkshop.online

- Severity: Informational | Confidence: Low | Risk score: 11/100
- Category: DNS Behavior
- Destinations: N/A | Domain(s): autodiscover.wiresharkworkshop.online
- Detection rule(s): DNS-003, DNS-004

**Evidence:**
- DGA heuristic score: 49/100 (confidence: Medium)
- autodiscover.wiresharkworkshop.online was queried only 1 time(s) across the entire capture.

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

**What we know:**
- _Established:_ 172.16.1.66 issued 1 DNS quer(y/ies) for autodiscover.wiresharkworkshop.online, directly observed in the capture.
- _Strongly indicated:_ Multi-signal heuristic scoring (entropy, digit/vowel ratio, dictionary-word absence) is consistent with algorithmic domain generation.

**Suggested next questions:**
- Did 172.16.1.66 communicate with this infrastructure prior to this capture?
- Has 172.16.1.66 shown similar behavior at other times, or authenticated to other systems?

#### F-011 — Potential DGA Domain Activity — img-s-msn-com.akamaized.net

- Severity: Informational | Confidence: Low | Risk score: 11/100
- Category: DNS Behavior
- Destinations: a1834.dscg2.akamai.net. | Domain(s): img-s-msn-com.akamaized.net
- Detection rule(s): DNS-003, DNS-004

**Evidence:**
- DGA heuristic score: 47/100 (confidence: Medium)
- img-s-msn-com.akamaized.net was queried only 2 time(s) across the entire capture.

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

**What we know:**
- _Established:_ 172.16.1.66 issued 1 DNS quer(y/ies) for img-s-msn-com.akamaized.net, directly observed in the capture.
- _Strongly indicated:_ Multi-signal heuristic scoring (entropy, digit/vowel ratio, dictionary-word absence) is consistent with algorithmic domain generation.

**Suggested next questions:**
- Did 172.16.1.66 communicate with this infrastructure prior to this capture?
- Has 172.16.1.66 shown similar behavior at other times, or authenticated to other systems?

## 4. Investigation Recommendations

**F-001 — Suspicious Connection to ip-api.com:**
- Investigate endpoint 172.16.1.66 for signs of compromise.
- Review historical DNS logs for ip-api.com across the environment.
- Search proxy/web logs for prior connections to ip-api.com.

**F-002 — Threat Intelligence Match:**
- Investigate endpoint 172.16.1.66 for signs of compromise.
- Review historical DNS logs for github.com across the environment.
- Block the associated infrastructure at the network boundary per policy.

**F-003 — Threat Intelligence Match:**
- Investigate endpoint 172.16.1.66 for signs of compromise.
- Review historical DNS logs for objects.githubusercontent.com across the environment.
- Block the associated infrastructure at the network boundary per policy.

**F-004 — Potential DGA Domain Activity — wiresharkworkshop.online:**
- Investigate endpoint 172.16.1.66 for signs of compromise.
- Review historical DNS logs for wiresharkworkshop.online across the environment.

**F-005 — Potential DGA Domain Activity — wiresharkworkshop.online:**
- Investigate endpoint 172.16.1.66 for signs of compromise.
- Review historical DNS logs for wiresharkworkshop.online across the environment.

**F-006 — Suspicious Network Activity:**
- Investigate endpoint 172.16.1.66 for signs of compromise.
- Review historical DNS logs for wpad.wiresharkworkshop.online across the environment.

**F-007 — Potential DGA Domain Activity — desktop-skbr25f.local:**
- Investigate endpoint 172.16.1.66 for signs of compromise.
- Review historical DNS logs for desktop-skbr25f.local across the environment.

**F-008 — Potential DGA Domain Activity — desktop-skbr25f.wiresharkworkshop.online:**
- Investigate endpoint 172.16.1.66 for signs of compromise.
- Review historical DNS logs for desktop-skbr25f.wiresharkworkshop.online across the environment.

**F-009 — Potential DGA Domain Activity — wireshark-ws-dc.wiresharkworkshop.online:**
- Investigate endpoint 172.16.1.66 for signs of compromise.
- Review historical DNS logs for wireshark-ws-dc.wiresharkworkshop.online across the environment.

**F-010 — Potential DGA Domain Activity — autodiscover.wiresharkworkshop.online:**
- Investigate endpoint 172.16.1.66 for signs of compromise.
- Review historical DNS logs for autodiscover.wiresharkworkshop.online across the environment.

**F-011 — Potential DGA Domain Activity — img-s-msn-com.akamaized.net:**
- Investigate endpoint 172.16.1.66 for signs of compromise.
- Review historical DNS logs for img-s-msn-com.akamaized.net across the environment.

**F-012 — Potential DGA Domain Activity — autodiscover-s.outlook.com:**
- Investigate endpoint 172.16.1.66 for signs of compromise.
- Review historical DNS logs for autodiscover-s.outlook.com across the environment.

**F-013 — Potential DGA Domain Activity — _kerberos._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online:**
- Investigate endpoint 172.16.1.66 for signs of compromise.
- Review historical DNS logs for _kerberos._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online across the environment.

## 5. Attack Timeline

Aggregated behavioral events, not individual packets -- each row already summarizes every underlying observation it represents.

| Timestamp (UTC) | Behavioral event | Related finding |
|---|---|---|
| 02:38:48 | 172.16.1.66 queried _ldap._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online (4 time(s), 02:38:48–02:40:13) | - |
| 02:38:48 | 172.16.1.66 queried wireshark-ws-dc.wiresharkworkshop.online (2 time(s), 02:38:48–02:38:49) | F-009 |
| 02:38:48 | 172.16.1.66 queried desktop-skbr25f.local (1 time(s), 02:38:48–02:38:48) | F-007 |
| 02:38:49 | 172.16.1.66 attempted connections to 38 distinct IP(s) / 11 distinct port(s), 98% success ratio (149 attempt(s)) | F-001 |
| 02:38:49 | 172.16.1.66 queried _ldap._tcp.default-first-site-name._sites.wiresharkworkshop.online (1 time(s), 02:38:49–02:38:49) | - |
| 02:38:49 | 172.16.1.66 queried mobile.events.data.microsoft.com (4 time(s), 02:38:49–02:42:18) | - |
| 02:38:49 | 172.16.1.66 queried wiresharkworkshop.online (1 time(s), 02:38:49–02:38:49) | F-004 |
| 02:38:49 | 172.16.1.66 queried www.msftconnecttest.com (1 time(s), 02:38:49–02:38:49) | - |
| 02:38:49 | 172.16.1.66 queried wpad.wiresharkworkshop.online (8 time(s), 02:38:49–02:44:23) | F-006 |
| 02:38:49 | 172.16.1.66 → 23.215.55.140 HTTP activity to www.msftconnecttest.com (1 request(s): /connecttest.txt) | - |
| 02:38:52 | 172.16.1.66 queried go.microsoft.com (4 time(s), 02:38:52–02:38:56) | - |
| 02:38:53 | 172.16.1.66 queried _kerberos._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online (1 time(s), 02:38:53–02:38:53) | F-013 |
| 02:38:53 | 172.16.1.66 queried desktop-skbr25f.wiresharkworkshop.online (1 time(s), 02:38:53–02:38:53) | F-008 |
| 02:38:53 | 172.16.1.66 queried wiresharkworkshop.online (1 time(s), 02:38:53–02:38:53) | F-004 |
| 02:39:13 | 172.16.1.66 queried www.bing.com (1 time(s), 02:39:13–02:39:13) | - |
| 02:39:14 | 172.16.1.66 queried v20.events.data.microsoft.com (1 time(s), 02:39:14–02:39:14) | - |
| 02:39:14 | 172.16.1.66 queried arc.msn.com (1 time(s), 02:39:14–02:39:14) | - |
| 02:39:16 | 172.16.1.66 queried client.wns.windows.com (5 time(s), 02:39:16–02:39:24) | - |
| 02:39:16 | 172.16.1.66 queried assets.msn.com (6 time(s), 02:39:16–02:44:17) | - |
| 02:39:17 | 172.16.1.66 queried officeclient.microsoft.com (2 time(s), 02:39:17–02:42:11) | - |
| 02:39:17 | 172.16.1.66 queried www.msn.com (2 time(s), 02:39:17–02:44:16) | - |
| 02:39:18 | 172.16.1.66 queried odc.officeapps.live.com (2 time(s), 02:39:18–02:42:12) | - |
| 02:39:23 | 172.16.1.66 queried g.live.com (1 time(s), 02:39:23–02:39:23) | - |
| 02:39:23 | 172.16.1.66 queried oneclient.sfx.ms (1 time(s), 02:39:23–02:39:23) | - |
| 02:39:27 | 172.16.1.66 queried default.exp-tas.com (1 time(s), 02:39:27–02:39:27) | - |
| 02:39:52 | 172.16.1.66 queried github.com (1 time(s), 02:39:52–02:39:52) | F-002 |
| 02:39:52 | 172.16.1.66 queried repo1.maven.org (4 time(s), 02:39:52–02:39:56) | - |
| 02:39:53 | 172.16.1.66 queried objects.githubusercontent.com (1 time(s), 02:39:53–02:39:53) | F-003 |
| 02:40:06 | 172.16.1.66 queried ip-api.com (1 time(s), 02:40:06–02:40:06) | F-001 |
| 02:40:06 | 172.16.1.66 → 208.95.112.1 HTTP activity to ip-api.com (1 request(s): /json/) | F-001 |
| 02:40:11 | 172.16.1.66 queried settings-win.data.microsoft.com (1 time(s), 02:40:11–02:40:11) | - |
| 02:40:12 | 172.16.1.66 queried th.bing.com (2 time(s), 02:40:12–02:44:17) | - |
| 02:40:14 | 172.16.1.66 queried login.microsoftonline.com (1 time(s), 02:40:14–02:40:14) | - |
| 02:40:41 | 172.16.1.66 queried _ldap._tcp.default-first-site-name._sites.wireshark-ws-dc.wiresharkworkshop.online (2 time(s), 02:40:41–02:44:16) | - |
| 02:40:41 | 172.16.1.66 queried _ldap._tcp.wireshark-ws-dc.wiresharkworkshop.online (2 time(s), 02:40:41–02:44:16) | - |
| 02:40:41 | 172.16.1.66 queried fd.api.iris.microsoft.com (4 time(s), 02:40:41–02:40:45) | - |
| 02:40:41 | 172.16.1.66 queried msedge.api.cdp.microsoft.com (1 time(s), 02:40:41–02:40:41) | - |
| 02:40:42 | 172.16.1.66 queried config.edge.skype.com (1 time(s), 02:40:42–02:40:42) | - |
| 02:42:12 | 172.16.1.66 queried ecs.office.com (1 time(s), 02:42:12–02:42:12) | - |
| 02:42:13 | 172.16.1.66 queried autodiscover-s.outlook.com (1 time(s), 02:42:13–02:42:13) | F-012 |
| 02:42:13 | 172.16.1.66 queried _gc._tcp.default-first-site-name._sites.wiresharkworkshop.online (1 time(s), 02:42:13–02:42:13) | - |
| 02:42:15 | 172.16.1.66 queried autodiscover.wiresharkworkshop.online (1 time(s), 02:42:15–02:42:15) | F-010 |
| 02:42:25 | 172.16.1.66 queried metadata.templates.cdn.office.net (1 time(s), 02:42:25–02:42:25) | - |
| 02:42:35 | 172.16.1.66 queried v10.events.data.microsoft.com (1 time(s), 02:42:35–02:42:35) | - |
| 02:44:15 | 172.16.1.66 queried windows.msn.com (1 time(s), 02:44:15–02:44:15) | - |
| 02:44:15 | 172.16.1.66 queried windows.msn.com (1 time(s), 02:44:15–02:44:15) | - |
| 02:44:16 | 172.16.1.66 queried www.msn.com (1 time(s), 02:44:16–02:44:16) | - |
| 02:44:17 | 172.16.1.66 queried api.msn.com (1 time(s), 02:44:17–02:44:17) | - |
| 02:44:17 | 172.16.1.66 queried api.msn.com (1 time(s), 02:44:17–02:44:17) | - |
| 02:44:17 | 172.16.1.66 queried assets.msn.com (1 time(s), 02:44:17–02:44:17) | - |
| 02:44:17 | 172.16.1.66 queried srtb.msn.com (1 time(s), 02:44:17–02:44:17) | - |
| 02:44:17 | 172.16.1.66 queried srtb.msn.com (1 time(s), 02:44:17–02:44:17) | - |
| 02:44:17 | 172.16.1.66 queried th.bing.com (1 time(s), 02:44:17–02:44:17) | - |
| 02:44:17 | 172.16.1.66 queried img-s-msn-com.akamaized.net (1 time(s), 02:44:17–02:44:17) | F-011 |
| 02:44:17 | 172.16.1.66 queried img-s-msn-com.akamaized.net (1 time(s), 02:44:17–02:44:17) | F-011 |
| 02:44:17 | 172.16.1.66 queried ecn.dev.virtualearth.net (1 time(s), 02:44:17–02:44:17) | - |
| 02:44:17 | 172.16.1.66 queried ecn.dev.virtualearth.net (1 time(s), 02:44:17–02:44:17) | - |
| 02:44:29 | 172.16.1.66 queried javadl-esd-secure.oracle.com (2 time(s), 02:44:29–02:44:29) | - |
| 02:47:19 | 172.16.1.66 queried pti.store.microsoft.com (2 time(s), 02:47:19–02:47:20) | - |

## 6. Attack Chain / Kill-Chain View

**F-001 — Suspicious Connection to ip-api.com**

```
DNS (ip-api.com)
  ↓
HTTP connection (ip-api.com)
  ↓
Threat Intelligence
```
MITRE tactics: Discovery

## 7. Entity / Infrastructure Summary

### Internal entities

| IP | Related finding(s) |
|---|---|
| 172.16.1.255 | - |
| 172.16.1.4 | - |
| 172.16.1.66 | F-001, F-002, F-003, F-004, F-005, F-006, F-007, F-008, F-009, F-010, F-011, F-012, F-013 |
| 224.0.0.22 | - |
| 224.0.0.251 | - |
| 224.0.0.252 | - |
| 239.255.255.250 | - |

### External entities

| IP | Related finding(s) | TI state(s) |
|---|---|---|
| 13.107.42.16 | - | CLEAN |
| 13.107.5.93 | - | CLEAN, WEAK_REPUTATION |
| 13.69.239.79 | - | CLEAN |
| 140.82.113.3 | F-002 | CLEAN, WEAK_REPUTATION |
| 141.98.10.79 | - | MALICIOUS, SUSPICIOUS |
| 185.199.110.133 | F-003 | CLEAN, SUSPICIOUS |
| 199.232.196.209 | - | CLEAN |
| 20.166.2.191 | - | CLEAN |
| 20.189.173.10 | - | CLEAN |
| 20.189.173.16 | - | CLEAN |
| 20.189.173.26 | - | CLEAN |
| 20.241.44.114 | - | CLEAN |
| 20.7.1.246 | - | CLEAN |
| 20.7.2.167 | - | CLEAN |
| 20.96.153.111 | - | CLEAN, WEAK_REPUTATION |
| 204.79.197.203 | - | CLEAN, WEAK_REPUTATION |
| 208.95.112.1 | F-001 | SUSPICIOUS, WEAK_REPUTATION |
| 23.194.164.136 | - | CLEAN |
| 23.198.7.168 | - | CLEAN |
| 23.198.7.175 | - | CLEAN |
| 23.198.7.177 | - | CLEAN |
| 23.215.55.133 | - | CLEAN |
| 23.215.55.140 | - | CLEAN |
| 23.221.22.68 | - | CLEAN |
| 23.46.192.165 | - | CLEAN |
| 23.48.203.203 | - | CLEAN |
| 23.48.203.208 | - | CLEAN |
| 23.52.9.140 | - | CLEAN |
| 23.52.9.222 | - | CLEAN |
| 23.53.11.166 | - | CLEAN |

## 8. Threat Intelligence Summary

- Indicators analyzed: 88
- Meaningful TI matches (Suspicious/Malicious): 6
- Weak reputation (not a finding on its own): 14
- Clean / no meaningful record: 194

**Meaningful indicators only** (full raw results, including no-record lookups, are in Section 13.2):

| IOC | Feed | State | Confidence | Summary |
|---|---|---|---|---|
| 141.98.10.79 | AbuseIPDB | SUSPICIOUS | Medium | AbuseIPDB abuse confidence 60/100 from 298 report(s), last reported 19d ago. Interpreted as Suspicious. |
| 141.98.10.79 | VirusTotal | MALICIOUS | High | VirusTotal: 6/89 vendor(s) flagged malicious, 1 suspicious. Interpreted as Malicious. |
| 185.199.110.133 | AbuseIPDB | SUSPICIOUS | Medium | AbuseIPDB abuse confidence 26/100 from 9 report(s), last reported 6d ago. Interpreted as Suspicious. |
| 208.95.112.1 | AbuseIPDB | SUSPICIOUS | Medium | AbuseIPDB abuse confidence 33/100 from 12 report(s), last reported 7d ago. Interpreted as Suspicious. |
| github.com | URLhaus | MALICIOUS | High | URLhaus record found (status: online, threat: malware_download). Interpreted as Malicious. |
| objects.githubusercontent.com | URLhaus | MALICIOUS | Medium | URLhaus record found (status: offline, threat: malware_download). Interpreted as Malicious. |


## 9. Technical Evidence

Raw observations: 176 DNS record(s), 4 HTTP record(s), 0 file transfer(s), 11562 raw packet(s) — aggregated below into 56 DNS behavioral event(s), 2 HTTP behavioral event(s), 0 distinct file behavioral event(s), and 49 TCP connection-attempt behavioral event(s).

### Protocol / traffic distribution

| Protocol | Packet Count |
|---|---|
| UDP | 243 |
| IP-PROTO-2 | 9 |
| Ether | 31 |
| TCP | 11276 |
| IP-PROTO-1 | 3 |

### DNS behavioral events

| Source | Domain | Type | Occurrences | NXDOMAIN % | Resolved IP(s) | First seen | Last seen |
|---|---|---|---|---|---|---|---|
| 172.16.1.66 | wpad.wiresharkworkshop.online | A | 8 | 100% | - | 02:38:49 | 02:44:23 |
| 172.16.1.66 | assets.msn.com | A | 6 | 0% | assets.msn.com.edgekey.net. | 02:39:16 | 02:44:17 |
| 172.16.1.66 | client.wns.windows.com | A | 5 | 0% | wns.notify.trafficmanager.net. | 02:39:16 | 02:39:24 |
| 172.16.1.66 | _ldap._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online | 33 | 4 | 0% | - | 02:38:48 | 02:40:13 |
| 172.16.1.66 | fd.api.iris.microsoft.com | A | 4 | 0% | fd-api-iris.trafficmanager.net. | 02:40:41 | 02:40:45 |
| 172.16.1.66 | go.microsoft.com | A | 4 | 0% | go.microsoft.com.edgekey.net. | 02:38:52 | 02:38:56 |
| 172.16.1.66 | mobile.events.data.microsoft.com | A | 4 | 0% | mobile.events.data.trafficmanager.net. | 02:38:49 | 02:42:18 |
| 172.16.1.66 | repo1.maven.org | A | 4 | 0% | dualstack.sonatype.map.fastly.net. | 02:39:52 | 02:39:56 |
| 172.16.1.66 | _ldap._tcp.default-first-site-name._sites.wireshark-ws-dc.wiresharkworkshop.online | 33 | 2 | 100% | - | 02:40:41 | 02:44:16 |
| 172.16.1.66 | _ldap._tcp.wireshark-ws-dc.wiresharkworkshop.online | 33 | 2 | 100% | - | 02:40:41 | 02:44:16 |
| 172.16.1.66 | javadl-esd-secure.oracle.com | A | 2 | 0% | javadl-esd-secure.oracle.com.edgekey.net. | 02:44:29 | 02:44:29 |
| 172.16.1.66 | odc.officeapps.live.com | A | 2 | 0% | prod.odcsm1.live.com.akadns.net. | 02:39:18 | 02:42:12 |
| 172.16.1.66 | officeclient.microsoft.com | A | 2 | 0% | config.officeapps.live.com. | 02:39:17 | 02:42:11 |
| 172.16.1.66 | pti.store.microsoft.com | A | 2 | 50% | - | 02:47:19 | 02:47:20 |
| 172.16.1.66 | th.bing.com | A | 2 | 0% | p-th.bing.com.trafficmanager.net. | 02:40:12 | 02:44:17 |
| 172.16.1.66 | wireshark-ws-dc.wiresharkworkshop.online | A | 2 | 0% | 172.16.1.4 | 02:38:48 | 02:38:49 |
| 172.16.1.66 | www.msn.com | A | 2 | 0% | www-msn-com.a-0003.a-msedge.net. | 02:39:17 | 02:44:16 |
| 172.16.1.66 | _gc._tcp.default-first-site-name._sites.wiresharkworkshop.online | 33 | 1 | 0% | - | 02:42:13 | 02:42:13 |
| 172.16.1.66 | _kerberos._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online | 33 | 1 | 0% | - | 02:38:53 | 02:38:53 |
| 172.16.1.66 | _ldap._tcp.default-first-site-name._sites.wiresharkworkshop.online | 33 | 1 | 0% | - | 02:38:49 | 02:38:49 |
| 172.16.1.66 | api.msn.com | A | 1 | 0% | api-msn-com.a-0003.a-msedge.net. | 02:44:17 | 02:44:17 |
| 172.16.1.66 | api.msn.com | 65 | 1 | 0% | api-msn-com.a-0003.a-msedge.net. | 02:44:17 | 02:44:17 |
| 172.16.1.66 | arc.msn.com | A | 1 | 0% | arc.trafficmanager.net. | 02:39:14 | 02:39:14 |
| 172.16.1.66 | assets.msn.com | 65 | 1 | 0% | assets.msn.com.edgekey.net. | 02:44:17 | 02:44:17 |
| 172.16.1.66 | autodiscover-s.outlook.com | A | 1 | 0% | outlook.office365.com. | 02:42:13 | 02:42:13 |
| 172.16.1.66 | autodiscover.wiresharkworkshop.online | A | 1 | 100% | - | 02:42:15 | 02:42:15 |
| 172.16.1.66 | config.edge.skype.com | A | 1 | 0% | config.edge.skype.com.trafficmanager.net. | 02:40:42 | 02:40:42 |
| 172.16.1.66 | default.exp-tas.com | A | 1 | 0% | deault-exp-tas-com.e-0014.e-msedge.net. | 02:39:27 | 02:39:27 |
| 172.16.1.66 | desktop-skbr25f.local | 255 | 1 | 0% | - | 02:38:48 | 02:38:48 |
| 172.16.1.66 | desktop-skbr25f.wiresharkworkshop.online | SOA | 1 | 0% | - | 02:38:53 | 02:38:53 |
| 172.16.1.66 | ecn.dev.virtualearth.net | A | 1 | 0% | ssl2.tiles.virtualearth.net.edgekey.net. | 02:44:17 | 02:44:17 |
| 172.16.1.66 | ecn.dev.virtualearth.net | 65 | 1 | 0% | ssl2.tiles.virtualearth.net.edgekey.net. | 02:44:17 | 02:44:17 |
| 172.16.1.66 | ecs.office.com | A | 1 | 0% | ecs.office.trafficmanager.net. | 02:42:12 | 02:42:12 |
| 172.16.1.66 | g.live.com | A | 1 | 0% | g.msn.com. | 02:39:23 | 02:39:23 |
| 172.16.1.66 | github.com | A | 1 | 0% | 140.82.113.3 | 02:39:52 | 02:39:52 |
| 172.16.1.66 | img-s-msn-com.akamaized.net | A | 1 | 0% | a1834.dscg2.akamai.net. | 02:44:17 | 02:44:17 |
| 172.16.1.66 | img-s-msn-com.akamaized.net | 65 | 1 | 0% | a1834.dscg2.akamai.net. | 02:44:17 | 02:44:17 |
| 172.16.1.66 | ip-api.com | A | 1 | 0% | 208.95.112.1 | 02:40:06 | 02:40:06 |
| 172.16.1.66 | login.microsoftonline.com | A | 1 | 0% | login.mso.msidentity.com. | 02:40:14 | 02:40:14 |
| 172.16.1.66 | metadata.templates.cdn.office.net | A | 1 | 0% | templatesmetadata.office.net. | 02:42:25 | 02:42:25 |
| 172.16.1.66 | msedge.api.cdp.microsoft.com | A | 1 | 0% | api.cdp.microsoft.com. | 02:40:41 | 02:40:41 |
| 172.16.1.66 | objects.githubusercontent.com | A | 1 | 0% | 185.199.110.133 | 02:39:53 | 02:39:53 |
| 172.16.1.66 | oneclient.sfx.ms | A | 1 | 0% | oneclient.sfx.ms.edgekey.net. | 02:39:23 | 02:39:23 |
| 172.16.1.66 | settings-win.data.microsoft.com | A | 1 | 0% | atm-settingsfe-prod-geo2.trafficmanager.net. | 02:40:11 | 02:40:11 |
| 172.16.1.66 | srtb.msn.com | A | 1 | 0% | www.msn.com. | 02:44:17 | 02:44:17 |
| 172.16.1.66 | srtb.msn.com | 65 | 1 | 0% | www.msn.com. | 02:44:17 | 02:44:17 |
| 172.16.1.66 | th.bing.com | 65 | 1 | 0% | p-th.bing.com.trafficmanager.net. | 02:44:17 | 02:44:17 |
| 172.16.1.66 | v10.events.data.microsoft.com | A | 1 | 0% | win-global-asimov-leafs-events-data.trafficmanager.net. | 02:42:35 | 02:42:35 |
| 172.16.1.66 | v20.events.data.microsoft.com | A | 1 | 0% | win-global-asimov-leafs-events-data.trafficmanager.net. | 02:39:14 | 02:39:14 |
| 172.16.1.66 | windows.msn.com | A | 1 | 0% | www-msn-com.a-0003.a-msedge.net. | 02:44:15 | 02:44:15 |
| 172.16.1.66 | windows.msn.com | 65 | 1 | 0% | www-msn-com.a-0003.a-msedge.net. | 02:44:15 | 02:44:15 |
| 172.16.1.66 | wiresharkworkshop.online | A | 1 | 0% | 172.16.1.4 | 02:38:49 | 02:38:49 |
| 172.16.1.66 | wiresharkworkshop.online | SOA | 1 | 0% | . | 02:38:53 | 02:38:53 |
| 172.16.1.66 | www.bing.com | A | 1 | 0% | www-www.bing.com.trafficmanager.net. | 02:39:13 | 02:39:13 |
| 172.16.1.66 | www.msftconnecttest.com | A | 1 | 0% | ncsi-geo.trafficmanager.net. | 02:38:49 | 02:38:49 |
| 172.16.1.66 | www.msn.com | 65 | 1 | 0% | www-msn-com.a-0003.a-msedge.net. | 02:44:16 | 02:44:16 |

### HTTP behavioral events

| Source | Destination | Host | Requests | Path(s) | User-Agent |
|---|---|---|---|---|---|
| 172.16.1.66 | 208.95.112.1 | ip-api.com | 1 | /json/ | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36 |
| 172.16.1.66 | 23.215.55.140 | www.msftconnecttest.com | 1 | /connecttest.txt | Microsoft NCSI |

### File transfer behavioral events

No complete files could be reassembled from the supplied PCAP.

### TCP connection-attempt behavioral events

| Source | Destination | Port | SYN | SYN-ACK | RST | Bytes src→dst | Bytes dst→src |
|---|---|---|---|---|---|---|---|
| 172.16.1.66 | 172.16.1.4 | 88 | 28 | 28 | 28 | 45,418 | 51,141 |
| 172.16.1.66 | 172.16.1.4 | 389 | 22 | 22 | 34 | 73,080 | 61,934 |
| 172.16.1.66 | 23.52.9.222 | 443 | 11 | 11 | 0 | 38,495 | 27,234 |
| 172.16.1.66 | 172.16.1.4 | 135 | 8 | 8 | 3 | 6,416 | 6,324 |
| 172.16.1.66 | 172.16.1.4 | 49667 | 7 | 7 | 3 | 31,428 | 15,507 |
| 172.16.1.66 | 204.79.197.203 | 443 | 7 | 7 | 4 | 19,994 | 70,677 |
| 172.16.1.66 | 23.198.7.177 | 443 | 6 | 6 | 0 | 8,228 | 57,150 |
| 172.16.1.66 | 172.16.1.4 | 139 | 5 | 5 | 0 | 8,991 | 9,817 |
| 172.16.1.66 | 172.16.1.4 | 443 | 5 | 0 | 5 | 330 | 270 |
| 172.16.1.66 | 23.48.203.208 | 443 | 4 | 4 | 4 | 7,656 | 106,085 |
| 172.16.1.66 | 52.109.20.47 | 443 | 4 | 4 | 4 | 5,306 | 32,929 |
| 172.16.1.66 | 172.16.1.4 | 445 | 3 | 3 | 1 | 50,409 | 40,347 |
| 172.16.1.66 | 199.232.196.209 | 443 | 3 | 3 | 3 | 26,728 | 8,868,103 |
| 172.16.1.66 | 23.198.7.175 | 443 | 2 | 2 | 1 | 20,371 | 108,514 |
| 172.16.1.66 | 40.126.29.14 | 443 | 2 | 2 | 2 | 4,014 | 12,351 |
| 172.16.1.66 | 52.109.0.142 | 443 | 2 | 2 | 1 | 4,298 | 19,062 |
| 172.16.1.66 | 13.107.42.16 | 443 | 1 | 1 | 0 | 3,584 | 8,269 |
| 172.16.1.66 | 13.107.5.93 | 443 | 1 | 1 | 1 | 1,817 | 15,467 |
| 172.16.1.66 | 13.69.239.79 | 443 | 1 | 1 | 0 | 2,728 | 5,492 |
| 172.16.1.66 | 140.82.113.3 | 443 | 1 | 1 | 1 | 1,392 | 8,491 |
| 172.16.1.66 | 141.98.10.79 | 12132 | 1 | 1 | 0 | 27,990 | 11,074 |
| 172.16.1.66 | 172.16.1.4 | 3268 | 1 | 1 | 2 | 3,388 | 3,995 |
| 172.16.1.66 | 172.16.1.4 | 49695 | 1 | 1 | 0 | 3,075 | 2,168 |
| 172.16.1.66 | 185.199.110.133 | 443 | 1 | 1 | 1 | 5,068 | 828,901 |
| 172.16.1.66 | 20.166.2.191 | 443 | 1 | 1 | 0 | 4,270 | 5,620 |
| 172.16.1.66 | 20.189.173.10 | 443 | 1 | 1 | 1 | 26,814 | 8,642 |
| 172.16.1.66 | 20.189.173.16 | 443 | 1 | 1 | 0 | 12,878 | 8,208 |
| 172.16.1.66 | 20.189.173.26 | 443 | 1 | 1 | 0 | 61,918 | 8,456 |
| 172.16.1.66 | 20.241.44.114 | 443 | 1 | 1 | 1 | 1,228 | 7,281 |
| 172.16.1.66 | 20.7.2.167 | 443 | 1 | 1 | 0 | 3,677 | 6,432 |
| 172.16.1.66 | 20.96.153.111 | 443 | 1 | 1 | 0 | 2,576 | 7,320 |
| 172.16.1.66 | 208.95.112.1 | 80 | 1 | 1 | 0 | 470 | 691 |
| 172.16.1.66 | 23.194.164.136 | 443 | 1 | 1 | 1 | 1,399 | 47,462 |
| 172.16.1.66 | 23.198.7.168 | 443 | 1 | 1 | 1 | 3,889 | 43,920 |
| 172.16.1.66 | 23.215.55.133 | 443 | 1 | 1 | 1 | 3,232 | 6,848 |
| 172.16.1.66 | 23.215.55.140 | 80 | 1 | 1 | 0 | 393 | 407 |
| 172.16.1.66 | 23.221.22.68 | 443 | 1 | 1 | 1 | 1,613 | 5,880 |
| 172.16.1.66 | 23.46.192.165 | 443 | 1 | 1 | 1 | 3,372 | 26,849 |
| 172.16.1.66 | 23.48.203.203 | 443 | 1 | 1 | 1 | 1,822 | 12,832 |
| 172.16.1.66 | 23.52.9.140 | 443 | 1 | 1 | 1 | 1,451 | 10,790 |

## 10. IOC Inventory

This inventory lists every indicator extracted from the capture. Listing an indicator here does **not** imply it is malicious -- see the significance tier and Section 3 for which indicators actually became findings.

| Tier | Count |
|---|---|
| Insignificant | 74 |
| Noteworthy | 10 |
| Suspicious | 4 |
| High-Priority | 0 |


**Noteworthy and above:**

| Indicator | Type | Tier | Significance | Detection rule(s) | TI state(s) |
|---|---|---|---|---|---|
| 141.98.10.79 | ipv4 | suspicious | 44 | - | AbuseIPDB:SUSPICIOUS, VirusTotal:MALICIOUS |
| wiresharkworkshop.online | domain | suspicious | 33 | DNS-003, DNS-004, DNS-007 | VirusTotal:WEAK_REPUTATION |
| github.com | domain | suspicious | 30 | DNS-004 | URLhaus:MALICIOUS, VirusTotal:CLEAN |
| objects.githubusercontent.com | domain | suspicious | 30 | DNS-004 | URLhaus:MALICIOUS, VirusTotal:CLEAN |

## 11. Detection Coverage Self-Test

For each conceptual detection category, whether it was detected IN THIS CAPTURE (not whether the capability generally exists) -- and, for categories genuinely not implemented in this build, that is stated plainly rather than silently omitted.

| Category | Rule(s) | Detected? | Signal count | Max confidence |
|---|---|---|---|---|
| Port/Host Scanning | NET-001, NET-002 | No | 0 | N/A |
| Credential/Brute-Force-Adjacent Activity | NET-003 | No | 0 | N/A |
| Data Exfiltration (volume heuristic) | NET-004 | No | 0 | N/A |
| DNS Anomalies (frequency/NXDOMAIN) | DNS-001, DNS-002 | Yes | 2 | Medium |
| Domain Generation Algorithm (DGA) | DNS-003 | Yes | 10 | Medium |
| DNS Tunneling | DNS-006 | No | 0 | N/A |
| Fast-Flux DNS | DNS-008 | No | 0 | N/A |
| Rare/Newly-Observed Domains | DNS-004, DNS-005 | Yes | 36 | Low |
| Excessive Subdomain Enumeration | DNS-007 | Yes | 2 | Medium |
| Suspicious Executable/Script Download | HTTP-001, HTTP-002 | No | 0 | N/A |
| Suspicious User-Agent | HTTP-003 | No | 0 | N/A |
| Suspicious Download Source | HTTP-005 | No | 0 | N/A |
| Executable/MIME Mismatch | HTTP-006 | No | 0 | N/A |
| Repeated Payload Retrieval | HTTP-007 | No | 0 | N/A |
| Web Application Attack Patterns (SQLi/traversal/XSS/LFI-RFI) | HTTP-008 | No | 0 | N/A |
| Suspicious File Signature | FILE-001 | No | 0 | N/A |
| Beaconing / C2-style Periodicity | BEACON-001 | No | 0 | N/A |
| TLS/JA3 Fingerprinting | - | Not implemented | 0 | N/A |
| Protocol-level Credential Brute-Force (SSH/FTP/RDP/SMB decode) | - | Not implemented | 0 | N/A |
| Certificate Anomaly Detection | - | Not implemented | 0 | N/A |


## 12. Unclassified / Observed Traffic

Notable-volume activity that no detection rule flagged. This is visibility, not a finding -- absence of a rule match does not mean the activity is safe, only that it did not meet any implemented rule's threshold.

| Protocol | Source | Destination/Domain | Volume |
|---|---|---|---|
| TCP | 172.16.1.66 | 38 dest IP(s) | 149 |
| DNS | 172.16.1.66 | assets.msn.com | 6 |
| DNS | 172.16.1.66 | client.wns.windows.com | 5 |
| DNS | 172.16.1.66 | _ldap._tcp.default-first-site-name._sites.dc._msdcs.wiresharkworkshop.online | 4 |
| DNS | 172.16.1.66 | fd.api.iris.microsoft.com | 4 |
| DNS | 172.16.1.66 | go.microsoft.com | 4 |
| DNS | 172.16.1.66 | mobile.events.data.microsoft.com | 4 |
| DNS | 172.16.1.66 | repo1.maven.org | 4 |

## 13. Appendix

### 13.1 Threat-intelligence summary

- Indicators analyzed: 88
- Meaningful TI matches (Suspicious/Malicious): 6
- Weak reputation (not a finding on its own): 14
- Clean / no meaningful record: 194

### 13.2 Raw threat-intelligence results (including no-record lookups)

| IOC | Feed | State | Confidence | Summary |
|---|---|---|---|---|
| 13.107.42.16 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 428d ago. Interpreted as Clean. |
| 13.107.42.16 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 13.107.42.16 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 13.107.5.93 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 3/100 from 14 report(s), last reported 19d ago. Interpreted as Weak Reputation. |
| 13.107.5.93 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 13.107.5.93 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 13.69.239.79 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 101d ago. Interpreted as Clean. |
| 13.69.239.79 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 13.69.239.79 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 140.82.113.3 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 1 report(s), last reported 43d ago. Interpreted as Weak Reputation. |
| 140.82.113.3 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 140.82.113.3 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 141.98.10.79 | AbuseIPDB | SUSPICIOUS | Medium | AbuseIPDB abuse confidence 60/100 from 298 report(s), last reported 19d ago. Interpreted as Suspicious. |
| 141.98.10.79 | VirusTotal | MALICIOUS | High | VirusTotal: 6/89 vendor(s) flagged malicious, 1 suspicious. Interpreted as Malicious. |
| 141.98.10.79 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 185.199.110.133 | AbuseIPDB | SUSPICIOUS | Medium | AbuseIPDB abuse confidence 26/100 from 9 report(s), last reported 6d ago. Interpreted as Suspicious. |
| 185.199.110.133 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 185.199.110.133 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 199.232.196.209 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 447d ago. Interpreted as Clean. |
| 199.232.196.209 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 199.232.196.209 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.166.2.191 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 787d ago. Interpreted as Clean. |
| 20.166.2.191 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.166.2.191 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.189.173.10 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 120d ago. Interpreted as Clean. |
| 20.189.173.10 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.189.173.10 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.189.173.16 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 116d ago. Interpreted as Clean. |
| 20.189.173.16 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.189.173.16 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.189.173.26 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 115d ago. Interpreted as Clean. |
| 20.189.173.26 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.189.173.26 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.241.44.114 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 417d ago. Interpreted as Clean. |
| 20.241.44.114 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.241.44.114 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.7.1.246 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 498d ago. Interpreted as Clean. |
| 20.7.1.246 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.7.1.246 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.7.2.167 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 538d ago. Interpreted as Clean. |
| 20.7.2.167 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.7.2.167 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.96.153.111 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 1 report(s), last reported 82d ago. Interpreted as Weak Reputation. |
| 20.96.153.111 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.96.153.111 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 204.79.197.203 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 9/100 from 6 report(s), last reported 18d ago. Interpreted as Weak Reputation. |
| 204.79.197.203 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 204.79.197.203 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 208.95.112.1 | AbuseIPDB | SUSPICIOUS | Medium | AbuseIPDB abuse confidence 33/100 from 12 report(s), last reported 7d ago. Interpreted as Suspicious. |
| 208.95.112.1 | VirusTotal | WEAK_REPUTATION | Low | VirusTotal: 1/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Weak Reputation. |
| 208.95.112.1 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.194.164.136 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.194.164.136 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.194.164.136 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.198.7.168 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.198.7.168 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.198.7.168 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.198.7.175 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.198.7.175 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.198.7.175 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.198.7.177 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.198.7.177 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.198.7.177 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.215.55.133 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.215.55.133 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.215.55.133 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.215.55.140 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.215.55.140 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.215.55.140 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.221.22.68 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.221.22.68 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.221.22.68 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.46.192.165 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.46.192.165 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.46.192.165 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.48.203.203 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.48.203.203 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.48.203.203 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.48.203.208 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.48.203.208 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.48.203.208 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.52.9.140 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.52.9.140 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.52.9.140 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.52.9.222 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.52.9.222 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.52.9.222 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.53.11.166 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.53.11.166 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.53.11.166 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 40.126.29.14 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 13/100 from 88 report(s), last reported 19d ago. Interpreted as Weak Reputation. |
| 40.126.29.14 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 40.126.29.14 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 40.97.199.114 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 40.97.199.114 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 40.97.199.114 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 52.109.0.142 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 3 report(s), last reported 35d ago. Interpreted as Weak Reputation. |
| 52.109.0.142 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 52.109.0.142 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 52.109.0.91 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 512d ago. Interpreted as Clean. |
| 52.109.0.91 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 52.109.0.91 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 52.109.20.47 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 22/100 from 18 report(s), last reported 3d ago. Interpreted as Weak Reputation. |
| 52.109.20.47 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 52.109.20.47 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 52.109.6.53 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 517d ago. Interpreted as Clean. |
| 52.109.6.53 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 52.109.6.53 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 52.113.194.132 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 2 report(s), last reported 52d ago. Interpreted as Weak Reputation. |
| 52.113.194.132 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 52.113.194.132 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 52.191.219.104 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 141d ago. Interpreted as Clean. |
| 52.191.219.104 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 52.191.219.104 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| DESKTOP-SKBR25F.local | VirusTotal | UNKNOWN | Low | VirusTotal lookup was unavailable at scan time (not a clean verdict). |
| DESKTOP-SKBR25F.local | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| DESKTOP-SKBR25F.wiresharkworkshop.online | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| DESKTOP-SKBR25F.wiresharkworkshop.online | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| WIRESHARK-WS-DC.wiresharkworkshop.online | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| WIRESHARK-WS-DC.wiresharkworkshop.online | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| _gc._tcp.Default-First-Site-Name._sites.wiresharkworkshop.online | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| _gc._tcp.Default-First-Site-Name._sites.wiresharkworkshop.online | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| _kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.wiresharkworkshop.online | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| _kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.wiresharkworkshop.online | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| _ldap._tcp.Default-First-Site-Name._sites.WIRESHARK-WS-DC.wiresharkworkshop.online | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| _ldap._tcp.Default-First-Site-Name._sites.WIRESHARK-WS-DC.wiresharkworkshop.online | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.wiresharkworkshop.online | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.wiresharkworkshop.online | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| _ldap._tcp.Default-First-Site-Name._sites.wiresharkworkshop.online | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| _ldap._tcp.Default-First-Site-Name._sites.wiresharkworkshop.online | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| _ldap._tcp.WIRESHARK-WS-DC.wiresharkworkshop.online | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| _ldap._tcp.WIRESHARK-WS-DC.wiresharkworkshop.online | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| api.msn.com | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| api.msn.com | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| arc.msn.com | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| arc.msn.com | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| assets.msn.com | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| assets.msn.com | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| autodiscover-s.outlook.com | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| autodiscover-s.outlook.com | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| autodiscover.wiresharkworkshop.online | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| autodiscover.wiresharkworkshop.online | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| client.wns.windows.com | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| client.wns.windows.com | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| config.edge.skype.com | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| config.edge.skype.com | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| default.exp-tas.com | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| default.exp-tas.com | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| ecn.dev.virtualearth.net | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| ecn.dev.virtualearth.net | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |

### 13.3 Suppressed and low-confidence detection signals

| Rule | Indicator | Suppression reason | Matched allowlist entry | Occurrences |
|---|---|---|---|---|
| DNS-003 | settings-win.data.microsoft.com | known_legitimate_infrastructure | microsoft.com | 1 |
| DNS-007 | microsoft.com | known_legitimate_infrastructure | microsoft.com | 20 |

### 13.4 Detection tuning report

| Rule | Title | Triggered | Suppressed | In findings | Avg. confidence | Avg. score |
|---|---|---|---|---|---|---|
| DNS-001 | Excessive DNS Frequency | 1 | 0 | 1 | Medium | 6.0 |
| DNS-002 | High NXDOMAIN Ratio | 1 | 0 | 1 | Medium | 10.0 |
| DNS-003 | Potential Algorithmically Generated Domain | 11 | 1 | 9 | Medium | 8.7 |
| DNS-004 | Rare External Domain | 36 | 0 | 12 | Low | 2.0 |
| DNS-007 | Excessive Unique Subdomains | 3 | 1 | 2 | Medium | 10.0 |
| HTTP-004 | Rare External Host | 1 | 0 | 1 | Low | 2.0 |

### 13.5 Observability / pipeline statistics

| Metric | Count |
|---|---|
| Raw packets | 11562 |
| Raw DNS observations | 176 |
| Raw HTTP observations | 4 |
| Raw file observations | 0 |
| Behavioral events (DNS) | 56 |
| Behavioral events (HTTP) | 2 |
| Behavioral events (File) | 0 |
| Behavioral events (Connection) | 49 |
| Detection signals raised | 53 |
| Detection signals suppressed | 2 |
| Correlation candidates evaluated | 56 |
| Findings before deduplication | 14 |
| Findings after deduplication | 13 |
| Incidents | 1 |

### 13.6 Limitations

- Encrypted traffic cannot be inspected beyond metadata.
- TLS/JA3 fingerprinting, certificate inspection, and protocol-level decoding of SSH/FTP/RDP/SMB are NOT implemented -- this parser has no TLS or those protocols' layers available, so NET-003 (repeated authentication-service connection attempts) reports connection-level evidence only and explicitly does not claim any credential was actually attempted.
- DNS query<->response pairing uses the DNS transaction ID when present, which is exact; only when a response's transaction ID has no matching outstanding query in this capture does resolution data fall back to being merged into every client bucket for the same (domain, query type) pair.
- The apex-domain grouping used for DNS-006/007 is a last-two-labels/public-suffix-list approximation (see analyzer/public_suffixes.py) and may not cover every ccTLD.
- DNS-005's 'newly observed' baseline is local to this tool's own history (cache/domain_history.json), not a commercial passive-DNS/domain-age feed -- it starts empty and becomes more useful as more captures are analyzed.
- DNS-008 fast-flux and NET-001/002 scan detection have no ASN/geolocation diversity signal available in this environment; they rely on distinct-IP/port counts and timing.
- NET-004 (possible data exfiltration) is a byte-volume/asymmetry heuristic only -- it does not inspect payload content and cannot confirm what, if anything, was transferred.
- HTTP-008 (web attack request patterns) matches request structure only; it does not inspect server responses and cannot establish whether any attempt succeeded.
- Asset context (Section 3's affected-endpoint notes, and the Asset Context risk dimension) is populated from config/assets.yaml; an IP with no entry there is always reported as 'Asset role: Unknown' rather than guessed.
- Threat-intelligence feeds are rate-limited and may be unavailable at scan time; the report states this explicitly rather than treating an unavailable feed as a clean result.
- The risk score is a project-defined prioritization aid, not an industry-standard rating, and a single indicator match is never proof of compromise on its own.

### 13.7 References

- AbuseIPDB — <https://www.abuseipdb.com>
- VirusTotal — <https://www.virustotal.com>
- URLhaus (abuse.ch) — <https://urlhaus.abuse.ch>
- MITRE ATT&CK — <https://attack.mitre.org>

## Conclusion

This analysis identified findings of Low or Medium severity only. None reached High or Critical severity; the correlated evidence above warrants routine follow-up consistent with local SOC procedure.
