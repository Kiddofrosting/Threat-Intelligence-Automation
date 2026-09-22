# Threat Intelligence & Network Security Analysis Report

- **PCAP file:** `pcaps/sample.pcap`
- **Analysis date:** 2026-09-22 23:30 UTC
- **Tool:** Threat Intelligence Automation Tool v2.0.0
- **Analyst:** SOC Analyst

---

## 1. Executive Summary

**Status:** LOW-SEVERITY ACTIVITY OBSERVED

- Packets analyzed: 15512
- Unique source IPs: 99
- Unique destination IPs: 102
- Unique public IP indicators: 95
- Unique domains: 49
- IOCs extracted: 163
- Detection signals raised: 27 (18 active, 9 suppressed by allowlist)
- Correlated findings: 15

**Findings by severity**

| Severity | Count |
|---|---|
| Low | 3 |
| Informational | 12 |


## 2. Key Findings

Only correlated, evidence-backed findings are shown here. Every finding combines behavioral detection signals and/or threat-intelligence evidence -- a domain, IP or hash observed with no corroborating evidence appears only in the IOC inventory (Section 6), not here.

### F-001 — Threat Intelligence Match

- **Severity:** Low &nbsp;|&nbsp; **Confidence:** Low &nbsp;|&nbsp; **Risk score:** 30/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** 45.131.214.85
- **Domain(s):** vadusa.xyz
- **First/last seen:** 19:55:51 – 19:55:51 (2 occurrence(s))
- **Detection rule(s):** None (TI-only)

**Why this matters:** 10.2.28.88 queried vadusa.xyz 2 time(s). Threat-intelligence assessment: CLEAN, MALICIOUS. Risk score 30/100 (Reputation 30, Behavior 0, Payload 0, Network context 0, Asset context 0 — asset role unknown).

**Threat intelligence:**
- AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean.
- VirusTotal: 8/89 vendor(s) flagged malicious, 3 suspicious. Interpreted as Malicious.
- VirusTotal: 6/89 vendor(s) flagged malicious, 3 suspicious. Interpreted as Malicious.

### F-002 — Suspicious Connection to ctldl.windowsupdate.com

- **Severity:** Low &nbsp;|&nbsp; **Confidence:** Low &nbsp;|&nbsp; **Risk score:** 27/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** 199.232.210.172, 23.213.232.101, 23.213.232.198, ctldl.windowsupdate.com.delivery.microsoft.com.
- **Domain(s):** ctldl.windowsupdate.com
- **First/last seen:** 20:48:58 – 22:50:01 (15 occurrence(s))
- **Detection rule(s):** None (TI-only)

**Why this matters:** 10.2.28.88 queried ctldl.windowsupdate.com 6 time(s). HTTP activity was observed to ctldl.windowsupdate.com. Threat-intelligence assessment: CLEAN, SUSPICIOUS, WEAK_REPUTATION. Risk score 27/100 (Reputation 22, Behavior 0, Payload 0, Network context 5, Asset context 0 — asset role unknown).

**Threat intelligence:**
- AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean.
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.
- AbuseIPDB abuse confidence 0/100 from 56 report(s), last reported 0d ago. Interpreted as Weak Reputation.
- VirusTotal: 2/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Suspicious.
- AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean.
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

### F-003 — Suspicious Connection to edge.microsoft.com

- **Severity:** Low &nbsp;|&nbsp; **Confidence:** Low &nbsp;|&nbsp; **Risk score:** 21/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** 150.171.27.11, edge-microsoft-com.ax-0002.ax-msedge.net.
- **Domain(s):** edge.microsoft.com
- **First/last seen:** 19:55:31 – 23:56:43 (16 occurrence(s))
- **Detection rule(s):** None (TI-only)

**Why this matters:** 10.2.28.88 queried edge.microsoft.com 15 time(s). HTTP activity was observed to edge.microsoft.com. Threat-intelligence assessment: CLEAN, SUSPICIOUS. Risk score 21/100 (Reputation 16, Behavior 0, Payload 0, Network context 5, Asset context 0 — asset role unknown).

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.
- AbuseIPDB abuse confidence 37/100 from 53 report(s), last reported 3d ago. Interpreted as Suspicious.
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

### F-004 — Suspicious Network Activity

- **Severity:** Informational &nbsp;|&nbsp; **Confidence:** Low &nbsp;|&nbsp; **Risk score:** 16/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** N/A
- **Domain(s):** wpad.mshome.net
- **First/last seen:** 19:55:09 – 00:16:30 (79 occurrence(s))
- **Detection rule(s):** DNS-001, DNS-002

**Why this matters:** 10.2.28.88 queried wpad.mshome.net 79 time(s). Local detection rule(s) DNS-001, DNS-002 fired for this activity. Threat-intelligence assessment: CLEAN. Risk score 16/100 (Reputation 0, Behavior 16, Payload 0, Network context 0, Asset context 0 — asset role unknown).

**Key evidence:**
- 10.2.28.88 queried wpad.mshome.net (A) 79 time(s) between 19:55:09 and 00:16:30.
- 78/79 queries for wpad.mshome.net from 10.2.28.88 resolved NXDOMAIN (99%).

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

### F-005 — Suspicious Network Activity

- **Severity:** Informational &nbsp;|&nbsp; **Confidence:** Low &nbsp;|&nbsp; **Risk score:** 16/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** N/A
- **Domain(s):** wpad.easyas123.tech
- **First/last seen:** 19:55:09 – 00:16:30 (78 occurrence(s))
- **Detection rule(s):** DNS-001, DNS-002

**Why this matters:** 10.2.28.88 queried wpad.easyas123.tech 78 time(s). Local detection rule(s) DNS-001, DNS-002 fired for this activity. Threat-intelligence assessment: CLEAN. Risk score 16/100 (Reputation 0, Behavior 16, Payload 0, Network context 0, Asset context 0 — asset role unknown).

**Key evidence:**
- 10.2.28.88 queried wpad.easyas123.tech (A) 78 time(s) between 19:55:09 and 00:16:30.
- 78/78 queries for wpad.easyas123.tech from 10.2.28.88 resolved NXDOMAIN (100%).

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

### F-006 — Potential DGA Domain Activity — acroipm2.adobe.com

- **Severity:** Informational &nbsp;|&nbsp; **Confidence:** Low &nbsp;|&nbsp; **Risk score:** 13/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** 23.218.232.161, acroipm2.adobe.com.edgesuite.net.
- **Domain(s):** acroipm2.adobe.com
- **First/last seen:** 20:07:24 – 20:07:24 (3 occurrence(s))
- **Detection rule(s):** DNS-003, HTTP-004

**Why this matters:** 10.2.28.88 queried acroipm2.adobe.com 2 time(s). HTTP activity was observed to acroipm2.adobe.com. Local detection rule(s) DNS-003, HTTP-004 fired for this activity. Threat-intelligence assessment: CLEAN. Risk score 13/100 (Reputation 0, Behavior 8, Payload 0, Network context 5, Asset context 0 — asset role unknown).

**Key evidence:**
- DGA heuristic score: 33/100 (confidence: Low)
- acroipm2.adobe.com was contacted only 1 time(s) across the entire capture.

**Threat intelligence:**
- AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean.
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

### F-007 — Suspicious Network Activity

- **Severity:** Informational &nbsp;|&nbsp; **Confidence:** Medium &nbsp;|&nbsp; **Risk score:** 12/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** login.mso.msidentity.com.
- **Domain(s):** login.microsoftonline.com
- **First/last seen:** 20:10:24 – 23:46:47 (31 occurrence(s))
- **Detection rule(s):** DNS-001

**Why this matters:** 10.2.28.88 queried login.microsoftonline.com 31 time(s). Local detection rule(s) DNS-001 fired for this activity. Threat-intelligence assessment: WEAK_REPUTATION. Risk score 12/100 (Reputation 6, Behavior 6, Payload 0, Network context 0, Asset context 0 — asset role unknown).

**Key evidence:**
- 10.2.28.88 queried login.microsoftonline.com (A) 31 time(s) between 20:10:24 and 23:46:47.

**Threat intelligence:**
- VirusTotal: 1/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Weak Reputation.

### F-008 — Potential DGA Domain Activity — easyas123-dc.easyas123.tech

- **Severity:** Informational &nbsp;|&nbsp; **Confidence:** Low &nbsp;|&nbsp; **Risk score:** 11/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** 10.2.28.2
- **Domain(s):** easyas123-dc.easyas123.tech
- **First/last seen:** 19:55:08 – 23:55:09 (7 occurrence(s))
- **Detection rule(s):** DNS-003

**Why this matters:** 10.2.28.88 queried easyas123-dc.easyas123.tech 7 time(s). Local detection rule(s) DNS-003 fired for this activity. Threat-intelligence assessment: CLEAN. Risk score 11/100 (Reputation 0, Behavior 11, Payload 0, Network context 0, Asset context 0 — asset role unknown).

**Key evidence:**
- DGA heuristic score: 59/100 (confidence: Medium)

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

### F-009 — Suspicious Network Activity

- **Severity:** Informational &nbsp;|&nbsp; **Confidence:** Low &nbsp;|&nbsp; **Risk score:** 10/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** N/A
- **Domain(s):** _ldap._tcp.default-first-site-name._sites.dc._msdcs.mshome.net
- **First/last seen:** 19:55:08 – 19:55:12 (5 occurrence(s))
- **Detection rule(s):** DNS-002

**Why this matters:** 10.2.28.88 queried _ldap._tcp.default-first-site-name._sites.dc._msdcs.mshome.net 5 time(s). Local detection rule(s) DNS-002 fired for this activity. Risk score 10/100 (Reputation 0, Behavior 10, Payload 0, Network context 0, Asset context 0 — asset role unknown).

**Key evidence:**
- 4/5 queries for _ldap._tcp.default-first-site-name._sites.dc._msdcs.mshome.net from 10.2.28.88 resolved NXDOMAIN (80%).

**Threat intelligence:**
- No meaningful threat-intelligence match.

### F-010 — Suspicious Network Activity

- **Severity:** Informational &nbsp;|&nbsp; **Confidence:** Low &nbsp;|&nbsp; **Risk score:** 10/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** N/A
- **Domain(s):** _ldap._tcp.dc._msdcs.mshome.net
- **First/last seen:** 19:55:09 – 19:55:10 (4 occurrence(s))
- **Detection rule(s):** DNS-002

**Why this matters:** 10.2.28.88 queried _ldap._tcp.dc._msdcs.mshome.net 4 time(s). Local detection rule(s) DNS-002 fired for this activity. Threat-intelligence assessment: CLEAN. Risk score 10/100 (Reputation 0, Behavior 10, Payload 0, Network context 0, Asset context 0 — asset role unknown).

**Key evidence:**
- 3/4 queries for _ldap._tcp.dc._msdcs.mshome.net from 10.2.28.88 resolved NXDOMAIN (75%).

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

### F-011 — Potential DGA Domain Activity — img-s-msn-com.akamaized.net

- **Severity:** Informational &nbsp;|&nbsp; **Confidence:** Low &nbsp;|&nbsp; **Risk score:** 9/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** a1834.dscg2.akamai.net.
- **Domain(s):** img-s-msn-com.akamaized.net
- **First/last seen:** 19:56:26 – 21:17:57 (4 occurrence(s))
- **Detection rule(s):** DNS-003

**Why this matters:** 10.2.28.88 queried img-s-msn-com.akamaized.net 2 time(s). Local detection rule(s) DNS-003 fired for this activity. Threat-intelligence assessment: CLEAN. Risk score 9/100 (Reputation 0, Behavior 9, Payload 0, Network context 0, Asset context 0 — asset role unknown).

**Key evidence:**
- DGA heuristic score: 47/100 (confidence: Medium)

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

### F-012 — Potential DGA Domain Activity — _googlecast._tcp.local

- **Severity:** Informational &nbsp;|&nbsp; **Confidence:** Low &nbsp;|&nbsp; **Risk score:** 8/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** N/A
- **Domain(s):** _googlecast._tcp.local
- **First/last seen:** 19:55:53 – 19:55:56 (3 occurrence(s))
- **Detection rule(s):** DNS-003

**Why this matters:** 10.2.28.88 queried _googlecast._tcp.local 3 time(s). Local detection rule(s) DNS-003 fired for this activity. Risk score 8/100 (Reputation 0, Behavior 8, Payload 0, Network context 0, Asset context 0 — asset role unknown).

**Key evidence:**
- DGA heuristic score: 40/100 (confidence: Low)

**Threat intelligence:**
- No meaningful threat-intelligence match.

### F-013 — Suspicious Network Activity

- **Severity:** Informational &nbsp;|&nbsp; **Confidence:** Low &nbsp;|&nbsp; **Risk score:** 7/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** 23.204.150.28, ocsp.edge.digicert.com.
- **Domain(s):** ocsp.digicert.com
- **First/last seen:** 20:19:01 – 21:19:01 (5 occurrence(s))
- **Detection rule(s):** HTTP-004

**Why this matters:** 10.2.28.88 queried ocsp.digicert.com 3 time(s). HTTP activity was observed to ocsp.digicert.com. Local detection rule(s) HTTP-004 fired for this activity. Threat-intelligence assessment: CLEAN. Risk score 7/100 (Reputation 0, Behavior 2, Payload 0, Network context 5, Asset context 0 — asset role unknown).

**Key evidence:**
- ocsp.digicert.com was contacted only 2 time(s) across the entire capture.

**Threat intelligence:**
- AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 465d ago. Interpreted as Clean.
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

### F-014 — Suspicious Network Activity

- **Severity:** Informational &nbsp;|&nbsp; **Confidence:** Low &nbsp;|&nbsp; **Risk score:** 6/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** N/A
- **Domain(s):** _ldap._tcp.default-first-site-name._sites.dc._msdcs.easyas123.tech
- **First/last seen:** 19:55:08 – 23:32:39 (10 occurrence(s))
- **Detection rule(s):** DNS-001

**Why this matters:** 10.2.28.88 queried _ldap._tcp.default-first-site-name._sites.dc._msdcs.easyas123.tech 10 time(s). Local detection rule(s) DNS-001 fired for this activity. Risk score 6/100 (Reputation 0, Behavior 6, Payload 0, Network context 0, Asset context 0 — asset role unknown).

**Key evidence:**
- 10.2.28.88 queried _ldap._tcp.default-first-site-name._sites.dc._msdcs.easyas123.tech (33) 10 time(s) between 19:55:08 and 23:32:39.

**Threat intelligence:**
- No meaningful threat-intelligence match.

### F-015 — Suspicious Network Activity

- **Severity:** Informational &nbsp;|&nbsp; **Confidence:** Low &nbsp;|&nbsp; **Risk score:** 6/100
- **Affected endpoint(s):** 10.2.28.88 (asset role: Unknown)
- **Destinations:** win-msn-com-world-atm-default.trafficmanager.net.
- **Domain(s):** windows.msn.com
- **First/last seen:** 19:55:25 – 23:18:18 (12 occurrence(s))
- **Detection rule(s):** DNS-001

**Why this matters:** 10.2.28.88 queried windows.msn.com 10 time(s). Local detection rule(s) DNS-001 fired for this activity. Threat-intelligence assessment: CLEAN. Risk score 6/100 (Reputation 0, Behavior 6, Payload 0, Network context 0, Asset context 0 — asset role unknown).

**Key evidence:**
- 10.2.28.88 queried windows.msn.com (A) 10 time(s) between 19:55:25 and 23:18:18.

**Threat intelligence:**
- VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean.

## 3. Investigation Recommendations

**F-001 — Threat Intelligence Match:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for vadusa.xyz across the environment.
- Block the associated infrastructure at the network boundary per policy.

**F-002 — Suspicious Connection to ctldl.windowsupdate.com:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for ctldl.windowsupdate.com across the environment.
- Search proxy/web logs for prior connections to ctldl.windowsupdate.com.

**F-003 — Suspicious Connection to edge.microsoft.com:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for edge.microsoft.com across the environment.
- Search proxy/web logs for prior connections to edge.microsoft.com.

**F-004 — Suspicious Network Activity:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for wpad.mshome.net across the environment.

**F-005 — Suspicious Network Activity:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for wpad.easyas123.tech across the environment.

**F-006 — Potential DGA Domain Activity — acroipm2.adobe.com:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for acroipm2.adobe.com across the environment.
- Search proxy/web logs for prior connections to acroipm2.adobe.com.

**F-007 — Suspicious Network Activity:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for login.microsoftonline.com across the environment.

**F-008 — Potential DGA Domain Activity — easyas123-dc.easyas123.tech:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for easyas123-dc.easyas123.tech across the environment.

**F-009 — Suspicious Network Activity:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for _ldap._tcp.default-first-site-name._sites.dc._msdcs.mshome.net across the environment.

**F-010 — Suspicious Network Activity:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for _ldap._tcp.dc._msdcs.mshome.net across the environment.

**F-011 — Potential DGA Domain Activity — img-s-msn-com.akamaized.net:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for img-s-msn-com.akamaized.net across the environment.

**F-012 — Potential DGA Domain Activity — _googlecast._tcp.local:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for _googlecast._tcp.local across the environment.

**F-013 — Suspicious Network Activity:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for ocsp.digicert.com across the environment.
- Search proxy/web logs for prior connections to ocsp.digicert.com.

**F-014 — Suspicious Network Activity:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for _ldap._tcp.default-first-site-name._sites.dc._msdcs.easyas123.tech across the environment.

**F-015 — Suspicious Network Activity:**
- Investigate endpoint 10.2.28.88 for signs of compromise.
- Review historical DNS logs for windows.msn.com across the environment.

## 4. Attack / Behavior Story

**F-002 — Suspicious Connection to ctldl.windowsupdate.com**

```
DNS (ctldl.windowsupdate.com)
  ↓
HTTP connection (ctldl.windowsupdate.com)
  ↓
Threat Intelligence
```

**F-003 — Suspicious Connection to edge.microsoft.com**

```
DNS (edge.microsoft.com)
  ↓
HTTP connection (edge.microsoft.com)
  ↓
Threat Intelligence
```

**F-006 — Potential DGA Domain Activity — acroipm2.adobe.com**

```
DNS (acroipm2.adobe.com)
  ↓
HTTP connection (acroipm2.adobe.com)
  ↓
Threat Intelligence
```

**F-013 — Suspicious Network Activity**

```
DNS (ocsp.digicert.com)
  ↓
HTTP connection (ocsp.digicert.com)
  ↓
Threat Intelligence
```

## 5. Technical Evidence

Raw observations: 831 DNS record(s), 88 HTTP record(s), 0 file transfer(s) — aggregated below into 62 DNS behavioral event(s), 11 HTTP behavioral event(s) and 0 distinct file behavioral event(s).

### Protocol / traffic distribution

| Protocol | Packet Count |
|---|---|
| UDP | 2113 |
| Ether | 836 |
| TCP | 12544 |
| IP-PROTO-1 | 19 |

### DNS behavioral events

| Source | Domain | Type | Occurrences | NXDOMAIN % | Resolved IP(s) | First seen | Last seen |
|---|---|---|---|---|---|---|---|
| 10.2.28.88 | wpad.mshome.net | A | 79 | 99% | - | 19:55:09 | 00:16:30 |
| 10.2.28.88 | wpad.easyas123.tech | A | 78 | 100% | - | 19:55:09 | 00:16:30 |
| 10.2.28.88 | login.microsoftonline.com | A | 31 | 0% | login.mso.msidentity.com. | 20:10:24 | 23:46:47 |
| 10.2.28.88 | settings-win.data.microsoft.com | A | 25 | 0% | atm-settingsfe-prod-geo2.trafficmanager.net. | 20:10:25 | 23:46:48 |
| 10.2.28.88 | v10.events.data.microsoft.com | A | 22 | 0% | win-global-asimov-leafs-events-data.traf., win-global-asimov-leafs-events-data.trafficmanager.net. | 19:55:10 | 23:51:00 |
| 10.2.28.88 | edge.microsoft.com | 65 | 15 | 0% | edge-microsoft-com.ax-0002.ax-msedge.net. | 19:55:31 | 23:56:43 |
| 10.2.28.88 | edge.microsoft.com | A | 15 | 0% | edge-microsoft-com.ax-0002.ax-msedge.net. | 19:55:31 | 23:56:43 |
| 10.2.28.88 | _ldap._tcp.default-first-site-name._sites.dc._msdcs.easyas123.tech | 33 | 10 | 0% | - | 19:55:08 | 23:32:39 |
| 10.2.28.88 | windows.msn.com | A | 10 | 0% | win-msn-com-world-atm-default.trafficmanager.net. | 19:55:25 | 23:18:18 |
| 10.2.28.88 | self.events.data.microsoft.com | A | 9 | 0% | self-events-data.trafficmanager.net. | 19:55:33 | 23:25:37 |
| 10.2.28.88 | msedge.b.tlu.dl.delivery.mp.microsoft.com | A | 8 | 0% | star.b.tlu.dl.delivery.mp.microsoft.com.delivery.microsoft.com. | 20:18:00 | 23:18:22 |
| 10.2.28.88 | easyas123-dc.easyas123.tech | A | 7 | 0% | 10.2.28.2 | 19:55:08 | 23:55:09 |
| 10.2.28.88 | ecs.office.com | A | 7 | 0% | ecs.office.trafficmanager.net. | 20:05:23 | 23:04:13 |
| 10.2.28.88 | ctldl.windowsupdate.com | A | 6 | 0% | ctldl.windowsupdate.com.delivery.microsoft.com. | 20:48:58 | 22:50:01 |
| 10.2.28.88 | odc.officeapps.live.com | A | 6 | 0% | prod.odcsm1.live.com.akadns.net. | 19:55:26 | 19:56:44 |
| 10.2.28.88 | www.msn.com | A | 6 | 0% | www-msn-com-world-atm-default.trafficmanager.net. | 19:55:26 | 23:18:18 |
| 10.2.28.88 | _ldap._tcp.default-first-site-name._sites.dc._msdcs.mshome.net | 33 | 5 | 80% | - | 19:55:08 | 19:55:12 |
| 10.2.28.88 | assets.msn.com | A | 5 | 0% | assets-msn-com-world-atm-default.trafficmanager.net. | 19:55:26 | 21:17:58 |
| 10.2.28.88 | mobile.events.data.microsoft.com | A | 5 | 0% | mobile.events.data.trafficmanager.net. | 20:19:00 | 23:19:00 |
| 10.2.28.88 | www.bing.com | 65 | 5 | 0% | www-www.bing.com.trafficmanager.net. | 19:55:25 | 20:17:57 |
| 10.2.28.88 | www.bing.com | A | 5 | 0% | www-www.bing.com.trafficmanager.net. | 19:55:25 | 20:17:57 |
| 10.2.28.88 | www.msn.com | 65 | 5 | 0% | www-msn-com-world-atm-default.trafficmanager.net. | 19:56:26 | 23:18:18 |
| 10.2.28.88 | _ldap._tcp.dc._msdcs.mshome.net | 33 | 4 | 75% | - | 19:55:09 | 19:55:10 |
| 10.2.28.88 | armmf.adobe.com | A | 4 | 0% | ssl.adobe.com.edgekey.net. | 20:07:28 | 23:37:28 |
| 10.2.28.88 | _googlecast._tcp.local | PTR | 3 | 0% | - | 19:55:53 | 19:55:56 |
| 10.2.28.88 | assets.msn.com | 65 | 3 | 0% | assets-msn-com-world-atm-default.trafficmanager.net. | 19:56:26 | 21:17:58 |
| 10.2.28.88 | client.wns.windows.com | A | 3 | 0% | wns.notify.trafficmanager.net. | 19:55:12 | 22:16:08 |
| 10.2.28.88 | ocsp.digicert.com | A | 3 | 0% | ocsp.edge.digicert.com. | 20:19:01 | 21:19:01 |
| 10.2.28.88 | th.bing.com | 65 | 3 | 0% | p-th.bing.com.trafficmanager.net. | 19:56:26 | 21:17:57 |
| 10.2.28.88 | th.bing.com | A | 3 | 0% | p-th.bing.com.trafficmanager.net. | 19:56:26 | 21:17:57 |
| 10.2.28.88 | _ldap._tcp.default-first-site-name._sites.easyas123-dc.easyas123.tech | 33 | 2 | 100% | - | 19:55:58 | 20:00:24 |
| 10.2.28.88 | _ldap._tcp.default-first-site-name._sites.easyas123.tech | 33 | 2 | 0% | - | 19:55:08 | 19:55:09 |
| 10.2.28.88 | _ldap._tcp.easyas123-dc.easyas123.tech | 33 | 2 | 100% | - | 19:55:58 | 20:00:24 |
| 10.2.28.88 | acroipm2.adobe.com | A | 2 | 0% | acroipm2.adobe.com.edgesuite.net. | 20:07:24 | 20:07:24 |
| 10.2.28.88 | api.msn.com | 65 | 2 | 0% | api-msn-com-oneservice-world-default.trafficmanager.net. | 19:56:26 | 20:17:57 |
| 10.2.28.88 | api.msn.com | A | 2 | 0% | api-msn-com-oneservice-world-default.trafficmanager.net. | 19:56:26 | 20:17:57 |
| 10.2.28.88 | assets.adobedtm.com | A | 2 | 0% | cn-assets.adobedtm.com.edgekey.net. | 19:55:30 | 19:55:30 |
| 10.2.28.88 | edge-consumer-static.azureedge.net | 65 | 2 | 0% | edge-consumer-static.afd.azureedge.net. | 19:56:01 | 19:57:14 |
| 10.2.28.88 | edge-consumer-static.azureedge.net | A | 2 | 0% | edge-consumer-static.afd.azureedge.net. | 19:56:01 | 19:57:14 |
| 10.2.28.88 | fd.api.iris.microsoft.com | A | 2 | 0% | fd-api-iris.trafficmanager.net. | 19:55:59 | 19:55:59 |
| 10.2.28.88 | g.live.com | A | 2 | 0% | g.msn.com. | 19:55:29 | 19:55:30 |
| 10.2.28.88 | img-s-msn-com.akamaized.net | 65 | 2 | 0% | a1834.dscg2.akamai.net. | 19:56:26 | 21:17:57 |
| 10.2.28.88 | img-s-msn-com.akamaized.net | A | 2 | 0% | a1834.dscg2.akamai.net. | 19:56:26 | 21:17:57 |
| 10.2.28.88 | licensing.mp.microsoft.com | A | 2 | 0% | consumer-licensing-aks2aks.md.mp.microsoft.com.akadns.net. | 20:38:13 | 20:38:13 |
| 10.2.28.88 | officeclient.microsoft.com | A | 2 | 0% | config.officeapps.live.com. | 19:55:26 | 19:55:26 |
| 10.2.28.88 | oneclient.sfx.ms | A | 2 | 0% | oneclient.sfx.ms.edgesuite.net. | 19:55:30 | 19:55:30 |
| 10.2.28.88 | services.gfe.nvidia.com | A | 2 | 0% | services.gfe.nvidia.com.edgesuite.net. | 19:56:05 | 19:56:05 |
| 10.2.28.88 | srtb.msn.com | 65 | 2 | 0% | srtb-msn-com-profile.trafficmanager.net. | 19:56:26 | 20:17:57 |
| 10.2.28.88 | srtb.msn.com | A | 2 | 0% | srtb-msn-com-profile.trafficmanager.net. | 19:56:26 | 20:17:57 |
| 10.2.28.88 | update.googleapis.com | A | 2 | 0% | 142.250.138.94 | 23:20:38 | 23:20:38 |
| 10.2.28.88 | vadusa.xyz | A | 2 | 0% | 45.131.214.85 | 19:55:51 | 19:55:51 |
| 10.2.28.88 | watson.events.data.microsoft.com | A | 2 | 0% | blobcollectorcommon.trafficmanager.net. | 19:55:23 | 19:55:24 |
| 10.2.28.88 | windows.msn.com | 65 | 2 | 0% | win-msn-com-world-atm-default.trafficmanager.net. | 19:56:26 | 20:17:56 |
| 10.2.28.88 | www.msftconnecttest.com | A | 2 | 0% | ncsi-geo.trafficmanager.net. | 19:55:09 | 19:55:09 |
| 10.2.28.88 | config.edge.skype.com | 65 | 1 | 0% | config.edge.skype.com.trafficmanager.net. | 19:55:25 | 19:55:25 |
| 10.2.28.88 | config.edge.skype.com | A | 1 | 0% | config.edge.skype.com.trafficmanager.net. | 19:55:25 | 19:55:25 |
| 10.2.28.88 | deff.nelreports.net | 65 | 1 | 0% | deff.nelreports.net.akamaized.net. | 20:17:56 | 20:17:56 |
| 10.2.28.88 | deff.nelreports.net | A | 1 | 0% | deff.nelreports.net.akamaized.net. | 20:17:56 | 20:17:56 |
| 10.2.28.88 | staticview.msn.com | 65 | 1 | 0% | staticview.msn.com.edgesuite.net. | 20:17:56 | 20:17:56 |
| 10.2.28.88 | staticview.msn.com | A | 1 | 0% | staticview.msn.com.edgesuite.net. | 20:17:56 | 20:17:56 |

### HTTP behavioral events

| Source | Destination | Host | Requests | Path(s) | User-Agent |
|---|---|---|---|---|---|
| 10.2.28.88 | 23.218.232.148 | msedge.b.tlu.dl.delivery.mp.microsoft.com | 11 | /filestreamingservice/files/2132f61f-f790-4ae6-a355-8cf9a1533800?P1=1772824359&P2=404&P3=2&P4=JBAPgdPQ5bbXP3YOD9Ig2AVW51pLa6vxUcHeGTEAadbzNEO5DlV3Wra1C9WqE7WnEd5RG1oYpt8saZgMxML1KA%3d%3d | Microsoft BITS/7.8 |
| 10.2.28.88 | 23.218.232.166 | msedge.b.tlu.dl.delivery.mp.microsoft.com | 7 | /filestreamingservice/files/13d0ef9b-70c8-43c9-9a51-13c752dfb777?P1=1772817857&P2=404&P3=2&P4=NxsPWDqY%2fPRN4X5tyugkA%2bdfU9EeHebHQ3SqTAWWr5XPVngvgEZDtSFAEYlah9GHFrc%2bS%2fExNx3X0xGxvdOPow%3d%3d | Microsoft BITS/7.8 |
| 10.2.28.88 | 23.218.232.142 | msedge.b.tlu.dl.delivery.mp.microsoft.com | 6 | /filestreamingservice/files/ddbf4492-d475-4fe4-bcde-6cbac56f6034?P1=1772824359&P2=404&P3=2&P4=TMSkemQv9LZfDxme9Q9GxU0tc2G9uhdO6d7QU9JVJHOk%2ba0A4pJYzApqbFnNEQ6bt9QSukbCYOxGUmPIOR1Xgw%3d%3d, /filestreamingservice/files/0b18f766-7469-4aa3-88b7-99e69c55d14d?P1=1772628813&P2=404&P3=2&P4=P9O%2fZqV3zHEog%2f8GWjY1LjxEXlCShXCmvVwfgCjP6c7Xjf6q9SdV5Cxrlht3k8c6RsZdgDSm48GRm8J1Kej36Q%3d%3d | Microsoft BITS/7.8 |
| 10.2.28.88 | 23.218.232.183 | msedge.b.tlu.dl.delivery.mp.microsoft.com | 6 | /filestreamingservice/files/86061e48-63b3-483f-8dac-609df0cbb238?P1=1772824359&P2=404&P3=2&P4=M%2br84JmdgFPOKPdw6GuIsCbfL0IaRRxCYqeiJbpH9IpxZr7vLbM4w9K8uMU5Ka6CyN%2fuMqIEMlyIHqGqCS8%2fXg%3d%3d | Microsoft BITS/7.8 |
| 10.2.28.88 | 199.232.210.172 | ctldl.windowsupdate.com | 3 | /msdownload/update/v3/static/trustedr/en/authrootstl.cab?238f51c2ab526be6, /msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?4e25f6955dc4f675, /msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?a8cb64ce6f292067 | Microsoft-CryptoAPI/10.0 |
| 10.2.28.88 | 23.213.232.198 | ctldl.windowsupdate.com | 3 | /msdownload/update/v3/static/trustedr/en/authrootstl.cab?1fe5743cf489a795, /msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?d7d014dbf0b66d22, /msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?811956fd58fe307b | Microsoft-CryptoAPI/10.0 |
| 10.2.28.88 | 23.213.232.101 | ctldl.windowsupdate.com | 3 | /msdownload/update/v3/static/trustedr/en/authrootstl.cab?957338f6d43a4cf5, /msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?d3434c35564aa4e5, /msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?fa2f866848cf44b7 | Microsoft-CryptoAPI/10.0 |
| 10.2.28.88 | 23.204.150.28 | ocsp.digicert.com | 2 | /MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ50otx%2Fh0Ztl%2Bz8SiPI7wEWVxDlQQUTiJUIBiV5uNu5g%2F6%2BrkS7QYXjzkCEA77flR%2B3w%2FxBpruV2lte6A%3D, /MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ50otx%2Fh0Ztl%2Bz8SiPI7wEWVxDlQQUTiJUIBiV5uNu5g%2F6%2BrkS7QYXjzkCEAUZZSZEml49Gjh0j13P68w%3D | Microsoft-CryptoAPI/10.0 |
| 10.2.28.88 | 23.218.232.161 | acroipm2.adobe.com | 1 | /assets/Owner/arm/ProcessMAU.txt | Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729) |
| 10.2.28.88 | 150.171.27.11 | edge.microsoft.com | 1 | /browsernetworktime/time/1/current?cup2key=2:cHFgppt5zfs9cbgaKCO2n0tk698hI27wU971tyrEQQg&cup2hreq=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0 |
| 10.2.28.88 | 23.47.50.182 | www.msftconnecttest.com | 1 | /connecttest.txt | Microsoft NCSI |

### File transfer behavioral events

No complete files could be reassembled from the supplied PCAP.

### Investigation timeline

| Timestamp (UTC) | Behavioral event | Related finding |
|---|---|---|
| 19:55:08 | 10.2.28.88 queried _ldap._tcp.default-first-site-name._sites.dc._msdcs.mshome.net (5 time(s), 19:55:08–19:55:12) | F-009 |
| 19:55:08 | 10.2.28.88 queried _ldap._tcp.default-first-site-name._sites.dc._msdcs.easyas123.tech (10 time(s), 19:55:08–23:32:39) | F-014 |
| 19:55:08 | 10.2.28.88 queried _ldap._tcp.default-first-site-name._sites.easyas123.tech (2 time(s), 19:55:08–19:55:09) | - |
| 19:55:08 | 10.2.28.88 queried easyas123-dc.easyas123.tech (7 time(s), 19:55:08–23:55:09) | F-008 |
| 19:55:09 | 10.2.28.88 queried _ldap._tcp.dc._msdcs.mshome.net (4 time(s), 19:55:09–19:55:10) | F-010 |
| 19:55:09 | 10.2.28.88 queried wpad.easyas123.tech (78 time(s), 19:55:09–00:16:30) | F-005 |
| 19:55:09 | 10.2.28.88 queried wpad.mshome.net (79 time(s), 19:55:09–00:16:30) | F-004 |
| 19:55:09 | 10.2.28.88 queried www.msftconnecttest.com (2 time(s), 19:55:09–19:55:09) | - |
| 19:55:09 | 10.2.28.88 → 23.47.50.182 HTTP activity to www.msftconnecttest.com (1 request(s): /connecttest.txt) | - |
| 19:55:10 | 10.2.28.88 queried v10.events.data.microsoft.com (22 time(s), 19:55:10–23:51:00) | - |
| 19:55:12 | 10.2.28.88 queried client.wns.windows.com (3 time(s), 19:55:12–22:16:08) | - |
| 19:55:23 | 10.2.28.88 queried watson.events.data.microsoft.com (2 time(s), 19:55:23–19:55:24) | - |
| 19:55:25 | 10.2.28.88 queried windows.msn.com (10 time(s), 19:55:25–23:18:18) | F-015 |
| 19:55:25 | 10.2.28.88 queried config.edge.skype.com (1 time(s), 19:55:25–19:55:25) | - |
| 19:55:25 | 10.2.28.88 queried config.edge.skype.com (1 time(s), 19:55:25–19:55:25) | - |
| 19:55:25 | 10.2.28.88 queried www.bing.com (5 time(s), 19:55:25–20:17:57) | - |
| 19:55:25 | 10.2.28.88 queried www.bing.com (5 time(s), 19:55:25–20:17:57) | - |
| 19:55:26 | 10.2.28.88 queried www.msn.com (6 time(s), 19:55:26–23:18:18) | - |
| 19:55:26 | 10.2.28.88 queried officeclient.microsoft.com (2 time(s), 19:55:26–19:55:26) | - |
| 19:55:26 | 10.2.28.88 queried odc.officeapps.live.com (6 time(s), 19:55:26–19:56:44) | - |
| 19:55:26 | 10.2.28.88 queried assets.msn.com (5 time(s), 19:55:26–21:17:58) | - |
| 19:55:29 | 10.2.28.88 queried g.live.com (2 time(s), 19:55:29–19:55:30) | - |
| 19:55:30 | 10.2.28.88 queried oneclient.sfx.ms (2 time(s), 19:55:30–19:55:30) | - |
| 19:55:30 | 10.2.28.88 queried assets.adobedtm.com (2 time(s), 19:55:30–19:55:30) | - |
| 19:55:31 | 10.2.28.88 queried edge.microsoft.com (15 time(s), 19:55:31–23:56:43) | F-003 |
| 19:55:31 | 10.2.28.88 queried edge.microsoft.com (15 time(s), 19:55:31–23:56:43) | F-003 |
| 19:55:33 | 10.2.28.88 queried self.events.data.microsoft.com (9 time(s), 19:55:33–23:25:37) | - |
| 19:55:50 | 10.2.28.88 queried www.fmcsa.dot.gov (1 time(s), 19:55:50–19:55:50) | - |
| 19:55:50 | 10.2.28.88 queried www.fmcsa.dot.gov (1 time(s), 19:55:50–19:55:50) | - |
| 19:55:51 | 10.2.28.88 queried vadusa.xyz (2 time(s), 19:55:51–19:55:51) | F-001 |
| 19:55:53 | 10.2.28.88 queried _googlecast._tcp.local (3 time(s), 19:55:53–19:55:56) | F-012 |
| 19:55:58 | 10.2.28.88 queried _ldap._tcp.default-first-site-name._sites.easyas123-dc.easyas123.tech (2 time(s), 19:55:58–20:00:24) | - |
| 19:55:58 | 10.2.28.88 queried _ldap._tcp.easyas123-dc.easyas123.tech (2 time(s), 19:55:58–20:00:24) | - |
| 19:55:59 | 10.2.28.88 queried fd.api.iris.microsoft.com (2 time(s), 19:55:59–19:55:59) | - |
| 19:56:01 | 10.2.28.88 queried edge-consumer-static.azureedge.net (2 time(s), 19:56:01–19:57:14) | - |
| 19:56:01 | 10.2.28.88 queried edge-consumer-static.azureedge.net (2 time(s), 19:56:01–19:57:14) | - |
| 19:56:05 | 10.2.28.88 queried services.gfe.nvidia.com (2 time(s), 19:56:05–19:56:05) | - |
| 19:56:26 | 10.2.28.88 queried windows.msn.com (2 time(s), 19:56:26–20:17:56) | F-015 |
| 19:56:26 | 10.2.28.88 queried www.msn.com (5 time(s), 19:56:26–23:18:18) | - |
| 19:56:26 | 10.2.28.88 queried api.msn.com (2 time(s), 19:56:26–20:17:57) | - |
| 19:56:26 | 10.2.28.88 queried api.msn.com (2 time(s), 19:56:26–20:17:57) | - |
| 19:56:26 | 10.2.28.88 queried assets.msn.com (3 time(s), 19:56:26–21:17:58) | - |
| 19:56:26 | 10.2.28.88 queried srtb.msn.com (2 time(s), 19:56:26–20:17:57) | - |
| 19:56:26 | 10.2.28.88 queried srtb.msn.com (2 time(s), 19:56:26–20:17:57) | - |
| 19:56:26 | 10.2.28.88 queried th.bing.com (3 time(s), 19:56:26–21:17:57) | - |
| 19:56:26 | 10.2.28.88 queried th.bing.com (3 time(s), 19:56:26–21:17:57) | - |
| 19:56:26 | 10.2.28.88 queried img-s-msn-com.akamaized.net (2 time(s), 19:56:26–21:17:57) | F-011 |
| 19:56:26 | 10.2.28.88 queried img-s-msn-com.akamaized.net (2 time(s), 19:56:26–21:17:57) | F-011 |
| 20:05:23 | 10.2.28.88 queried ecs.office.com (7 time(s), 20:05:23–23:04:13) | - |
| 20:07:24 | 10.2.28.88 queried acroipm2.adobe.com (2 time(s), 20:07:24–20:07:24) | F-006 |
| 20:07:24 | 10.2.28.88 → 23.218.232.161 HTTP activity to acroipm2.adobe.com (1 request(s): /assets/Owner/arm/ProcessMAU.txt) | F-006 |
| 20:07:28 | 10.2.28.88 queried armmf.adobe.com (4 time(s), 20:07:28–23:37:28) | - |
| 20:10:24 | 10.2.28.88 queried login.microsoftonline.com (31 time(s), 20:10:24–23:46:47) | F-007 |
| 20:10:25 | 10.2.28.88 queried settings-win.data.microsoft.com (25 time(s), 20:10:25–23:46:48) | - |
| 20:17:56 | 10.2.28.88 queried deff.nelreports.net (1 time(s), 20:17:56–20:17:56) | - |
| 20:17:56 | 10.2.28.88 queried deff.nelreports.net (1 time(s), 20:17:56–20:17:56) | - |
| 20:17:56 | 10.2.28.88 queried staticview.msn.com (1 time(s), 20:17:56–20:17:56) | - |
| 20:17:56 | 10.2.28.88 queried staticview.msn.com (1 time(s), 20:17:56–20:17:56) | - |
| 20:18:00 | 10.2.28.88 queried msedge.b.tlu.dl.delivery.mp.microsoft.com (8 time(s), 20:18:00–23:18:22) | - |
| 20:18:00 | 10.2.28.88 → 23.218.232.142 HTTP activity to msedge.b.tlu.dl.delivery.mp.microsoft.com (6 request(s): /filestreamingservice/files/ddbf4492-d475-4fe4-bcde-6cbac56f6034?P1=1772824359&P2=404&P3=2&P4=TMSkemQv9LZfDxme9Q9GxU0tc2G9uhdO6d7QU9JVJHOk%2ba0A4pJYzApqbFnNEQ6bt9QSukbCYOxGUmPIOR1Xgw%3d%3d, /filestreamingservice/files/0b18f766-7469-4aa3-88b7-99e69c55d14d?P1=1772628813&P2=404&P3=2&P4=P9O%2fZqV3zHEog%2f8GWjY1LjxEXlCShXCmvVwfgCjP6c7Xjf6q9SdV5Cxrlht3k8c6RsZdgDSm48GRm8J1Kej36Q%3d%3d) | - |
| 20:19:00 | 10.2.28.88 queried mobile.events.data.microsoft.com (5 time(s), 20:19:00–23:19:00) | - |
| 20:19:01 | 10.2.28.88 queried ocsp.digicert.com (3 time(s), 20:19:01–21:19:01) | F-013 |
| 20:19:01 | 10.2.28.88 → 23.204.150.28 HTTP activity to ocsp.digicert.com (2 request(s): /MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ50otx%2Fh0Ztl%2Bz8SiPI7wEWVxDlQQUTiJUIBiV5uNu5g%2F6%2BrkS7QYXjzkCEA77flR%2B3w%2FxBpruV2lte6A%3D, /MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ50otx%2Fh0Ztl%2Bz8SiPI7wEWVxDlQQUTiJUIBiV5uNu5g%2F6%2BrkS7QYXjzkCEAUZZSZEml49Gjh0j13P68w%3D) | F-013 |
| 20:38:13 | 10.2.28.88 queried licensing.mp.microsoft.com (2 time(s), 20:38:13–20:38:13) | - |
| 20:48:58 | 10.2.28.88 queried ctldl.windowsupdate.com (6 time(s), 20:48:58–22:50:01) | F-002 |
| 20:48:58 | 10.2.28.88 → 199.232.210.172 HTTP activity to ctldl.windowsupdate.com (3 request(s): /msdownload/update/v3/static/trustedr/en/authrootstl.cab?238f51c2ab526be6, /msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?4e25f6955dc4f675, /msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?a8cb64ce6f292067) | F-002 |
| 21:18:02 | 10.2.28.88 → 23.218.232.183 HTTP activity to msedge.b.tlu.dl.delivery.mp.microsoft.com (6 request(s): /filestreamingservice/files/86061e48-63b3-483f-8dac-609df0cbb238?P1=1772824359&P2=404&P3=2&P4=M%2br84JmdgFPOKPdw6GuIsCbfL0IaRRxCYqeiJbpH9IpxZr7vLbM4w9K8uMU5Ka6CyN%2fuMqIEMlyIHqGqCS8%2fXg%3d%3d) | - |
| 21:49:00 | 10.2.28.88 → 23.213.232.198 HTTP activity to ctldl.windowsupdate.com (3 request(s): /msdownload/update/v3/static/trustedr/en/authrootstl.cab?1fe5743cf489a795, /msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?d7d014dbf0b66d22, /msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?811956fd58fe307b) | F-002 |
| 22:18:12 | 10.2.28.88 → 23.218.232.166 HTTP activity to msedge.b.tlu.dl.delivery.mp.microsoft.com (7 request(s): /filestreamingservice/files/13d0ef9b-70c8-43c9-9a51-13c752dfb777?P1=1772817857&P2=404&P3=2&P4=NxsPWDqY%2fPRN4X5tyugkA%2bdfU9EeHebHQ3SqTAWWr5XPVngvgEZDtSFAEYlah9GHFrc%2bS%2fExNx3X0xGxvdOPow%3d%3d) | - |
| 22:50:01 | 10.2.28.88 → 23.213.232.101 HTTP activity to ctldl.windowsupdate.com (3 request(s): /msdownload/update/v3/static/trustedr/en/authrootstl.cab?957338f6d43a4cf5, /msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?d3434c35564aa4e5, /msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?fa2f866848cf44b7) | F-002 |
| 23:02:44 | 10.2.28.88 → 150.171.27.11 HTTP activity to edge.microsoft.com (1 request(s): /browsernetworktime/time/1/current?cup2key=2:cHFgppt5zfs9cbgaKCO2n0tk698hI27wU971tyrEQQg&cup2hreq=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855) | F-003 |
| 23:18:22 | 10.2.28.88 → 23.218.232.148 HTTP activity to msedge.b.tlu.dl.delivery.mp.microsoft.com (11 request(s): /filestreamingservice/files/2132f61f-f790-4ae6-a355-8cf9a1533800?P1=1772824359&P2=404&P3=2&P4=JBAPgdPQ5bbXP3YOD9Ig2AVW51pLa6vxUcHeGTEAadbzNEO5DlV3Wra1C9WqE7WnEd5RG1oYpt8saZgMxML1KA%3d%3d) | - |
| 23:20:38 | 10.2.28.88 queried update.googleapis.com (2 time(s), 23:20:38–23:20:38) | - |

## 6. IOC Inventory

This inventory lists every indicator extracted from the capture. Listing an indicator here does **not** imply it is malicious -- see the significance tier and Section 2 for which indicators actually became findings.

| Tier | Count |
|---|---|
| Insignificant | 148 |
| Noteworthy | 13 |
| Suspicious | 2 |
| High-Priority | 0 |


**Noteworthy and above:**

| Indicator | Type | Tier | Significance | Detection rule(s) | TI state(s) |
|---|---|---|---|---|---|
| vadusa.xyz | domain | suspicious | 29 | - | VirusTotal:MALICIOUS |
| 45.131.214.85 | ipv4 | suspicious | 28 | - | AbuseIPDB:CLEAN, VirusTotal:MALICIOUS |

## 7. Appendix

### 7.1 Threat-intelligence summary

- Indicators analyzed: 163
- Meaningful TI matches (Suspicious/Malicious): 6
- Weak reputation (not a finding on its own): 43
- Clean / no meaningful record: 372

### 7.2 Raw threat-intelligence results (including no-record lookups)

| IOC | Feed | State | Confidence | Summary |
|---|---|---|---|---|
| 104.208.203.89 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 3 report(s), last reported 39d ago. Interpreted as Weak Reputation. |
| 104.208.203.89 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 104.208.203.89 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 104.46.162.224 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 11/100 from 32 report(s), last reported 21d ago. Interpreted as Weak Reputation. |
| 104.46.162.224 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 104.46.162.224 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 13.107.213.57 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 1205d ago. Interpreted as Clean. |
| 13.107.213.57 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 13.107.213.57 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 13.107.246.57 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 357d ago. Interpreted as Clean. |
| 13.107.246.57 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 13.107.246.57 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 13.69.116.109 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 8 report(s), last reported 49d ago. Interpreted as Weak Reputation. |
| 13.69.116.109 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 13.69.116.109 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 13.70.79.200 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 6 report(s), last reported 79d ago. Interpreted as Weak Reputation. |
| 13.70.79.200 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 13.70.79.200 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 13.89.178.27 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 11 report(s), last reported 75d ago. Interpreted as Weak Reputation. |
| 13.89.178.27 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 13.89.178.27 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 13.89.179.13 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 7 report(s), last reported 75d ago. Interpreted as Weak Reputation. |
| 13.89.179.13 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 13.89.179.13 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 13.89.179.14 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 5 report(s), last reported 77d ago. Interpreted as Weak Reputation. |
| 13.89.179.14 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 13.89.179.14 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 13.89.179.8 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 9 report(s), last reported 75d ago. Interpreted as Weak Reputation. |
| 13.89.179.8 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 13.89.179.8 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 13.89.179.9 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 7 report(s), last reported 75d ago. Interpreted as Weak Reputation. |
| 13.89.179.9 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 13.89.179.9 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 135.234.160.246 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 16/100 from 23 report(s), last reported 18d ago. Interpreted as Weak Reputation. |
| 135.234.160.246 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 135.234.160.246 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 142.250.138.94 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 1 report(s), last reported 16d ago. Interpreted as Weak Reputation. |
| 142.250.138.94 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 142.250.138.94 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 150.171.22.17 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 21/100 from 9 report(s), last reported 5d ago. Interpreted as Weak Reputation. |
| 150.171.22.17 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 150.171.22.17 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 150.171.27.11 | AbuseIPDB | SUSPICIOUS | Medium | AbuseIPDB abuse confidence 37/100 from 53 report(s), last reported 3d ago. Interpreted as Suspicious. |
| 150.171.27.11 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 150.171.27.11 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 150.171.27.12 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 9/100 from 9 report(s), last reported 25d ago. Interpreted as Weak Reputation. |
| 150.171.27.12 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 150.171.27.12 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 150.171.28.11 | AbuseIPDB | SUSPICIOUS | Medium | AbuseIPDB abuse confidence 26/100 from 13 report(s), last reported 4d ago. Interpreted as Suspicious. |
| 150.171.28.11 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 150.171.28.11 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 150.171.28.12 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 10/100 from 3 report(s), last reported 18d ago. Interpreted as Weak Reputation. |
| 150.171.28.12 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 150.171.28.12 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 184.29.31.84 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 1/100 from 1 report(s), last reported 19d ago. Interpreted as Weak Reputation. |
| 184.29.31.84 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 184.29.31.84 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 199.232.210.172 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 56 report(s), last reported 0d ago. Interpreted as Weak Reputation. |
| 199.232.210.172 | VirusTotal | SUSPICIOUS | Medium | VirusTotal: 2/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Suspicious. |
| 199.232.210.172 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.106.86.13 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 139d ago. Interpreted as Clean. |
| 20.106.86.13 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.106.86.13 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.189.173.1 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 114d ago. Interpreted as Clean. |
| 20.189.173.1 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.189.173.1 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.189.173.14 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 116d ago. Interpreted as Clean. |
| 20.189.173.14 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.189.173.14 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.189.173.2 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 8 report(s), last reported 77d ago. Interpreted as Weak Reputation. |
| 20.189.173.2 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.189.173.2 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.189.173.8 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 113d ago. Interpreted as Clean. |
| 20.189.173.8 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.189.173.8 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.190.135.16 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 4/100 from 82 report(s), last reported 17d ago. Interpreted as Weak Reputation. |
| 20.190.135.16 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.190.135.16 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.190.135.3 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 13/100 from 88 report(s), last reported 17d ago. Interpreted as Weak Reputation. |
| 20.190.135.3 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.190.135.3 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.190.135.4 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 13/100 from 84 report(s), last reported 17d ago. Interpreted as Weak Reputation. |
| 20.190.135.4 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.190.135.4 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.190.135.7 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 4/100 from 84 report(s), last reported 17d ago. Interpreted as Weak Reputation. |
| 20.190.135.7 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.190.135.7 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.190.157.14 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 5/100 from 88 report(s), last reported 17d ago. Interpreted as Weak Reputation. |
| 20.190.157.14 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.190.157.14 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.190.157.4 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 13/100 from 89 report(s), last reported 18d ago. Interpreted as Weak Reputation. |
| 20.190.157.4 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.190.157.4 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.190.157.9 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 13/100 from 93 report(s), last reported 17d ago. Interpreted as Weak Reputation. |
| 20.190.157.9 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.190.157.9 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.42.65.84 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 23/100 from 43 report(s), last reported 9d ago. Interpreted as Weak Reputation. |
| 20.42.65.84 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.42.65.84 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.42.65.88 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 21/100 from 38 report(s), last reported 3d ago. Interpreted as Weak Reputation. |
| 20.42.65.88 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.42.65.88 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.42.65.94 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 21/100 from 45 report(s), last reported 15d ago. Interpreted as Weak Reputation. |
| 20.42.65.94 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.42.65.94 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.42.73.30 | AbuseIPDB | SUSPICIOUS | Medium | AbuseIPDB abuse confidence 26/100 from 47 report(s), last reported 13d ago. Interpreted as Suspicious. |
| 20.42.73.30 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.42.73.30 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.49.150.241 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 146d ago. Interpreted as Clean. |
| 20.49.150.241 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.49.150.241 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.72.205.209 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 151d ago. Interpreted as Clean. |
| 20.72.205.209 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.72.205.209 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 20.96.153.111 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 0/100 from 1 report(s), last reported 80d ago. Interpreted as Weak Reputation. |
| 20.96.153.111 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 20.96.153.111 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 204.79.197.203 | AbuseIPDB | WEAK_REPUTATION | Low | AbuseIPDB abuse confidence 9/100 from 6 report(s), last reported 16d ago. Interpreted as Weak Reputation. |
| 204.79.197.203 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 204.79.197.203 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.192.223.16 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.192.223.16 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.192.223.16 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.192.223.17 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.192.223.17 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.192.223.17 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.192.223.23 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.192.223.23 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.192.223.23 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.192.223.5 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.192.223.5 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.192.223.5 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.204.150.28 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), last reported 465d ago. Interpreted as Clean. |
| 23.204.150.28 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.204.150.28 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.205.110.136 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.205.110.136 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.205.110.136 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.205.110.140 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.205.110.140 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.205.110.140 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.205.110.142 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.205.110.142 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.205.110.142 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.205.110.145 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.205.110.145 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.205.110.145 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |
| 23.205.110.151 | AbuseIPDB | CLEAN | High | AbuseIPDB abuse confidence 0/100 from 0 report(s), no reported date on file. Interpreted as Clean. |
| 23.205.110.151 | VirusTotal | CLEAN | High | VirusTotal: 0/89 vendor(s) flagged malicious, 0 suspicious. Interpreted as Clean. |
| 23.205.110.151 | URLhaus | UNKNOWN | Low | No URLhaus record found for this indicator. |

### 7.3 Suppressed and low-confidence detection signals

| Rule | Indicator | Suppression reason | Matched allowlist entry | Occurrences |
|---|---|---|---|---|
| DNS-001 | settings-win.data.microsoft.com | known_legitimate_infrastructure | microsoft.com | 25 |
| DNS-003 | settings-win.data.microsoft.com | known_legitimate_infrastructure | microsoft.com | 25 |
| DNS-001 | v10.events.data.microsoft.com | known_legitimate_infrastructure | microsoft.com | 22 |
| DNS-001 | edge.microsoft.com | known_legitimate_infrastructure | microsoft.com | 15 |
| DNS-001 | edge.microsoft.com | known_legitimate_infrastructure | microsoft.com | 15 |
| DNS-001 | self.events.data.microsoft.com | known_legitimate_infrastructure | microsoft.com | 9 |
| DNS-001 | msedge.b.tlu.dl.delivery.mp.microsoft.com | known_legitimate_infrastructure | microsoft.com | 8 |
| DNS-003 | licensing.mp.microsoft.com | known_legitimate_infrastructure | microsoft.com | 2 |
| DNS-007 | microsoft.com | known_legitimate_infrastructure | microsoft.com | 107 |

### 7.4 Detection tuning report

| Rule | Title | Triggered | Suppressed | In findings | Avg. confidence | Avg. score |
|---|---|---|---|---|---|---|
| DNS-001 | Excessive DNS Frequency | 11 | 6 | 5 | Medium | 6.0 |
| DNS-002 | High NXDOMAIN Ratio | 4 | 0 | 4 | Medium | 10.0 |
| DNS-003 | Potential Algorithmically Generated Domain | 7 | 2 | 4 | Medium | 8.6 |
| DNS-007 | Excessive Unique Subdomains | 3 | 1 | 0 | Medium | 10.0 |
| HTTP-004 | Rare External Host | 2 | 0 | 2 | Low | 2.0 |

### 7.5 Observability / pipeline statistics

| Metric | Count |
|---|---|
| Raw packets | 15512 |
| Raw DNS observations | 831 |
| Raw HTTP observations | 88 |
| Raw file observations | 0 |
| Behavioral events (DNS) | 62 |
| Behavioral events (HTTP) | 11 |
| Behavioral events (File) | 0 |
| Detection signals raised | 27 |
| Detection signals suppressed | 9 |
| Correlation candidates evaluated | 62 |
| Findings before deduplication | 17 |
| Findings after deduplication | 15 |

### 7.6 Limitations

- Encrypted traffic cannot be inspected beyond metadata.
- DNS response data (resolved IPs, response codes) is merged into every client bucket for the same (domain, query type) pair, since this layer does not retain DNS transaction IDs; captures with multiple distinct clients querying the same domain in the same run may see resolved-IP data shared across those clients' behavioral events.
- The apex-domain grouping used for DNS-007 is a last-two-labels approximation and is not authoritative for multi-part TLDs (e.g. .co.uk).
- Asset role/criticality context is not available in this environment; every finding explicitly reports 'Asset role: Unknown' rather than guessing at criticality.
- Threat-intelligence feeds are rate-limited and may be unavailable at scan time; the report states this explicitly rather than treating an unavailable feed as a clean result.
- The risk score is a project-defined prioritization aid, not an industry-standard rating, and a single indicator match is never proof of compromise on its own.

### 7.7 References

- AbuseIPDB — <https://www.abuseipdb.com>
- VirusTotal — <https://www.virustotal.com>
- URLhaus (abuse.ch) — <https://urlhaus.abuse.ch>

## Conclusion

This analysis identified findings of Low or Medium severity only. None reached High or Critical severity; the correlated evidence above warrants routine follow-up consistent with local SOC procedure.
