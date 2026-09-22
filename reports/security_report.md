# Threat Intelligence & Network Security Analysis Report

- **PCAP file:** `pcaps/sample.pcap`
- **Analysis date:** 2026-09-22 14:22 UTC
- **Tool:** Threat Intelligence Automation Tool v1.0.0
- **Analyst:** SOC Analyst
- **Classification:** Security Analysis

---

## Introduction

This report documents the automated analysis of `pcaps/sample.pcap` (15512 packets), performed by the Threat Intelligence Automation Tool. The tool extracts network, DNS, HTTP and file-transfer metadata from the capture, identifies indicators of compromise (IOCs), correlates those indicators against three threat-intelligence feeds (AbuseIPDB, VirusTotal, URLhaus), and reports the resulting findings here for SOC analyst review.

## Scope and Objective

**Objective:** determine whether the supplied packet capture contains evidence of suspicious or malicious network activity, using packet-level detection combined with external threat-intelligence correlation.

**Scope:** analysis is limited to what is observable in the supplied PCAP file. Encrypted payloads are not decrypted. Threat-intelligence results reflect each feed's data at the time of the scan and are subject to that feed's own coverage and rate limits. This tool assists triage; it does not itself constitute a compromise determination.

## Findings and Recommendations

### Network Analysis

15512 packets analyzed, covering 95 unique public IP indicator(s) and 49 unique domain(s).

**Protocol distribution**

| Protocol | Packet Count |
|---|---|
| UDP | 2113 |
| Ether | 836 |
| TCP | 12544 |
| IP-PROTO-1 | 19 |

**Top source IPs**

| Source IP | Packet Count |
|---|---|
| 10.2.28.88 | 7405 |
| 10.2.28.2 | 2326 |
| 23.64.147.24 | 823 |
| 23.218.232.148 | 743 |
| 45.131.214.85 | 274 |
| 150.171.28.11 | 256 |
| 23.192.223.23 | 176 |
| 23.41.251.53 | 143 |
| 104.208.203.89 | 140 |
| 23.192.223.16 | 135 |

**Top destination IPs**

| Destination IP | Packet Count |
|---|---|
| 10.2.28.88 | 7268 |
| 10.2.28.2 | 2743 |
| 10.2.28.255 | 497 |
| 23.64.147.24 | 445 |
| 23.218.232.148 | 387 |
| 45.131.214.85 | 276 |
| 150.171.28.11 | 219 |
| 23.192.223.23 | 178 |
| 104.208.203.89 | 162 |
| 23.41.251.53 | 124 |

**Top destination ports**

| Destination Port | Packet Count |
|---|---|
| 443 | 3598 |
| 445 | 825 |
| 51911 | 823 |
| 62035 | 739 |
| 389 | 623 |
| 80 | 533 |
| 49671 | 470 |
| 53 | 443 |
| 138 | 430 |
| 135 | 283 |

**DNS activity**

| Query | Type | Resolved IP(s) | Source IP |
|---|---|---|---|
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net | 33 | - | 10.2.28.88 |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.easyas123.tech | 33 | - | 10.2.28.88 |
| _ldap._tcp.Default-First-Site-Name._sites.easyas123.tech | 33 | - | 10.2.28.88 |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.easyas123.tech | 33 | - | 10.2.28.2 |
| _ldap._tcp.Default-First-Site-Name._sites.easyas123.tech | 33 | - | 10.2.28.2 |
| easyas123-dc.easyas123.tech | A | - | 10.2.28.88 |
| easyas123-dc.easyas123.tech | A | 10.2.28.2 | 10.2.28.2 |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net | 33 | - | 10.2.28.88 |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.easyas123.tech | 33 | - | 10.2.28.88 |
| _ldap._tcp.Default-First-Site-Name._sites.easyas123.tech | 33 | - | 10.2.28.88 |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.easyas123.tech | 33 | - | 10.2.28.2 |
| _ldap._tcp.Default-First-Site-Name._sites.easyas123.tech | 33 | - | 10.2.28.2 |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net | 33 | - | 10.2.28.2 |
| _ldap._tcp.dc._msdcs.mshome.net | 33 | - | 10.2.28.88 |
| _ldap._tcp.dc._msdcs.mshome.net | 33 | - | 10.2.28.88 |
| _ldap._tcp.dc._msdcs.mshome.net | 33 | - | 10.2.28.2 |
| wpad.easyas123.tech | A | - | 10.2.28.88 |
| wpad.easyas123.tech | A | - | 10.2.28.88 |
| wpad.easyas123.tech | A | - | 10.2.28.2 |
| wpad.easyas123.tech | A | - | 10.2.28.2 |
| wpad.mshome.net | A | - | 10.2.28.88 |
| wpad.mshome.net | A | - | 10.2.28.88 |
| wpad.mshome.net | A | - | 10.2.28.2 |
| wpad.mshome.net | A | - | 10.2.28.2 |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net | 33 | - | 10.2.28.88 |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net | 33 | - | 10.2.28.2 |
| _ldap._tcp.dc._msdcs.mshome.net | 33 | - | 10.2.28.88 |
| _ldap._tcp.dc._msdcs.mshome.net | 33 | - | 10.2.28.2 |
| www.msftconnecttest.com | A | - | 10.2.28.88 |
| www.msftconnecttest.com | A | - | 10.2.28.88 |
| www.msftconnecttest.com | A | ncsi-geo.trafficmanager.net. | 10.2.28.2 |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net | 33 | - | 10.2.28.88 |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net | 33 | - | 10.2.28.2 |
| _ldap._tcp.dc._msdcs.mshome.net | 33 | - | 10.2.28.88 |
| _ldap._tcp.dc._msdcs.mshome.net | 33 | - | 10.2.28.2 |
| v10.events.data.microsoft.com | A | - | 10.2.28.88 |
| v10.events.data.microsoft.com | A | win-global-asimov-leafs-events-data.trafficmanager.net. | 10.2.28.2 |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net | 33 | - | 10.2.28.88 |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net | 33 | - | 10.2.28.2 |
| client.wns.windows.com | A | - | 10.2.28.88 |

**HTTP activity**

| Method | Host | Path | User-Agent / Status |
|---|---|---|---|
| GET | www.msftconnecttest.com | /connecttest.txt | Microsoft NCSI |
| - | - | - | 200 |
| GET | acroipm2.adobe.com | /assets/Owner/arm/ProcessMAU.txt | Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729) |
| - | - | - | 304 |
| HEAD | msedge.b.tlu.dl.delivery.mp.microsoft.com | /filestreamingservice/files/ddbf4492-d475-4fe4-bcde-6cbac56f6034?P1=1772824359&P2=404&P3=2&P4=TMSkemQv9LZfDxme9Q9GxU0tc2G9uhdO6d7QU9JVJHOk%2ba0A4pJYzApqbFnNEQ6bt9QSukbCYOxGUmPIOR1Xgw%3d%3d | Microsoft BITS/7.8 |
| - | - | - | 200 |
| GET | msedge.b.tlu.dl.delivery.mp.microsoft.com | /filestreamingservice/files/ddbf4492-d475-4fe4-bcde-6cbac56f6034?P1=1772824359&P2=404&P3=2&P4=TMSkemQv9LZfDxme9Q9GxU0tc2G9uhdO6d7QU9JVJHOk%2ba0A4pJYzApqbFnNEQ6bt9QSukbCYOxGUmPIOR1Xgw%3d%3d | Microsoft BITS/7.8 |
| - | - | - | 206 |
| GET | msedge.b.tlu.dl.delivery.mp.microsoft.com | /filestreamingservice/files/ddbf4492-d475-4fe4-bcde-6cbac56f6034?P1=1772824359&P2=404&P3=2&P4=TMSkemQv9LZfDxme9Q9GxU0tc2G9uhdO6d7QU9JVJHOk%2ba0A4pJYzApqbFnNEQ6bt9QSukbCYOxGUmPIOR1Xgw%3d%3d | Microsoft BITS/7.8 |
| - | - | - | 206 |
| HEAD | msedge.b.tlu.dl.delivery.mp.microsoft.com | /filestreamingservice/files/0b18f766-7469-4aa3-88b7-99e69c55d14d?P1=1772628813&P2=404&P3=2&P4=P9O%2fZqV3zHEog%2f8GWjY1LjxEXlCShXCmvVwfgCjP6c7Xjf6q9SdV5Cxrlht3k8c6RsZdgDSm48GRm8J1Kej36Q%3d%3d | Microsoft BITS/7.8 |
| - | - | - | 200 |
| GET | msedge.b.tlu.dl.delivery.mp.microsoft.com | /filestreamingservice/files/0b18f766-7469-4aa3-88b7-99e69c55d14d?P1=1772628813&P2=404&P3=2&P4=P9O%2fZqV3zHEog%2f8GWjY1LjxEXlCShXCmvVwfgCjP6c7Xjf6q9SdV5Cxrlht3k8c6RsZdgDSm48GRm8J1Kej36Q%3d%3d | Microsoft BITS/7.8 |
| - | - | - | 206 |
| GET | msedge.b.tlu.dl.delivery.mp.microsoft.com | /filestreamingservice/files/0b18f766-7469-4aa3-88b7-99e69c55d14d?P1=1772628813&P2=404&P3=2&P4=P9O%2fZqV3zHEog%2f8GWjY1LjxEXlCShXCmvVwfgCjP6c7Xjf6q9SdV5Cxrlht3k8c6RsZdgDSm48GRm8J1Kej36Q%3d%3d | Microsoft BITS/7.8 |
| - | - | - | 206 |
| GET | ocsp.digicert.com | /MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ50otx%2Fh0Ztl%2Bz8SiPI7wEWVxDlQQUTiJUIBiV5uNu5g%2F6%2BrkS7QYXjzkCEA77flR%2B3w%2FxBpruV2lte6A%3D | Microsoft-CryptoAPI/10.0 |
| - | - | - | 200 |
| GET | ctldl.windowsupdate.com | /msdownload/update/v3/static/trustedr/en/authrootstl.cab?238f51c2ab526be6 | Microsoft-CryptoAPI/10.0 |
| - | - | - | 304 |
| GET | ctldl.windowsupdate.com | /msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?4e25f6955dc4f675 | Microsoft-CryptoAPI/10.0 |
| - | - | - | 304 |
| GET | ctldl.windowsupdate.com | /msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?a8cb64ce6f292067 | Microsoft-CryptoAPI/10.0 |
| - | - | - | 304 |
| HEAD | msedge.b.tlu.dl.delivery.mp.microsoft.com | /filestreamingservice/files/86061e48-63b3-483f-8dac-609df0cbb238?P1=1772824359&P2=404&P3=2&P4=M%2br84JmdgFPOKPdw6GuIsCbfL0IaRRxCYqeiJbpH9IpxZr7vLbM4w9K8uMU5Ka6CyN%2fuMqIEMlyIHqGqCS8%2fXg%3d%3d | Microsoft BITS/7.8 |
| - | - | - | 200 |
| GET | msedge.b.tlu.dl.delivery.mp.microsoft.com | /filestreamingservice/files/86061e48-63b3-483f-8dac-609df0cbb238?P1=1772824359&P2=404&P3=2&P4=M%2br84JmdgFPOKPdw6GuIsCbfL0IaRRxCYqeiJbpH9IpxZr7vLbM4w9K8uMU5Ka6CyN%2fuMqIEMlyIHqGqCS8%2fXg%3d%3d | Microsoft BITS/7.8 |
| - | - | - | 206 |
| GET | msedge.b.tlu.dl.delivery.mp.microsoft.com | /filestreamingservice/files/86061e48-63b3-483f-8dac-609df0cbb238?P1=1772824359&P2=404&P3=2&P4=M%2br84JmdgFPOKPdw6GuIsCbfL0IaRRxCYqeiJbpH9IpxZr7vLbM4w9K8uMU5Ka6CyN%2fuMqIEMlyIHqGqCS8%2fXg%3d%3d | Microsoft BITS/7.8 |
| - | - | - | 206 |
| GET | msedge.b.tlu.dl.delivery.mp.microsoft.com | /filestreamingservice/files/86061e48-63b3-483f-8dac-609df0cbb238?P1=1772824359&P2=404&P3=2&P4=M%2br84JmdgFPOKPdw6GuIsCbfL0IaRRxCYqeiJbpH9IpxZr7vLbM4w9K8uMU5Ka6CyN%2fuMqIEMlyIHqGqCS8%2fXg%3d%3d | Microsoft BITS/7.8 |
| - | - | - | 206 |
| GET | msedge.b.tlu.dl.delivery.mp.microsoft.com | /filestreamingservice/files/86061e48-63b3-483f-8dac-609df0cbb238?P1=1772824359&P2=404&P3=2&P4=M%2br84JmdgFPOKPdw6GuIsCbfL0IaRRxCYqeiJbpH9IpxZr7vLbM4w9K8uMU5Ka6CyN%2fuMqIEMlyIHqGqCS8%2fXg%3d%3d | Microsoft BITS/7.8 |
| - | - | - | 206 |
| GET | msedge.b.tlu.dl.delivery.mp.microsoft.com | /filestreamingservice/files/86061e48-63b3-483f-8dac-609df0cbb238?P1=1772824359&P2=404&P3=2&P4=M%2br84JmdgFPOKPdw6GuIsCbfL0IaRRxCYqeiJbpH9IpxZr7vLbM4w9K8uMU5Ka6CyN%2fuMqIEMlyIHqGqCS8%2fXg%3d%3d | Microsoft BITS/7.8 |
| - | - | - | 206 |
| GET | ocsp.digicert.com | /MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ50otx%2Fh0Ztl%2Bz8SiPI7wEWVxDlQQUTiJUIBiV5uNu5g%2F6%2BrkS7QYXjzkCEAUZZSZEml49Gjh0j13P68w%3D | Microsoft-CryptoAPI/10.0 |
| - | - | - | 200 |
| GET | ctldl.windowsupdate.com | /msdownload/update/v3/static/trustedr/en/authrootstl.cab?1fe5743cf489a795 | Microsoft-CryptoAPI/10.0 |
| - | - | - | 304 |

**Files and file signatures**

No complete files could be reassembled from the supplied PCAP. This is expected for encrypted transfers or captures without full TCP streams.

### Threat Detection

Local, rule-based detections generated directly from the PCAP (log-based and PCAP-based threats). Each is explicitly classified; none is labeled malicious on local heuristics alone.

| ID | Time (UTC) | Category | Classification | IOC | Evidence |
|---|---|---|---|---|---|
| DET-001 | 19:55:51 | Suspicious DNS Query | Suspicious | vadusa.xyz | DNS query for vadusa.xyz |
| DET-002 | 19:55:51 | Suspicious DNS Query | Suspicious | vadusa.xyz | DNS query for vadusa.xyz |
| DET-003 | 19:55:51 | Suspicious DNS Query | Suspicious | vadusa.xyz | DNS query for vadusa.xyz |
| DET-004 | 19:56:26 | Possible DGA-like Domain | Suspicious | img-s-msn-com.akamaized.net | DNS query for img-s-msn-com.akamaized.net |
| DET-005 | 19:56:26 | Possible DGA-like Domain | Suspicious | img-s-msn-com.akamaized.net | DNS query for img-s-msn-com.akamaized.net |
| DET-006 | 19:56:26 | Possible DGA-like Domain | Suspicious | img-s-msn-com.akamaized.net | DNS query for img-s-msn-com.akamaized.net |
| DET-007 | 19:56:27 | Possible DGA-like Domain | Suspicious | img-s-msn-com.akamaized.net | DNS query for img-s-msn-com.akamaized.net |
| DET-008 | 21:17:57 | Possible DGA-like Domain | Suspicious | img-s-msn-com.akamaized.net | DNS query for img-s-msn-com.akamaized.net |
| DET-009 | 21:17:57 | Possible DGA-like Domain | Suspicious | img-s-msn-com.akamaized.net | DNS query for img-s-msn-com.akamaized.net |
| DET-010 | 21:17:57 | Possible DGA-like Domain | Suspicious | img-s-msn-com.akamaized.net | DNS query for img-s-msn-com.akamaized.net |
| DET-011 | 21:17:58 | Possible DGA-like Domain | Suspicious | img-s-msn-com.akamaized.net | DNS query for img-s-msn-com.akamaized.net |

### Threat Intelligence Correlation

| IOC | Type | Feed | Result | Confidence |
|---|---|---|---|---|
| 104.208.203.89 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 3 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-08-14T18:08:07+00:00. | Low |
| 104.208.203.89 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 104.208.203.89 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 104.46.162.224 | ipv4 | AbuseIPDB | Abuse confidence score 11/100 from 32 report(s). Country: AU, ISP: Microsoft Corporation. Last reported: 2026-09-01T02:15:04+00:00. | Low |
| 104.46.162.224 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 104.46.162.224 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 13.107.213.57 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2023-06-05T14:21:29+00:00. | Low |
| 13.107.213.57 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 13.107.213.57 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 13.107.246.57 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2025-09-30T11:41:36+00:00. | Low |
| 13.107.246.57 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 13.107.246.57 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 13.69.116.109 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 8 report(s). Country: NL, ISP: Microsoft Corporation. Last reported: 2026-08-04T10:55:10+00:00. | Low |
| 13.69.116.109 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 13.69.116.109 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 13.70.79.200 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 6 report(s). Country: AU, ISP: Microsoft Corporation. Last reported: 2026-07-05T16:58:12+00:00. | Low |
| 13.70.79.200 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 13.70.79.200 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 13.89.178.27 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 11 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-09T09:14:44+00:00. | Low |
| 13.89.178.27 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 13.89.178.27 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 13.89.179.13 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 7 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-09T11:43:08+00:00. | Low |
| 13.89.179.13 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 13.89.179.13 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 13.89.179.14 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 5 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-07T05:14:57+00:00. | Low |
| 13.89.179.14 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 13.89.179.14 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 13.89.179.8 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 9 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-08T23:40:18+00:00. | Low |
| 13.89.179.8 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 13.89.179.8 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 13.89.179.9 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 7 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-09T01:58:58+00:00. | Low |
| 13.89.179.9 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 13.89.179.9 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 135.234.160.246 | ipv4 | AbuseIPDB | Abuse confidence score 16/100 from 23 report(s). Country: US, ISP: Microsoft Limited. Last reported: 2026-09-04T20:26:04+00:00. | Low |
| 135.234.160.246 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 135.234.160.246 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 142.250.138.94 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 1 report(s). Country: US, ISP: Google LLC. Last reported: 2026-09-06T06:12:31+00:00. | Low |
| 142.250.138.94 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 142.250.138.94 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 150.171.22.17 | ipv4 | AbuseIPDB | Abuse confidence score 21/100 from 9 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-17T05:50:17+00:00. | Low |
| 150.171.22.17 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 150.171.22.17 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 150.171.27.11 | ipv4 | AbuseIPDB | Abuse confidence score 37/100 from 53 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-18T23:55:58+00:00. | Medium |
| 150.171.27.11 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 150.171.27.11 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 150.171.27.12 | ipv4 | AbuseIPDB | Abuse confidence score 9/100 from 9 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-08-28T03:22:09+00:00. | Low |
| 150.171.27.12 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 150.171.27.12 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 150.171.28.11 | ipv4 | AbuseIPDB | Abuse confidence score 26/100 from 13 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-18T07:40:45+00:00. | Medium |
| 150.171.28.11 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 150.171.28.11 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 150.171.28.12 | ipv4 | AbuseIPDB | Abuse confidence score 10/100 from 3 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-04T17:31:12+00:00. | Low |
| 150.171.28.12 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 150.171.28.12 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 184.29.31.84 | ipv4 | AbuseIPDB | Abuse confidence score 1/100 from 1 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: 2026-09-03T11:29:48+00:00. | Low |
| 184.29.31.84 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 184.29.31.84 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 199.232.210.172 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 56 report(s). Country: US, ISP: Fastly, Inc.. Last reported: 2026-09-21T23:12:25+00:00. | Low |
| 199.232.210.172 | ipv4 | VirusTotal | 2/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Medium |
| 199.232.210.172 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.106.86.13 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-05-06T14:03:04+00:00. | Low |
| 20.106.86.13 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.106.86.13 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.189.173.1 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-05-31T06:00:37+00:00. | Low |
| 20.189.173.1 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.189.173.1 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.189.173.14 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-05-29T05:30:25+00:00. | Low |
| 20.189.173.14 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.189.173.14 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.189.173.2 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 8 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-07T09:40:09+00:00. | Low |
| 20.189.173.2 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.189.173.2 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.189.173.8 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-06-01T03:30:09+00:00. | Low |
| 20.189.173.8 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.189.173.8 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.190.135.16 | ipv4 | AbuseIPDB | Abuse confidence score 4/100 from 82 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T07:07:53+00:00. | Low |
| 20.190.135.16 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.190.135.16 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.190.135.3 | ipv4 | AbuseIPDB | Abuse confidence score 13/100 from 88 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T10:52:01+00:00. | Low |
| 20.190.135.3 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.190.135.3 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.190.135.4 | ipv4 | AbuseIPDB | Abuse confidence score 13/100 from 84 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T10:57:54+00:00. | Low |
| 20.190.135.4 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.190.135.4 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.190.135.7 | ipv4 | AbuseIPDB | Abuse confidence score 4/100 from 84 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T08:58:34+00:00. | Low |
| 20.190.135.7 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.190.135.7 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.190.157.14 | ipv4 | AbuseIPDB | Abuse confidence score 5/100 from 88 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T00:35:51+00:00. | Low |
| 20.190.157.14 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.190.157.14 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.190.157.4 | ipv4 | AbuseIPDB | Abuse confidence score 13/100 from 89 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-04T13:22:26+00:00. | Low |
| 20.190.157.4 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.190.157.4 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.190.157.9 | ipv4 | AbuseIPDB | Abuse confidence score 13/100 from 93 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T09:03:40+00:00. | Low |
| 20.190.157.9 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.190.157.9 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.42.65.84 | ipv4 | AbuseIPDB | Abuse confidence score 23/100 from 43 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-13T07:40:11+00:00. | Low |
| 20.42.65.84 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.42.65.84 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.42.65.88 | ipv4 | AbuseIPDB | Abuse confidence score 21/100 from 38 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-18T23:55:58+00:00. | Low |
| 20.42.65.88 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.42.65.88 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.42.65.94 | ipv4 | AbuseIPDB | Abuse confidence score 21/100 from 45 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-07T18:43:02+00:00. | Low |
| 20.42.65.94 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.42.65.94 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.42.73.30 | ipv4 | AbuseIPDB | Abuse confidence score 26/100 from 47 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-09T08:59:56+00:00. | Medium |
| 20.42.73.30 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.42.73.30 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.49.150.241 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: GB, ISP: Microsoft Corporation. Last reported: 2026-04-29T14:02:20+00:00. | Low |
| 20.49.150.241 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.49.150.241 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.72.205.209 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-04-24T00:49:06+00:00. | Low |
| 20.72.205.209 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.72.205.209 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 20.96.153.111 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 1 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-04T13:20:15+00:00. | Low |
| 20.96.153.111 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 20.96.153.111 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 204.79.197.203 | ipv4 | AbuseIPDB | Abuse confidence score 9/100 from 6 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-06T16:33:41+00:00. | Low |
| 204.79.197.203 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 204.79.197.203 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.192.223.16 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.192.223.16 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.192.223.16 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.192.223.17 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.192.223.17 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.192.223.17 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.192.223.23 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.192.223.23 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.192.223.23 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.192.223.5 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.192.223.5 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.192.223.5 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.204.150.28 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: 2025-06-14T03:50:33+00:00. | Low |
| 23.204.150.28 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.204.150.28 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.205.110.136 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.205.110.136 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.205.110.136 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.205.110.140 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.205.110.140 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.205.110.140 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.205.110.142 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.205.110.142 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.205.110.142 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.205.110.145 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.205.110.145 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.205.110.145 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.205.110.151 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.205.110.151 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.205.110.151 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.205.110.155 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.205.110.155 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.205.110.155 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.213.232.101 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.213.232.101 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.213.232.101 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.213.232.198 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.213.232.198 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.213.232.198 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.218.232.142 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: 2025-08-25T22:53:19+00:00. | Low |
| 23.218.232.142 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.218.232.142 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.218.232.148 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.218.232.148 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.218.232.148 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.218.232.156 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.218.232.156 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.218.232.156 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.218.232.161 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.218.232.161 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.218.232.161 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.218.232.166 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: 2025-02-27T19:05:03+00:00. | Low |
| 23.218.232.166 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.218.232.166 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.218.232.170 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.218.232.170 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.218.232.170 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.218.232.174 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.218.232.174 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.218.232.174 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.218.232.183 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.218.232.183 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.218.232.183 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.41.251.53 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.41.251.53 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.41.251.53 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.47.50.182 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai International, BV. Last reported: None. | Low |
| 23.47.50.182 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.47.50.182 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.55.178.208 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.55.178.208 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.55.178.208 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.55.178.219 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.55.178.219 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.55.178.219 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.60.174.202 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.60.174.202 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.60.174.202 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.64.115.206 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.64.115.206 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.64.115.206 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 23.64.147.24 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: None. | Low |
| 23.64.147.24 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 23.64.147.24 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 4.149.160.182 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 1 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-13T08:48:38+00:00. | Low |
| 4.149.160.182 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 4.149.160.182 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 40.119.249.228 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: SG, ISP: Microsoft Corporation. Last reported: 2026-04-02T00:37:18+00:00. | Low |
| 40.119.249.228 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 40.119.249.228 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 40.126.28.12 | ipv4 | AbuseIPDB | Abuse confidence score 13/100 from 89 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-04T23:59:48+00:00. | Low |
| 40.126.28.12 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 40.126.28.12 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 40.126.28.13 | ipv4 | AbuseIPDB | Abuse confidence score 5/100 from 90 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T06:58:10+00:00. | Low |
| 40.126.28.13 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 40.126.28.13 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 40.126.29.10 | ipv4 | AbuseIPDB | Abuse confidence score 5/100 from 83 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T04:09:34+00:00. | Low |
| 40.126.29.10 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 40.126.29.10 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 40.126.29.13 | ipv4 | AbuseIPDB | Abuse confidence score 5/100 from 87 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-04T21:09:32+00:00. | Low |
| 40.126.29.13 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 40.126.29.13 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 40.126.29.15 | ipv4 | AbuseIPDB | Abuse confidence score 13/100 from 85 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T02:32:14+00:00. | Low |
| 40.126.29.15 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 40.126.29.15 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 40.126.29.5 | ipv4 | AbuseIPDB | Abuse confidence score 13/100 from 89 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T10:28:57+00:00. | Low |
| 40.126.29.5 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 40.126.29.5 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 40.126.29.9 | ipv4 | AbuseIPDB | Abuse confidence score 13/100 from 88 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T01:32:27+00:00. | Low |
| 40.126.29.9 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 40.126.29.9 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 45.131.214.85 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: DE, ISP: MHost LLC. Last reported: None. | Low |
| 45.131.214.85 | ipv4 | VirusTotal | 8/89 security vendors flagged this indicator as malicious, 3 as suspicious. | High |
| 45.131.214.85 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 51.105.71.136 | ipv4 | AbuseIPDB | Abuse confidence score 18/100 from 30 report(s). Country: GB, ISP: Microsoft Limited. Last reported: 2026-09-09T08:59:56+00:00. | Low |
| 51.105.71.136 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 51.105.71.136 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 51.105.71.137 | ipv4 | AbuseIPDB | Abuse confidence score 12/100 from 22 report(s). Country: GB, ISP: Microsoft Limited. Last reported: 2026-09-12T07:40:05+00:00. | Low |
| 51.105.71.137 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 51.105.71.137 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 51.11.168.232 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: GB, ISP: Microsoft Limited. Last reported: 2026-04-24T00:49:06+00:00. | Low |
| 51.11.168.232 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 51.11.168.232 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 51.116.246.106 | ipv4 | AbuseIPDB | Abuse confidence score 11/100 from 7 report(s). Country: DE, ISP: Microsoft Limited. Last reported: 2026-09-12T07:40:05+00:00. | Low |
| 51.116.246.106 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 51.116.246.106 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 52.110.6.19 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: None. | Low |
| 52.110.6.19 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 52.110.6.19 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 52.110.6.37 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: None. | Low |
| 52.110.6.37 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 52.110.6.37 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 52.110.6.45 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: None. | Low |
| 52.110.6.45 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 52.110.6.45 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 52.110.6.48 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: None. | Low |
| 52.110.6.48 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 52.110.6.48 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 52.123.129.14 | ipv4 | AbuseIPDB | Abuse confidence score 21/100 from 13 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-04T13:47:53+00:00. | Low |
| 52.123.129.14 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 52.123.129.14 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 52.123.246.74 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: None. | Low |
| 52.123.246.74 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 52.123.246.74 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 52.123.250.16 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: None. | Low |
| 52.123.250.16 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 52.123.250.16 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 52.123.250.27 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: None. | Low |
| 52.123.250.27 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 52.123.250.27 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 52.137.106.217 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-02-10T02:01:41+00:00. | Low |
| 52.137.106.217 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 52.137.106.217 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 52.167.17.97 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-04-27T02:58:27+00:00. | Low |
| 52.167.17.97 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 52.167.17.97 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 52.168.112.67 | ipv4 | AbuseIPDB | Abuse confidence score 22/100 from 48 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-08T08:59:27+00:00. | Low |
| 52.168.112.67 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 52.168.112.67 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 52.183.220.149 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-05-06T14:03:04+00:00. | Low |
| 52.183.220.149 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 52.183.220.149 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| 52.185.211.133 | ipv4 | AbuseIPDB | Abuse confidence score 0/100 from 0 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-05-06T14:03:04+00:00. | Low |
| 52.185.211.133 | ipv4 | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| 52.185.211.133 | ipv4 | URLhaus | No URLhaus record found for this indicator. | Low |
| EASYAS123-DC.easyas123.tech | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| EASYAS123-DC.easyas123.tech | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| _googlecast._tcp.local | domain | VirusTotal | Threat intelligence lookup unavailable. | N/A |
| _googlecast._tcp.local | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| _ldap._tcp.Default-First-Site-Name._sites.EASYAS123-DC.easyas123.tech | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| _ldap._tcp.Default-First-Site-Name._sites.EASYAS123-DC.easyas123.tech | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.easyas123.tech | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.easyas123.tech | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| _ldap._tcp.Default-First-Site-Name._sites.easyas123.tech | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| _ldap._tcp.Default-First-Site-Name._sites.easyas123.tech | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| _ldap._tcp.EASYAS123-DC.easyas123.tech | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| _ldap._tcp.EASYAS123-DC.easyas123.tech | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| _ldap._tcp.dc._msdcs.mshome.net | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| _ldap._tcp.dc._msdcs.mshome.net | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| acroipm2.adobe.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| acroipm2.adobe.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| api.msn.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| api.msn.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| armmf.adobe.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| armmf.adobe.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| assets.adobedtm.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| assets.adobedtm.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| assets.msn.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| assets.msn.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| client.wns.windows.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| client.wns.windows.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| config.edge.skype.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| config.edge.skype.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| ctldl.windowsupdate.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| ctldl.windowsupdate.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| deff.nelreports.net | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| deff.nelreports.net | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| easyas123-dc.easyas123.tech | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| easyas123-dc.easyas123.tech | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| ecs.office.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| ecs.office.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| edge-consumer-static.azureedge.net | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| edge-consumer-static.azureedge.net | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| edge.microsoft.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| edge.microsoft.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| fd.api.iris.microsoft.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| fd.api.iris.microsoft.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| g.live.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| g.live.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| img-s-msn-com.akamaized.net | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| img-s-msn-com.akamaized.net | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| licensing.mp.microsoft.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| licensing.mp.microsoft.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| login.microsoftonline.com | domain | VirusTotal | 1/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Medium |
| login.microsoftonline.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| mobile.events.data.microsoft.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| mobile.events.data.microsoft.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| msedge.b.tlu.dl.delivery.mp.microsoft.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| msedge.b.tlu.dl.delivery.mp.microsoft.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| ocsp.digicert.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| ocsp.digicert.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| odc.officeapps.live.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| odc.officeapps.live.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| officeclient.microsoft.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| officeclient.microsoft.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| oneclient.sfx.ms | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| oneclient.sfx.ms | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| self.events.data.microsoft.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| self.events.data.microsoft.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| services.gfe.nvidia.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| services.gfe.nvidia.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| settings-win.data.microsoft.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| settings-win.data.microsoft.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| srtb.msn.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| srtb.msn.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| staticview.msn.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| staticview.msn.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| th.bing.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| th.bing.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| update.googleapis.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| update.googleapis.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| v10.events.data.microsoft.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| v10.events.data.microsoft.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| vadusa.xyz | domain | VirusTotal | 6/89 security vendors flagged this indicator as malicious, 3 as suspicious. | High |
| vadusa.xyz | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| watson.events.data.microsoft.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| watson.events.data.microsoft.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| windows.msn.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| windows.msn.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| wpad.easyas123.tech | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| wpad.easyas123.tech | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| wpad.mshome.net | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| wpad.mshome.net | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| www.bing.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| www.bing.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| www.fmcsa.dot.gov | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| www.fmcsa.dot.gov | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| www.msftconnecttest.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| www.msftconnecttest.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| www.msn.com | domain | VirusTotal | 0/89 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| www.msn.com | domain | URLhaus | No URLhaus record found for this indicator. | Low |
| http://acroipm2.adobe.com/assets/Owner/arm/ProcessMAU.txt | url | VirusTotal | 0/91 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| http://acroipm2.adobe.com/assets/Owner/arm/ProcessMAU.txt | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab?1fe5743cf489a795 | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab?1fe5743cf489a795 | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab?238f51c2ab526be6 | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab?238f51c2ab526be6 | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab?957338f6d43a4cf5 | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab?957338f6d43a4cf5 | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?811956fd58fe307b | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?811956fd58fe307b | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?a8cb64ce6f292067 | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?a8cb64ce6f292067 | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?fa2f866848cf44b7 | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?fa2f866848cf44b7 | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?4e25f6955dc4f675 | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?4e25f6955dc4f675 | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?d3434c35564aa4e5 | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?d3434c35564aa4e5 | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?d7d014dbf0b66d22 | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab?d7d014dbf0b66d22 | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://edge.microsoft.com/browsernetworktime/time/1/current?cup2key=2:cHFgppt5zfs9cbgaKCO2n0tk698hI27wU971tyrEQQg&cup2hreq=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://edge.microsoft.com/browsernetworktime/time/1/current?cup2key=2:cHFgppt5zfs9cbgaKCO2n0tk698hI27wU971tyrEQQg&cup2hreq=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/0b18f766-7469-4aa3-88b7-99e69c55d14d?P1=1772628813&P2=404&P3=2&P4=P9O%2fZqV3zHEog%2f8GWjY1LjxEXlCShXCmvVwfgCjP6c7Xjf6q9SdV5Cxrlht3k8c6RsZdgDSm48GRm8J1Kej36Q%3d%3d | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/0b18f766-7469-4aa3-88b7-99e69c55d14d?P1=1772628813&P2=404&P3=2&P4=P9O%2fZqV3zHEog%2f8GWjY1LjxEXlCShXCmvVwfgCjP6c7Xjf6q9SdV5Cxrlht3k8c6RsZdgDSm48GRm8J1Kej36Q%3d%3d | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/13d0ef9b-70c8-43c9-9a51-13c752dfb777?P1=1772817857&P2=404&P3=2&P4=NxsPWDqY%2fPRN4X5tyugkA%2bdfU9EeHebHQ3SqTAWWr5XPVngvgEZDtSFAEYlah9GHFrc%2bS%2fExNx3X0xGxvdOPow%3d%3d | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/13d0ef9b-70c8-43c9-9a51-13c752dfb777?P1=1772817857&P2=404&P3=2&P4=NxsPWDqY%2fPRN4X5tyugkA%2bdfU9EeHebHQ3SqTAWWr5XPVngvgEZDtSFAEYlah9GHFrc%2bS%2fExNx3X0xGxvdOPow%3d%3d | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/2132f61f-f790-4ae6-a355-8cf9a1533800?P1=1772824359&P2=404&P3=2&P4=JBAPgdPQ5bbXP3YOD9Ig2AVW51pLa6vxUcHeGTEAadbzNEO5DlV3Wra1C9WqE7WnEd5RG1oYpt8saZgMxML1KA%3d%3d | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/2132f61f-f790-4ae6-a355-8cf9a1533800?P1=1772824359&P2=404&P3=2&P4=JBAPgdPQ5bbXP3YOD9Ig2AVW51pLa6vxUcHeGTEAadbzNEO5DlV3Wra1C9WqE7WnEd5RG1oYpt8saZgMxML1KA%3d%3d | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/86061e48-63b3-483f-8dac-609df0cbb238?P1=1772824359&P2=404&P3=2&P4=M%2br84JmdgFPOKPdw6GuIsCbfL0IaRRxCYqeiJbpH9IpxZr7vLbM4w9K8uMU5Ka6CyN%2fuMqIEMlyIHqGqCS8%2fXg%3d%3d | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/86061e48-63b3-483f-8dac-609df0cbb238?P1=1772824359&P2=404&P3=2&P4=M%2br84JmdgFPOKPdw6GuIsCbfL0IaRRxCYqeiJbpH9IpxZr7vLbM4w9K8uMU5Ka6CyN%2fuMqIEMlyIHqGqCS8%2fXg%3d%3d | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/ddbf4492-d475-4fe4-bcde-6cbac56f6034?P1=1772824359&P2=404&P3=2&P4=TMSkemQv9LZfDxme9Q9GxU0tc2G9uhdO6d7QU9JVJHOk%2ba0A4pJYzApqbFnNEQ6bt9QSukbCYOxGUmPIOR1Xgw%3d%3d | url | VirusTotal | No VirusTotal record found for this indicator. | Low |
| http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/ddbf4492-d475-4fe4-bcde-6cbac56f6034?P1=1772824359&P2=404&P3=2&P4=TMSkemQv9LZfDxme9Q9GxU0tc2G9uhdO6d7QU9JVJHOk%2ba0A4pJYzApqbFnNEQ6bt9QSukbCYOxGUmPIOR1Xgw%3d%3d | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://ocsp.digicert.com/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ50otx%2Fh0Ztl%2Bz8SiPI7wEWVxDlQQUTiJUIBiV5uNu5g%2F6%2BrkS7QYXjzkCEA77flR%2B3w%2FxBpruV2lte6A%3D | url | VirusTotal | 0/91 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| http://ocsp.digicert.com/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ50otx%2Fh0Ztl%2Bz8SiPI7wEWVxDlQQUTiJUIBiV5uNu5g%2F6%2BrkS7QYXjzkCEA77flR%2B3w%2FxBpruV2lte6A%3D | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://ocsp.digicert.com/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ50otx%2Fh0Ztl%2Bz8SiPI7wEWVxDlQQUTiJUIBiV5uNu5g%2F6%2BrkS7QYXjzkCEAUZZSZEml49Gjh0j13P68w%3D | url | VirusTotal | 0/91 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| http://ocsp.digicert.com/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ50otx%2Fh0Ztl%2Bz8SiPI7wEWVxDlQQUTiJUIBiV5uNu5g%2F6%2BrkS7QYXjzkCEAUZZSZEml49Gjh0j13P68w%3D | url | URLhaus | No URLhaus record found for this indicator. | Low |
| http://www.msftconnecttest.com/connecttest.txt | url | VirusTotal | 0/90 security vendors flagged this indicator as malicious, 0 as suspicious. | Low |
| http://www.msftconnecttest.com/connecttest.txt | url | URLhaus | No URLhaus record found for this indicator. | Low |

Threat-intelligence lookups produced **49** matching result(s) across the configured feeds.

### Correlated Findings

#### THREAT-003 — Suspicious DNS Query

- **Severity:** High (risk score 70/100)
- **Confidence:** High
- **IOC:** `vadusa.xyz` (domain)
- **PCAP evidence:** Suspicious DNS Query: DNS query for vadusa.xyz; Suspicious DNS Query: DNS query for vadusa.xyz; Suspicious DNS Query: DNS query for vadusa.xyz
- **Threat intelligence:** VirusTotal — 6/89 security vendors flagged this indicator as malicious, 3 as suspicious.
- **Correlation:** Multiple independent sources — local packet-level detection and one or more threat-intelligence feeds — support further investigation of this indicator.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-021 — Threat Intelligence Match

- **Severity:** Medium (risk score 45/100)
- **Confidence:** Medium
- **IOC:** `199.232.210.172` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 0/100 from 56 report(s). Country: US, ISP: Fastly, Inc.. Last reported: 2026-09-21T23:12:25+00:00.; VirusTotal — 2/89 security vendors flagged this indicator as malicious, 0 as suspicious.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-044 — Threat Intelligence Match

- **Severity:** Medium (risk score 40/100)
- **Confidence:** Medium
- **IOC:** `45.131.214.85` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** VirusTotal — 8/89 security vendors flagged this indicator as malicious, 3 as suspicious.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-002 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `login.microsoftonline.com` (domain)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** VirusTotal — 1/89 security vendors flagged this indicator as malicious, 0 as suspicious.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-004 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `104.208.203.89` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 0/100 from 3 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-08-14T18:08:07+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-005 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `104.46.162.224` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 11/100 from 32 report(s). Country: AU, ISP: Microsoft Corporation. Last reported: 2026-09-01T02:15:04+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-006 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `13.69.116.109` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 0/100 from 8 report(s). Country: NL, ISP: Microsoft Corporation. Last reported: 2026-08-04T10:55:10+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-007 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `13.70.79.200` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 0/100 from 6 report(s). Country: AU, ISP: Microsoft Corporation. Last reported: 2026-07-05T16:58:12+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-008 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `13.89.178.27` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 0/100 from 11 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-09T09:14:44+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-009 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `13.89.179.13` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 0/100 from 7 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-09T11:43:08+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-010 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `13.89.179.14` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 0/100 from 5 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-07T05:14:57+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-011 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `13.89.179.8` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 0/100 from 9 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-08T23:40:18+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-012 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `13.89.179.9` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 0/100 from 7 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-09T01:58:58+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-013 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `135.234.160.246` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 16/100 from 23 report(s). Country: US, ISP: Microsoft Limited. Last reported: 2026-09-04T20:26:04+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-014 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `142.250.138.94` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 0/100 from 1 report(s). Country: US, ISP: Google LLC. Last reported: 2026-09-06T06:12:31+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-015 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `150.171.22.17` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 21/100 from 9 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-17T05:50:17+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-016 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `150.171.27.11` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 37/100 from 53 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-18T23:55:58+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-017 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `150.171.27.12` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 9/100 from 9 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-08-28T03:22:09+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-018 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `150.171.28.11` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 26/100 from 13 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-18T07:40:45+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-019 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `150.171.28.12` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 10/100 from 3 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-04T17:31:12+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-020 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `184.29.31.84` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 1/100 from 1 report(s). Country: US, ISP: Akamai Technologies, Inc.. Last reported: 2026-09-03T11:29:48+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-022 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `20.189.173.2` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 0/100 from 8 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-07T09:40:09+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-023 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `20.190.135.16` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 4/100 from 82 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T07:07:53+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-024 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `20.190.135.3` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 13/100 from 88 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T10:52:01+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-025 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `20.190.135.4` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 13/100 from 84 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T10:57:54+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-026 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `20.190.135.7` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 4/100 from 84 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T08:58:34+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-027 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `20.190.157.14` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 5/100 from 88 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T00:35:51+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-028 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `20.190.157.4` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 13/100 from 89 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-04T13:22:26+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-029 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `20.190.157.9` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 13/100 from 93 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T09:03:40+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-030 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `20.42.65.84` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 23/100 from 43 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-13T07:40:11+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-031 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `20.42.65.88` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 21/100 from 38 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-18T23:55:58+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-032 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `20.42.65.94` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 21/100 from 45 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-07T18:43:02+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-033 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `20.42.73.30` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 26/100 from 47 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-09T08:59:56+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-034 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `20.96.153.111` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 0/100 from 1 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-04T13:20:15+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-035 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `204.79.197.203` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 9/100 from 6 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-06T16:33:41+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-036 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `4.149.160.182` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 0/100 from 1 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-07-13T08:48:38+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-037 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `40.126.28.12` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 13/100 from 89 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-04T23:59:48+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-038 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `40.126.28.13` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 5/100 from 90 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T06:58:10+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-039 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `40.126.29.10` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 5/100 from 83 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T04:09:34+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-040 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `40.126.29.13` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 5/100 from 87 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-04T21:09:32+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-041 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `40.126.29.15` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 13/100 from 85 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T02:32:14+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-042 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `40.126.29.5` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 13/100 from 89 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T10:28:57+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-043 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `40.126.29.9` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 13/100 from 88 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-05T01:32:27+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-045 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `51.105.71.136` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 18/100 from 30 report(s). Country: GB, ISP: Microsoft Limited. Last reported: 2026-09-09T08:59:56+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-046 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `51.105.71.137` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 12/100 from 22 report(s). Country: GB, ISP: Microsoft Limited. Last reported: 2026-09-12T07:40:05+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-047 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `51.116.246.106` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 11/100 from 7 report(s). Country: DE, ISP: Microsoft Limited. Last reported: 2026-09-12T07:40:05+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-048 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `52.123.129.14` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 21/100 from 13 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-04T13:47:53+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-049 — Threat Intelligence Match

- **Severity:** Low (risk score 25/100)
- **Confidence:** Medium
- **IOC:** `52.168.112.67` (ipv4)
- **PCAP evidence:** Indicator observed in capture; see IOC inventory.
- **Threat intelligence:** AbuseIPDB — Abuse confidence score 22/100 from 48 report(s). Country: US, ISP: Microsoft Corporation. Last reported: 2026-09-08T08:59:27+00:00.
- **Correlation:** Threat-intelligence feed(s) flagged this indicator; no local detection rule fired for it, so this stands on TI reputation alone.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

#### THREAT-001 — Possible DGA-like Domain

- **Severity:** Informational (risk score 0/100)
- **Confidence:** Medium
- **IOC:** `img-s-msn-com.akamaized.net` (domain)
- **PCAP evidence:** Possible DGA-like Domain: DNS query for img-s-msn-com.akamaized.net; Possible DGA-like Domain: DNS query for img-s-msn-com.akamaized.net; Possible DGA-like Domain: DNS query for img-s-msn-com.akamaized.net; Possible DGA-like Domain: DNS query for img-s-msn-com.akamaized.net; Possible DGA-like Domain: DNS query for img-s-msn-com.akamaized.net; Possible DGA-like Domain: DNS query for img-s-msn-com.akamaized.net; Possible DGA-like Domain: DNS query for img-s-msn-com.akamaized.net; Possible DGA-like Domain: DNS query for img-s-msn-com.akamaized.net
- **Threat intelligence:** No threat-intelligence match available.
- **Correlation:** Local detection logic flagged this indicator; no threat-intelligence feed had a record for it at the time of the scan.
- **Recommended action:** Investigate the originating endpoint and search historical network/security logs for this indicator. Consider blocking confirmed malicious infrastructure per local policy.

### Investigation Timeline

| Timestamp (UTC) | Event |
|---|---|
| 19:55:08 | DNS query for _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net |
| 19:55:08 | DNS query for _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.easyas123.tech |
| 19:55:08 | DNS query for _ldap._tcp.Default-First-Site-Name._sites.easyas123.tech |
| 19:55:08 | DNS query for easyas123-dc.easyas123.tech |
| 19:55:08 | easyas123-dc.easyas123.tech resolved to 10.2.28.2 |
| 19:55:08 | DNS query for _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net |
| 19:55:09 | DNS query for _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.easyas123.tech |
| 19:55:09 | DNS query for _ldap._tcp.Default-First-Site-Name._sites.easyas123.tech |
| 19:55:09 | DNS query for _ldap._tcp.dc._msdcs.mshome.net |
| 19:55:09 | DNS query for _ldap._tcp.dc._msdcs.mshome.net |
| 19:55:09 | DNS query for wpad.easyas123.tech |
| 19:55:09 | DNS query for wpad.easyas123.tech |
| 19:55:09 | DNS query for wpad.mshome.net |
| 19:55:09 | DNS query for wpad.mshome.net |
| 19:55:09 | DNS query for _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net |
| 19:55:09 | DNS query for _ldap._tcp.dc._msdcs.mshome.net |
| 19:55:09 | DNS query for www.msftconnecttest.com |
| 19:55:09 | DNS query for www.msftconnecttest.com |
| 19:55:09 | www.msftconnecttest.com resolved to ncsi-geo.trafficmanager.net. |
| 19:55:09 | GET /connecttest.txt to host www.msftconnecttest.com |
| 19:55:09 | HTTP response 200 |
| 19:55:10 | DNS query for _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net |
| 19:55:10 | DNS query for _ldap._tcp.dc._msdcs.mshome.net |
| 19:55:10 | DNS query for v10.events.data.microsoft.com |
| 19:55:10 | v10.events.data.microsoft.com resolved to win-global-asimov-leafs-events-data.trafficmanager.net. |
| 19:55:12 | DNS query for _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net |
| 19:55:12 | DNS query for client.wns.windows.com |
| 19:55:12 | DNS query for client.wns.windows.com |
| 19:55:12 | client.wns.windows.com resolved to wns.notify.trafficmanager.net. |
| 19:55:13 | DNS query for _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.easyas123.tech |
| 19:55:14 | DNS query for _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.easyas123.tech |
| 19:55:14 | DNS query for _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.easyas123.tech |
| 19:55:14 | DNS query for wpad.easyas123.tech |
| 19:55:14 | DNS query for wpad.easyas123.tech |
| 19:55:14 | DNS query for wpad.mshome.net |
| 19:55:14 | DNS query for wpad.mshome.net |
| 19:55:23 | DNS query for watson.events.data.microsoft.com |
| 19:55:24 | DNS query for watson.events.data.microsoft.com |
| 19:55:24 | watson.events.data.microsoft.com resolved to blobcollectorcommon.trafficmanager.net. |
| 19:55:25 | DNS query for windows.msn.com |
| 19:55:25 | DNS query for wpad.easyas123.tech |
| 19:55:25 | DNS query for wpad.mshome.net |
| 19:55:25 | DNS query for config.edge.skype.com |
| 19:55:25 | DNS query for config.edge.skype.com |
| 19:55:25 | DNS query for windows.msn.com |
| 19:55:25 | windows.msn.com resolved to win-msn-com-world-atm-default.trafficmanager.net. |
| 19:55:25 | config.edge.skype.com resolved to config.edge.skype.com.trafficmanager.net. |
| 19:55:25 | config.edge.skype.com resolved to config.edge.skype.com.trafficmanager.net. |
| 19:55:25 | config.edge.skype.com resolved to config.edge.skype.com.trafficmanager.net. |
| 19:55:25 | DNS query for www.bing.com |
| 19:55:25 | DNS query for www.bing.com |
| 19:55:26 | www.bing.com resolved to www-www.bing.com.trafficmanager.net. |
| 19:55:26 | DNS query for www.msn.com |
| 19:55:26 | www.bing.com resolved to www-www.bing.com.trafficmanager.net. |
| 19:55:26 | DNS query for officeclient.microsoft.com |
| 19:55:26 | www.msn.com resolved to www-msn-com-world-atm-default.trafficmanager.net. |
| 19:55:26 | DNS query for officeclient.microsoft.com |
| 19:55:26 | officeclient.microsoft.com resolved to config.officeapps.live.com. |
| 19:55:26 | DNS query for odc.officeapps.live.com |
| 19:55:26 | DNS query for odc.officeapps.live.com |

### Recommendations

- Investigate any endpoint associated with a High or Critical severity finding.
- Search historical SIEM/EDR logs for the indicators listed in this report.
- Where infrastructure is confirmed malicious by policy, block at the network boundary.
- Review DNS logs for repeated queries to the flagged domains.
- Analyze any recovered file payloads in an isolated sandbox before further action.
- Continue monitoring related infrastructure identified in the IOC inventory.

## References

Threat-intelligence feeds used for correlation:

- AbuseIPDB — <https://www.abuseipdb.com>
- VirusTotal — <https://www.virustotal.com>
- URLhaus (abuse.ch) — <https://urlhaus.abuse.ch>

Sample PCAP source: <https://www.malware-traffic-analysis.net/>

## Conclusion

This analysis identified 1 finding(s) rated High or Critical severity, supported by the packet-level and threat-intelligence evidence above. Analysts should prioritize review of these findings and follow the recommendations listed.

**Limitations:** encrypted traffic cannot be inspected beyond metadata; fields absent from the PCAP are reported as unavailable rather than guessed; threat-intelligence feeds are rate-limited and may be unavailable at scan time; a single indicator match is not proof of compromise; the risk score is a project-defined prioritization aid, not an industry-standard rating.
