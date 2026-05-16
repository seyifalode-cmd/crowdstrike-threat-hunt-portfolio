# CrowdStrike Threat Hunt Portfolio — Hunting SCATTERED SPIDER

**Analyst:** Shaymill — Cloud & Cybersecurity Engineer  
**Platform:** CrowdStrike Falcon (Simulated Environment)  
**Date:** May 2026  
**Classification:** Portfolio Project

---

## Overview

This repository contains a structured threat hunt report targeting **SCATTERED SPIDER** (also tracked as Octo Tempest / UNC3944), one of the most damaging financially motivated threat actors operating today. The hunt was conducted using the **CrowdStrike Falcon** platform and mapped entirely to the **MITRE ATT&CK Enterprise Framework (v14)**.

SCATTERED SPIDER is responsible for the 2023 MGM Resorts breach (~$100M+ in losses) and the Caesars Entertainment compromise. Unlike most adversaries, they rely almost exclusively on **social engineering and identity abuse** — no malware, no zero-days. This makes them invisible to signature-based tools and detectable only through behavioural threat hunting.

---

## What's Inside

| File | Description |
|------|-------------|
| `CrowdStrike_ThreatHunt_SCATTERED_SPIDER.docx` | Full threat hunt report — hypotheses, CQL queries, findings, timeline, and recommendations |

---

## Threat Actor Profile

| Attribute | Detail |
|-----------|--------|
| CrowdStrike Name | SCATTERED SPIDER |
| Also Known As | Octo Tempest, UNC3944, Starfraud, 0ktapus |
| Motivation | Financial — Ransomware, Data Extortion, Cryptocurrency Theft |
| Primary Method | Social Engineering, SIM Swapping, MFA Bypass |
| Malware Used | Minimal — primarily living-off-the-land (LOLBins) |
| Primary Targets | Hospitality, Gaming, Telecom, Financial Services |
| Notable Breaches | MGM Resorts (2023), Caesars Entertainment (2023), Okta, Twilio |

---

## Hunt Hypotheses

The hunt was built around four detection hypotheses, each tied to a specific MITRE ATT&CK technique:

| # | Hypothesis | MITRE Technique | Severity |
|---|------------|----------------|----------|
| H1 | MFA fatigue bombing in progress — users receiving 5+ failed push notifications from unrecognized IPs | T1621 — MFA Request Generation | CRITICAL |
| H2 | Unauthorized privileged account created outside business hours by a human identity | T1136.001 — Create Local Account | CRITICAL |
| H3 | Single credential authenticating to 10+ unique endpoints via network logon | T1021 — Remote Services | HIGH |
| H4 | 500MB+ outbound data transfer to a single external IP over port 443 | T1041 — Exfiltration Over C2 Channel | CRITICAL |

---

## Hunt Queries (CrowdStrike Query Language)

### H1 — MFA Fatigue Detection
```
event_simpleName=UserLogon
| AuthMethod="MFA_PUSH"
| LogonResult="FAILED"
| stats count by UserName, IPAddress
| where count > 5
| sort count desc
```

### H2 — Unauthorized Admin Account Creation
```
event_simpleName=UserAccountCreated
| CreatedByUserName!="automated_provisioning"
| NewUserPrivilege="Admin"
| stats count by CreatedByUserName, ComputerName, timestamp
| sort timestamp desc
```

### H3 — Lateral Movement Detection
```
event_simpleName=UserLogon
| LogonType="Network"
| stats dc(ComputerName) as UniqueHosts by UserName
| where UniqueHosts > 10
| sort UniqueHosts desc
```

### H4 — Data Exfiltration Detection
```
event_simpleName=NetworkConnectIP4
| RemotePort IN (443, 80)
| stats sum(BytesSent) as TotalSent by UserName, RemoteIP
| where TotalSent > 500000000
| sort TotalSent desc
```

---

## Key Findings

All four hypotheses were confirmed against the simulated 72-hour dataset:

- **H1 — MFA Fatigue:** `j.morrison@corp.com` received 23 failed MFA push notifications from a Tor exit node (`185.220.101.47`) over 47 minutes before approving the 24th — granting attacker access at 02:14 EST.

- **H2 — Unauthorized Admin Account:** Account `svc_backup_admin` created at 03:22 EST by the compromised identity on `CORP-DC-01` and immediately added to Domain Admins. No change ticket existed.

- **H3 — Lateral Movement:** `svc_backup_admin` authenticated via network logon to **37 unique endpoints** within 4 hours, including file servers and the HR database (`CORP-HR-DB-02`). Baseline for service accounts in this environment: 2–3 hosts.

- **H4 — Data Exfiltration:** **2.3GB** transferred from `CORP-HR-DB-02` to a bulletproof hosting IP (`185.220.101.52`) over HTTPS between 10:15–11:47 EST — 1,900% above the 30-day baseline for that host.

---

## Attack Timeline

| Time | Phase | Event | MITRE ATT&CK |
|------|-------|-------|--------------|
| Day 1 00:30 | Initial Access | Attacker vishes IT helpdesk posing as employee, requests MFA deregistration | T1566, T1078 |
| Day 1 02:14 | Credential Access | 23 MFA pushes sent; victim approves 24th. Attacker logs in from Tor exit node | T1621 |
| Day 1 03:22 | Persistence | `svc_backup_admin` created on DC, added to Domain Admins | T1136.001, T1098 |
| Day 1 06:00 | Lateral Movement | 37 endpoints accessed in 4 hours including HR database | T1021, T1078.002 |
| Day 1 09:47 | Collection | HR, payroll, and customer PII bulk-downloaded from `CORP-HR-DB-02` | T1005, T1213 |
| Day 1 10:15 | Exfiltration | 2.3GB exfiltrated to bulletproof host over HTTPS | T1041, T1048.002 |
| Day 2 08:00 | Impact | $4.5M ransom demand delivered, threat of data leak | T1486, T1657 |

---

## Recommendations

| Priority | Recommendation |
|----------|---------------|
| CRITICAL — Immediate | Enable MFA number matching or FIDO2 hardware keys to eliminate fatigue bombing |
| CRITICAL — Immediate | Alert on any privileged account creation outside approved change windows |
| HIGH — 7 Days | Set lateral movement detection thresholds (8+ unique hosts in 2 hours) in Falcon |
| HIGH — 7 Days | Baseline outbound data per host; auto-quarantine on 3x baseline breach |
| HIGH — 30 Days | Deploy CrowdStrike Falcon OverWatch for continuous managed threat hunting |
| MEDIUM — 30 Days | Train helpdesk staff on out-of-band identity verification before any account action |

> Full remediation of Critical and High priority items is estimated to reduce risk exposure against SCATTERED SPIDER-style attacks by approximately **85%**.

---

## MITRE ATT&CK Techniques Covered

`T1566` `T1078` `T1621` `T1136.001` `T1098` `T1021` `T1078.002` `T1005` `T1213` `T1041` `T1048.002` `T1486` `T1657`

---

## Tools & Framework

- **CrowdStrike Falcon** — EDR platform, Event Search, CQL
- **MITRE ATT&CK Enterprise Framework v14**
- **Simulated environment:** 500 endpoints, hybrid cloud (AWS + Azure), 72-hour dataset

---

## About This Project

This is a portfolio threat hunt report produced as part of a hands-on cybersecurity project. It demonstrates structured, hypothesis-driven threat hunting methodology using industry-standard tooling and adversary intelligence — the same approach used by professional threat hunters in enterprise SOC environments.
