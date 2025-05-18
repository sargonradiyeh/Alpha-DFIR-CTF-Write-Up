# Alpha Digital Forensics & Incident Response CTF Write-up

## 📁 Project Overview

This repository contains the full digital forensics and incident response (DFIR) report for a simulated enterprise network compromise conducted as part of a capture-the-flag (CTF) challenge. The investigation centers on a targeted attack involving remote access, malware deployment, credential compromise, lateral movement, and data exfiltration.

This CTF scenario is based on [The Stolen Szechuan Sauce](https://dfirmadness.com/the-stolen-szechuan-sauce/) challenge from DFIRMadness, adapted for academic and training purposes.

---

## 🎯 Scope of Investigation

The analysis focused on two Windows-based systems:
- **CITADEL-DC01**: Domain Controller (Windows Server 2012 R2)
- **DESKTOP-SDN1RPT**: Domain-joined client (Windows 10 Enterprise)

Investigators were provided with:
- Disk images (`.E01`)
- Memory dumps (`.mem`)
- Network packet captures (`.pcap`)

The goal was to trace attacker activity across hosts and identify key forensic artifacts left behind.

---

## 🛠️ Methodology

The investigation followed a full-spectrum DFIR workflow:
- **Disk Forensics**: MFT, USN Journal, Recycle Bin, Registry hives
- **Memory Analysis**: Volatility 2 & 3 for process injection, credential dumping, network connections
- **Network Forensics**: PCAP inspection with Wireshark and NetworkMiner
- **Timeline Reconstruction**: Super timelines using MFTECmd, Plaso, and Timeline Explorer
- **Malware Analysis**: Behavior profiling with VirusTotal, Any.Run, and Hybrid Analysis

All analysis was conducted in isolated environments with forensic integrity in mind.

---

## 🔍 Key Findings

- **Initial Access**: Brute-force RDP login using default Administrator credentials
- **Malware Execution**: `coreupdater.exe`, a Meterpreter reverse shell
- **Persistence**: Registry run keys and malicious services (`T1547.001`, `T1543.003`)
- **Lateral Movement**: RDP from DC to client using reused credentials (`T1021.001`)
- **Exfiltration**: ZIP archives extracted from memory artifacts and confirmed in PCAP traffic
- **Evasion**: File timestomping, process injection into `spoolsv.exe` (`T1070.006`, `T1055`)
- **Command & Control**: HTTPS traffic with known suspicious IP addresses
- **Threat Intel**: Infrastructure tied to Russian and Thai IPs, though no APT attribution confirmed

---

## 🧰 Some of the Tools Used

| Tool                     | Purpose                          |
|--------------------------|----------------------------------|
| Volatility 2 / 3         | Memory forensics                 |
| Wireshark / NetworkMiner| Network analysis & reconstruction|
| MFTECmd / Plaso          | Timeline building                |
| Registry Explorer / Regripper | Registry artifact extraction |
| VirusTotal / Any.Run     | Malware behavior analysis        |
| Arsenal Image Mounter    | Forensic disk mounting           |
| KAPE, EvtxECMD, SrumECmd | Artifact triage and parsing      |

---

## 📑 Report Contents

| Section                   | Highlights                                                                 |
|---------------------------|---------------------------------------------------------------------------|
| Executive Summary         | High-level overview of the incident, key findings, and impact assessment  |
| Scope and Objectives      | Defines the systems investigated and goals of the analysis                |
| Methodology               | Step-by-step forensic process across disk, memory, and network layers     |
| Findings                  | Detailed breakdown of attacker activity, malware behavior, and persistence|
| Indicators of Compromise  | IPs, hashes, filenames, and forensic artifacts linked to the breach       |
| Timeline of Events        | Reconstructed sequence of attacker actions based on multi-source evidence|
| Conclusions               | Summary of investigation results and confirmed security gaps              |
| Recommendations           | Actionable steps for containment, remediation, recovery, and prevention   |
| Contributions             | Breakdown of individual team member contributions to the investigation    |
| References                | Tools, frameworks, and sources cited throughout the analysis              |

---

## 📘 License

This repository is for academic and educational use. Please do not reuse without permission or proper attribution.
