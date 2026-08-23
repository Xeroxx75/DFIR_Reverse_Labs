# DFIR and Reverse Engineering Labs

Hands-on investigations and reverse-engineering exercises focused on evidence correlation, reproducible methods and concise reporting.

## Featured Investigations

| Project | Focus | Main techniques |
| --- | --- | --- |
| [Honeynet Collapse](dfir/honeynet-collapse/) | Six-stage TryHackMe investigation across Linux, Windows, memory, disk, NTFS and macOS | auditd, EVTX, Volatility 3, Zimmerman tools, APFS and cross-host timeline correlation |
| [Windows Workstation Incident](dfir/windows-workstation-incident/) | Simulated endpoint compromise | Volatility 3, KAPE, Sysmon, Wireshark and timeline reconstruction |
| [Windows Memory - TrueCrypt and KeePass](dfir/windows-memory-truecrypt-keepass/) | Memory-led recovery and artifact analysis | Volatility 3, process and credential artifacts, Base64 decoding |

## Malware Analysis and Reverse Engineering

| Project | Focus | Deliverables |
| --- | --- | --- |
| [GPGcryptor](malware-analysis/gpgcryptor/) | Academic ransomware analysis | Technical report, decryptor and restoration script |
| [Sallos Key License](reverse-engineering/sallos-key-license/) | Windows crackme and license validation | Static analysis, key generator and annotated screenshots |
| [YARA Rules](detection/yara/) | Rules derived from analyzed samples | Binary and encrypted-file detection rules |

## Binary Exploitation Case Study

| Project | Focus | Main techniques |
| --- | --- | --- |
| [Incident to RCE](https://github.com/Xeroxx75/incident-to-rce) | Controlled incident-to-RCE study connecting PCAP reconstruction with a C audit and remediation | Format-string leak, off-by-one, stack corruption, GDB, x86 shellcode and end-to-end tested RCE |

## Reporting Approach

The reports separate observations, interpretations and evidence constraints. Commands and parsers are included when they make an investigation reproducible, while raw secrets and unnecessary output are omitted.
