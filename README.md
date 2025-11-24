# DFIR & Reverse Labs

This repository gathers several hands-on labs in **DFIR**, **reverse engineering** and **malware analysis**.
The goal is to document my technical exploration, consolidate practical knowledge, and share reproducible analysis artefacts.


> All experiments are performed in isolated lab environments.  
> No real-world malware binaries are distributed here.

---

## Contents

- `crackme key-license/`  
  Reverse engineering of the “Sallos's Key License” crackme:
  - IDA/Ghidra-based analysis of the license verification logic,
  - understanding of user / license key checks,
  - small tooling in `generate_key.py` to reproduce the valid key,
  - screenshots of the GUI, imports, and sections.  
  See the local `README.md` in this folder for details.

- `malware-lab-gpgcryptor/`  
  Academic ransomware analysis lab (CentraleSupélec):
  - full report `TP_Analyse_GPGcryptor.pdf`,
  - analysis of persistence, encrypted file format and Camellia-128 CFB crypto,
  - defensive tools: Python decryptor and PowerShell restoration script.  
  See `malware-lab-gpgcryptor/README.md`.

- `yara/`  
  Educational YARA rules derived from the labs:
  - detection of the crackme binary,
  - detection of GPGcryptor encrypted files,
  - detection of the GPGcryptor lab ransomware binary.  
  See `yara/README.md` for rule descriptions and usage examples.

---

## Technologies & Tools

Across these labs I use:

- **Reverse engineering**: Ghidra, GDB/x64dbg, PE analysis tools.
- **DFIR / Forensics**: Windows artefacts (EVTX, Prefetch, Amcache), memory dumps, Python/PowerShell tooling.
- **Detection engineering**: YARA rules based on strings, structures and IOCs derived from analysis.

---

## Disclaimer

- This repository is intended for **educational and defensive** purposes only.  
- All experiments are conducted in isolated lab environments.  
- No real-world malware binaries are released here; only analysis reports, scripts and detection rules.
