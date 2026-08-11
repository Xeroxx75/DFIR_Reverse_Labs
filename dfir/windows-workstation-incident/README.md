# Incident Report - WS01 (DFIR Homelab)

## 1. Executive Summary

This report documents a simulated security incident on workstation **WS01** (Windows 10, domain member of `corp.local`).
The investigation identified execution of a suspicious binary `update_win.exe` under user account `CORP\adminlab`, followed by:

* outbound HTTP “phone-home” to a host on the internal lab network,
* creation of an artefact file `C:\Users\Public\malware_log.txt`,
* renaming of user documents with a `.locked` extension, mimicking ransomware behaviour,
* long-running processes remaining in memory.

No evidence of lateral movement or persistence mechanisms (e.g. registry Run keys, scheduled tasks) was found. The activity was contained to WS01.

---

## 2. Scope and Environment

* **Host:** `WS01.corp.local`
* **OS:** Windows 10 x64 (build 19041)
* **Role:** Domain-joined client in lab domain `corp.local`
* **User affected:** `CORP\adminlab`
* **Time of activity (approx.):** 2025-11-26 around 12:44-12:46 UTC
* **Monitoring / artefacts available:**

  * Sysmon (Operational log, standard community config)
  * Windows event logs (EVTX)
  * Memory image (CrashDump via DumpIt)
  * KAPE triage output (filesystem, registry, Prefetch, Amcache, etc.)
  * Network capture (Wireshark PCAP)
  * Screenshots of impacted files and the attacker HTTP server logs

---

## 3. Methodology

The investigation followed a standard DFIR workflow, starting from the most volatile artefacts:

1. **Memory acquisition and analysis**

   * Acquisition of a full memory dump from WS01 using DumpIt.
   * Triage with **Volatility 3**:

     * `windows.info` to confirm profile and system time.
     * `windows.pslist` / `windows.pstree` to identify suspicious processes.
     * `windows.cmdline` / `windows.cmdscan` for command-line and console history.
     * `windows.handles` / `windows.filescan` / `windows.dumpfiles` for file artefacts and process handles.
     * `windows.netscan` to check for active connections at dump time.

2. **Disk and artefact collection (KAPE)**

   * KAPE was run against `C:` using the `!SANS_Triage` target set.
   * Focused analysis of:

     * Sysmon log (`Microsoft-Windows-Sysmon/Operational.evtx`),
     * filesystem artefacts (Prefetch, Amcache, user directories),
     * registry hives (for persistence).

3. **Network analysis**

   * Review of Wireshark PCAP captured on the lab network.
   * Correlation with HTTP server logs on the Kali host.

4. **Host triage**

   * Manual review of user folders (`Documents`, `C:\Users\Public`) to confirm file-system impact.
   * Correlation of findings across memory, logs, and network artefacts.

---

## 4. Detailed Findings

### 4.1 Sysmon / EVTX correlation

Sysmon provided a clear sequence of events around the introduction and execution of `update_win.exe`:

1. **File creation in Downloads (Event ID 11 - RuleName: Downloads)**
   - `Image: C:\Windows\Explorer.EXE` (PID 1684, user `CORP\adminlab`)
   - `TargetFilename: C:\Users\adminlab\Downloads\update_win.exe`
   - `UtcTime: 2025-11-26 12:44:36.745`

   This shows the binary being written to disk under the user’s profile by Explorer (most likely a manual download or copy).

2. **First execution (Event ID 1 - Process Create)**
   - `Image: C:\Users\adminlab\Downloads\update_win.exe`
   - `CommandLine: "C:\Users\adminlab\Downloads\update_win.exe"`
   - `User: CORP\adminlab`
   - `Hashes: MD5=0008152B..., SHA256=347C9369..., IMPHASH=351592D5...`
   - `ParentImage: C:\Windows\Explorer.EXE` (PID 1684)

   This confirms the user launching the binary from the Downloads folder and provides a strong set of file hashes for IOC purposes.

3. **DLL extraction phase (multiple Event ID 11 - RuleName: DLL)**
   Several Sysmon 11 events are triggered shortly after process creation, all with:
   - `Image: C:\Users\adminlab\Downloads\update_win.exe`
   - `TargetFilename` values under `C:\Users\adminlab\AppData\Local\Temp\_MEIxxxxx\`, for example:
     - `python313.dll`
     - `libssl-3.dll`
     - `libffi-8.dll`
     - `libcrypto-3.dll`
     - `VCRUNTIME140.dll`

   This pattern is typical of **PyInstaller**-packed executables, where a first-stage loader unpacks the Python runtime and libraries into a temporary `_MEI*` directory.

4. **Second-stage child processes (Event ID 1)**
   Additional Sysmon process-creation events show `update_win.exe` spawning child instances of itself:

   - Example:
     - Parent: `update_win.exe` (PID 13092)
     - Child: `update_win.exe` (PID 13024)

   The resulting process tree looks like:

   `explorer.exe → update_win.exe (loader) → update_win.exe (second stage)`

   This two-stage chain is another strong indicator of PyInstaller-based malware.

5. **Network connections (Event ID 3 - NetworkConnect)**
   - `Image: C:\Users\adminlab\Downloads\update_win.exe`
   - `SourceIp: 192.168.56.20` (WS01), `SourcePort: 49675 / 49677`
   - `DestinationIp: 192.168.56.30`, `DestinationPort: 8000`
   - `Protocol: tcp`, `Initiated: true`

   These entries match the HTTP GET requests observed on the Kali HTTP server and in the PCAP, confirming that `update_win.exe` is responsible for the C2-like “phone home” behaviour.

### 4.2 Process execution and behaviour (memory forensics)

Volatility `windows.pslist` and `windows.pstree` show multiple instances of `update_win.exe` running at the time of acquisition:

* Example entries (simplified):

  * `PID 13092, PPID 1684, Image: update_win.exe, Start: 2025-11-26 12:44:57 UTC`
  * `PID 13024, PPID 13092, Image: update_win.exe, Start: 2025-11-26 12:44:57 UTC`
  * `PID 11800, PPID 1684, Image: update_win.exe, Start: 2025-11-26 12:45:02 UTC`
  * `PID 8640,  PPID 11800, Image: update_win.exe, Start: 2025-11-26 12:45:02 UTC`

All instances point to the same executable path:

* `\Device\HarddiskVolume2\Users\adminlab\Downloads\update_win.exe`
* Command line from `windows.cmdline` confirms execution from that path:

  * `"C:\Users\adminlab\Downloads\update_win.exe"`

`windows.handles` highlights:

* A file handle to `\Users\adminlab\AppData\Local\Temp\_MEIxxxxxx\base_library.zip`, indicative of a **PyInstaller-packed** Python executable.
* Console handles (`\Device\ConDrv\...`) showing that it was launched from a console (PowerShell/cmd).
* A handle to `\Device\Afd\AsyncConnectHlp`, consistent with the process using network sockets.

No suspicious code injections or unusual memory regions were observed in `windows.malfind`; the process appears to be a standalone userland executable.

### 4.3 File-system impact

Host triage and directory listing on WS01 reveal the following artefacts:

1. **Ransomware-like renaming in user documents**

   * In `C:\Users\adminlab\Documents`, benign test files were renamed:

     * `SensitiveFile1.txt` → `SensitiveFile1.txt.locked`
     * `SensitiveFile2.txt` → `SensitiveFile2.txt.locked`
   * This demonstrates a simple ransomware-style behaviour (extension appending) rather than true encryption.

2. **Dropped artefact in `C:\Users\Public`**

   * File: `C:\Users\Public\malware_log.txt`
   * Contents: `I was here.` (plaintext)
   * This file is created by the malware as a disk artefact / marker.

3. **Executable on disk**

   * The original binary `update_win.exe` was recovered from memory using Volatility (`windows.filescan` + `windows.dumpfiles`) and hashed:

     * Original file SHA-256:
       `347c93696c437e5e69339e23f5327c27e6f69a379e29be9ad30e759b46f86cf3`
     * Memory-backed images (`.dat`, `.img`) have different hashes, as expected for loaded PE images.

### 4.4 Network activity

A Python HTTP server was running on the Kali host (attacker simulation) on port 8000.
The server logs show inbound requests from WS01:

* Source IP: `192.168.56.20` (WS01)
* Destination: `http://192.168.56.30:8000/connect?user=adminlab&os=Windows`
* HTTP method: `GET`
* Response code: `404` (expected from a simple Python `http.server`)

Wireshark PCAP captured the same HTTP traffic between WS01 and the Kali host. This behaviour matches the “phone-home” / C2 simulation stage in the malware code.

At the time of memory acquisition, `windows.netscan` shows no active connections belonging to `update_win.exe`, which is consistent with a short-lived HTTP request occurring before the memory snapshot.

### 4.5 Persistence

Registry and artefact analysis did not reveal any persistence mechanisms:

* Volatility `windows.registry.hivelist` / `windows.registry.printkey` did not show Run/RunOnce or similar keys related to `update_win.exe`.
* No scheduled tasks or services pointing to the executable were identified in the available artefacts.

Conclusion: in this scenario, `update_win.exe` appears to rely on **manual execution** without a durable persistence mechanism.

---

## 5. Indicators of Compromise (IOCs)

### 5.1 File IOCs

**Executable**

* Path: `C:\Users\adminlab\Downloads\update_win.exe`
* SHA-256 (original on disk):
  `347c93696c437e5e69339e23f5327c27e6f69a379e29be9ad30e759b46f86cf3`

**Dropped file**

* Path: `C:\Users\Public\malware_log.txt`
* Contents: `I was here.`

**Ransomware artefacts**

* Directory: `C:\Users\adminlab\Documents\`
* Pattern: `*.locked` (e.g. `SensitiveFile1.txt.locked`, `SensitiveFile2.txt.locked`)

**Prefetch / execution trace**

* Prefetch entry (from KAPE triage): `UPDATE_WIN.EXE-*.pf` (indicates execution of the binary).

### 5.2 Registry / configuration

* None identified (no Run key or scheduled task associated with `update_win.exe` in this scenario).

### 5.3 Network IOCs

* Attacker host (lab): `192.168.56.30`
* Victim host: `192.168.56.20`
* Protocol: HTTP
* URI pattern: `/connect?user=<username>&os=<os>`
* Port: TCP 8000

---

## 6. Conclusions

The investigation confirms that workstation WS01 executed a suspicious Python-based executable (`update_win.exe`) packed with PyInstaller. The program:

1. Collected basic host information (username, OS) and exfiltrated it via a single HTTP GET request to an external host on the lab network.
2. Dropped a marker file to `C:\Users\Public\malware_log.txt`.
3. Renamed files in the user’s Documents directory by appending `.locked`, mimicking ransomware behaviour.
4. Remained running in memory (long-lived process tree), but did not establish persistence at the OS level.

Activity was limited to the local host; no evidence of lateral movement or domain compromise was found in the data examined.

---

## 7. Recommendations

Based on this incident, the following measures are recommended for a production environment:

1. **Detection**

   * Add detection rules for:

     * execution of unknown binaries from `Downloads` / user profile paths,
     * creation of files under `C:\Users\Public\` with suspicious names (e.g. `*malware*`),
     * bulk renaming of files to extensions such as `.locked`.
   * Monitor Sysmon Event ID 1, 3, 11 for patterns matching `update_win.exe`-like behaviour.

2. **Endpoint hardening**

   * Restrict execution from user writeable locations where possible.
   * Enforce application control (AppLocker / WDAC) to limit execution of unsigned or unknown binaries.

3. **User awareness**

   * Train users to avoid running executables from untrusted sources and to report unexpected file renames or ransom-style messages immediately.

4. **IR playbooks**

   * Maintain and test playbooks that include:

     * quick memory and artefact acquisition,
     * triage of Sysmon / EVTX / Prefetch / Amcache,
     * network capture in suspected C2 scenarios.

---

## 8. Appendix - High-Level Timeline (UTC)

| Time (approx.)          | Source          | Event                                                                |
| ----------------------- | --------------- | -------------------------------------------------------------------- |
| 2025-11-26 12:44:36.745 | Sysmon EID 11   | `update_win.exe` created in `C:\Users\adminlab\Downloads`            |
| 2025-11-26 12:44:57     | Volatility      | First `update_win.exe` process started (PID 13092/13024)             |
| 2025-11-26 12:45:02     | Volatility      | Additional `update_win.exe` processes (PIDs 11800, 8640)             |
| ~2025-11-26 12:45:00-05    | Wireshark/HTTP  | HTTP GET `/connect?user=adminlab&os=Windows` to 192.168.56.30:8000   |
| 2025-11-26 12:45:01-06     | Host filesystem | Files in `Documents` renamed to `.locked`; `malware_log.txt` created |
| 2025-11-26 12:45:16-19  | Volatility / PS | `kape.exe` and `DumpIt.exe` executed for artefact collection         |
| 2025-11-26 12:45:23     | Volatility info | System time recorded in memory image header                          |

This timeline correlates user activity, malware execution, network communication, and response actions taken during the investigation.

