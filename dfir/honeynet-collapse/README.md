# Honeynet Collapse

## Context and Scope

Honeynet Collapse is a multi-stage endpoint investigation following the compromise of DeceptiTech. The investigation spans Linux, Windows, memory, disk, filesystem and macOS evidence. The objective is to reconstruct the attack chain across the six environments and consolidate the significant events into one global timeline.

This write-up covers the six stages of the investigation, from the Linux foothold to the Windows, memory, disk, filesystem and macOS evidence.

## Systems and Evidence

| ID | Day | System | Evidence examined | Related note |
| --- | --- | --- | --- | --- |
| E-LNX-01 | Friday, Day 1 | `deceptipot-demo` - Linux / WordPress | Live SSH triage; Apache access logs; auditd records; filesystem metadata and PHP content; SSH configuration; shell history; systemd service configuration and status | [01-Initial-Access-Pot-Linux](01-initial-access-pot-linux.md) |
| E-WIN-01 | Monday, Day 4 | `SRV-IT-QA` - Windows Server 2019 | Live RDP triage; Terminal Services and Security EVTX; `$MFT`; `$UsnJrnl:$J`; Prefetch; PowerShell transcripts; `text.txt.dmp` | [02-Elevating-Movement-Windows](02-elevating-movement-windows.md) |
| E-MEM-01 | Wednesday, Day 6 | `SRV-DMZ-GW` - Windows memory | `SRV-DMZ-GW-evidence.mem`; Volatility 3 `windows.info`, process, console, VAD and network plugins | [03-Lost-in-RAMslation](03-lost-in-ramslation.md) |
| E-DISK-01 | Thursday, Day 7 | `SRV-CRM-01` - Windows disk | disk image, EVTX export, `NTUSER.DAT`, UserAssist, PowerShell history, rclone configuration and CRM exports | [04-CRM-Snatch-Disk](04-crm-snatch-disk.md) |
| E-FS-01 | Friday, Day 8 | `DC-01` - NTFS logs | partial AD1, `$MFT`, USN Journal, `$LogFile`, `$Boot`, `$Bitmap` and `Zone.Identifier` | [05-Shock-and-Silence-Filesystem](05-shock-and-silence-filesystem.md) |
| E-MAC-01 | macOS stage | Lucas Rivera's Mac | APFS image, Safari downloads, InstallHistory, TCC.db, application bundle and LaunchAgents | [06-The-Last-Trial-macOS](06-the-last-trial-macos.md) |

## Evidence Constraints

Only constraints that affect a conclusion are retained here:

- The two live-triage stages did not provide a complete forensic acquisition. The Linux command sequence without timestamps is therefore used for ordering, not for dating events, and Windows Event ID 1149 establishes an RDP connection rather than a complete authenticated session by itself.
- The memory image preserves process and socket state at acquisition, but its network entries have no exact event time. They are not placed in the timestamped timeline.
- The disk and filesystem evidence is partial. It demonstrates staging and ransomware activity, but does not independently prove successful transfer to Mega or preserve every original executable.
- The macOS artifacts demonstrate delivery, installation, permissions and implemented collection behavior. They do not independently prove which files reached the C2.

## Major Findings

| ID | Conclusion | System | Confidence | Note |
| --- | --- | --- | --- | --- |
| F-LNX-01 | An attacker brute-forced the WordPress login and obtained administrative access. | `deceptipot-demo` | High | 01 |
| F-LNX-02 | The attacker backdoored the Blocksy theme's `404.php` file with a command-execution webshell. | `deceptipot-demo` | High | 01 |
| F-LNX-03 | Commands executed through the compromised web application exposed and used a local root SSH private key. | `deceptipot-demo` | High | 01 |
| F-LNX-04 | SSH authentication as root on localhost succeeded using the copied key. | `deceptipot-demo` | High | 01 |
| F-LNX-05 | After obtaining root, the attacker scanned an internal range, probed `172.16.8.216` and executed a downloaded second-stage payload. | `deceptipot-demo` | High for the recorded sequence | 01 |
| F-LNX-06 | Persistence was established through `kworker.service`, launching `/usr/sbin/kworker` and reconnecting to the external infrastructure. | `deceptipot-demo` | High | 01 |
| F-WIN-01 | An RDP network connection to `SRV-IT-QA` originated from `172.16.8.239` (DeceptiPot) at `2025-06-30 16:33:16`; the event associated the connection with `emily.ross`. | `SRV-IT-QA` | High for the connection; medium for authenticated-user attribution | 02 |
| F-WIN-02 | `Coreinfo64.exe`, whose PE original filename is `ab.exe`, is the replaced binary relevant to persistence and privilege escalation. | `SRV-IT-QA` | Medium to high | 02 |
| F-WIN-03 | A PowerShell transcript records `pcd.exe /accepteula -ma lsass.exe text.txt`, followed by retrieval of `text.txt.dmp`. | `SRV-IT-QA` | High for the recorded command | 02 |
| F-WIN-04 | Prefetch records `psexesvc` with a last run at `2025-06-30 19:47:14`, consistent with PsExec-style lateral movement. | `SRV-IT-QA` | High for execution; medium for remote outcome | 02 |
| F-WIN-05 | The LSASS minidump contains the NTLM field for `DECEPT\matthew.collins`: raw value omitted. | `SRV-IT-QA` | High within the authorized lab evidence | 02 |
| F-MEM-01 | `MicrosoftUpdate.dll` was loaded by `rundll32.exe` (PID `2928`) with export `RunMe`, leading to `windows-update.exe` and the later process chain. | `SRV-DMZ-GW` | High for the observed memory chain; medium for remote attribution | 03 |
| F-MEM-02 | `notepad.exe` (PID `836`) contains a private executable region whose first five bytes are `fc4889ce48`, identified by the room as Meterpreter shellcode. | `SRV-DMZ-GW` | High for the bytes; medium for the injection conclusion | 03 |
| F-MEM-03 | PowerShell (PID `464`) has a socket to `172.16.2.9:3389`, the RDP lateral-movement address. | `SRV-DMZ-GW` | High for the IP/port association; remote success unconfirmed | 03 |
| F-DISK-01 | `matthew.collins` is the domain account associated with the remote session; UserAssist records 3,455 seconds of PowerShell focus time. | `SRV-CRM-01` | Medium for account attribution; high for the UserAssist value | 04 |
| F-DISK-02 | `rclone` was configured to stage CRM data to Mega through `167.172.41.141`; the exports contain `lucas.rivera@deceptitech.thm`. | `SRV-CRM-01` | High for configuration and data presence; transfer success unconfirmed | 04 |
| F-FS-01 | `HiddenFile.zip` was downloaded from Gofile, `pb.exe` is the original ransomware filename and `.EeUfy` is the appended extension. | `DC-01` | High for filesystem/provenance artifacts | 05 |
| F-FS-02 | `HpAgent.exe` precedes the rename wave; an OSINT pivot from the ransom note identifies BlackLock. | `DC-01` | Medium to high; group attribution is OSINT-based | 05 |
| F-MAC-01 | `DevelopAIInstaller.pkg` was downloaded from `developai.thm`, installed at `2025-07-04 10:09:03`, and first received Desktop TCC access. | Mac de Lucas | High for recorded artifacts | 06 |
| F-MAC-02 | The application collects recent sensitive files, POSTs a ZIP to `http://c7.macos-updatesupport.info:8080` and persists through a user LaunchAgent. | Mac de Lucas | High for static script/configuration; network success unconfirmed | 06 |

## Global Timeline

| ID | Timestamp (UTC) | Host | Event | Source |
| --- | --- | --- | --- | --- |
| T-LNX-01 | 2025-06-27 21:20:27 | `deceptipot-demo` | Automated brute force begins against `/wp-login.php`. | Apache access log |
| T-LNX-02 | 2025-06-27 21:21:27 | `deceptipot-demo` | WordPress authentication succeeds and `/wp-admin/` is accessed. | Apache access log |
| T-LNX-03 | 2025-06-27 21:21:50 | `deceptipot-demo` | The attacker opens the theme editor. | Apache access log |
| T-LNX-04 | 2025-06-27 21:22:46 | `deceptipot-demo` | The Blocksy `404.php` template is selected. | Apache access log |
| T-LNX-05 | 2025-06-27 21:23 | `deceptipot-demo` | `404.php` is modified and contains a webshell. | File metadata and content |
| T-LNX-06 | 2025-06-27 22:07:53 | `deceptipot-demo` | The exposed root key is copied to `/tmp/key`. | auditd |
| T-LNX-07 | 2025-06-27 22:08:00 | `deceptipot-demo` | Key permissions are changed to `400`. | auditd |
| T-LNX-08 | 2025-06-27 22:08:07 to 22:08:08 | `deceptipot-demo` | The key is used for a successful root login on localhost. | auditd |
| T-WIN-01 | 2025-06-30 16:33:16 | `SRV-IT-QA` | RDP connection from `172.16.8.239`, associated with `emily.ross`. | TerminalServices 1149 |
| T-WIN-02 | 2025-06-30 16:55:20 | `SRV-IT-QA` | `Coreinfo64.exe` creation, overwrite and named-stream activity. | USN Journal / MFT |
| T-WIN-03 | 2025-06-30 18:28:30 | `SRV-IT-QA` | PowerShell decodes the LSASS dump command. | PowerShell transcript |
| T-WIN-04 | 2025-06-30 18:28:52 | `SRV-IT-QA` | PowerShell decodes `download text.txt.dmp`. | PowerShell transcript |
| T-WIN-05 | 2025-06-30 19:47:14 | `SRV-IT-QA` | `psexesvc` last run. | Prefetch |
| T-MEM-01 | 2025-07-02 01:01:37 | `SRV-DMZ-GW` | `PSEXESVC.exe` and its `cmd.exe` child appear. | Volatility `windows.pstree` |
| T-MEM-02 | 2025-07-02 01:04:39 | `SRV-DMZ-GW` | `rundll32.exe` launches `MicrosoftUpdate.dll, RunMe`. | Volatility process plugins |
| T-MEM-03 | 2025-07-02 01:04:40 | `SRV-DMZ-GW` | `windows-update.exe` is created. | Volatility `windows.pstree` |
| T-MEM-04 | 2025-07-02 01:05:29 | `SRV-DMZ-GW` | `security-update.exe` is created. | Volatility `windows.pstree` |
| T-MEM-05 | 2025-07-02 01:06:07 | `SRV-DMZ-GW` | `notepad.exe` is created. | Volatility `windows.pstree` |
| T-MEM-06 | 2025-07-02 01:07:52 | `SRV-DMZ-GW` | `cmd.exe` is created under `notepad.exe`. | Volatility `windows.pstree` |
| T-MEM-07 | 2025-07-02 01:08:03 | `SRV-DMZ-GW` | PowerShell is created under `cmd.exe`. | Volatility `windows.pstree` |
| T-DISK-01 | 2025-07-03 10:33:55 | `SRV-CRM-01` | UserAssist records the last PowerShell execution. | `NTUSER.DAT` / UserAssist |
| T-DISK-02 | 2025-07-03 | `SRV-CRM-01` | PowerShell history and `mega.conf` show rclone configured toward Mega. | PowerShell history / `mega.conf` |
| T-MAC-01 | 2025-07-04 10:08:23 to 10:08:25 | Lucas Rivera's Mac | Safari downloads `DevelopAIInstaller.pkg`. | Safari `Downloads.plist` |
| T-MAC-02 | 2025-07-04 10:09:03 | Lucas Rivera's Mac | Installer registers `DevelopAIInstaller`. | `InstallHistory.plist` |
| T-MAC-03 | 2025-07-04 10:10:33 | Lucas Rivera's Mac | DevelopAI receives Desktop access. | TCC.db |
| T-MAC-04 | 2025-07-04 10:10:41 | Lucas Rivera's Mac | DevelopAI receives Downloads access. | TCC.db |
| T-MAC-05 | 2025-07-04 10:10:46 | Lucas Rivera's Mac | DevelopAI receives Documents access. | TCC.db |
| T-FS-01 | 2025-07-04 11:32-11:35 | `DC-01` | Archive download entries appear before ransomware activity. | USN Journal |
| T-FS-02 | 2025-07-04 11:52:41 | `DC-01` | `README.EeUfy.txt` appears during the rename sequence. | USN Journal |
| T-FS-03 | 2025-07-04 12:02:22 | `DC-01` | `readme_lgpl.txt` appears after the main rename wave. | USN Journal |

## Cross-Stage Correlation

The following pivots connect evidence already established across the six stages:

| Type | Value | Relevance |
| --- | --- | --- |
| External attacker / infrastructure IP | `167.172.41.141` | Brute force, payload source and C2 endpoint |
| Internal target | `172.16.8.216` | Scanned after root compromise |
| Second-stage archive | `5841.tar.gz` | Downloaded and executed, then deleted |
| Persistence executable | `/usr/sbin/kworker` | Malware launched by systemd |
| Persistence service | `/etc/systemd/system/kworker.service` | Automatic execution mechanism |
| C2 endpoint | `167.172.41.141:10443` | Outbound reconnect attempts |
| Malware MD5 | `d6f2d80e78f264aff8c7aea21acb6ca6` | Cross-room pivot |
| SSH key comment | `maksym.varnakov` | Contextual lead only; attribution unproven |
| Windows RDP source | `172.16.8.239` (`deceptipot-demo`) | Links the Linux foothold to the Windows phase |
| Windows binary | `Coreinfo64.exe`, original filename `ab.exe` | Pivot for static analysis; exact overwritten target path remains open |
| Windows sample SHA-256 | `3ae834b3d24e56a5216ca69f8210c4ba92f4315197babeb6e34eacf06952c7de` | Stable sample identifier |
| Credential-dump artifact | `text.txt.dmp`; command `pcd.exe /accepteula -ma lsass.exe text.txt` | Explains credential theft; sensitive lab material |
| Windows lateral movement | `psexesvc`, `2025-06-30 19:47:14` | Pivot to the next host/room |
| Memory payload | `C:\Windows\Tasks\MicrosoftUpdate.dll`, PID `2928`, export `RunMe` | Pivot for disk, EVTX and persistence correlation |
| Injected code | `notepad.exe` PID `836`, bytes `fc4889ce48` | Pivot for memory extraction and thread validation |
| Memory RDP destination | `172.16.2.9:3389` from PowerShell PID `464` | Search the remote host's RDP and process evidence |
| CRM exfiltration | rclone remote `crmremote` → Mega, C2 `167.172.41.141` | correlate staging commands and network evidence |
| Ransomware | Gofile `HiddenFile.zip`, `pb.exe`, extension `.EeUfy`, `HpAgent.exe` | search payload, process and recovery artifacts |
| macOS delivery | `developai.thm` → `DevelopAIInstaller.pkg` | correlate Safari, Installer, TCC and APFS evidence |
| macOS C2/persistence | `c7.macos-updatesupport.info:8080`, user LaunchAgent | inspect Unified Logs, plist and network traces |

## Conclusion

The available Linux evidence reconstructs a coherent initial compromise. An external actor brute-forced the WordPress administration interface, used the theme editor to implant a PHP webshell, then executed commands under the web-service context. The actor copied an exposed root SSH private key and successfully authenticated to the same host as root. Root-level activity included internal reconnaissance, download and execution of a second-stage payload, cleanup of the staging files and installation of a persistent systemd service communicating with the same external infrastructure.

The Windows evidence shows the next stage of the intrusion. A connection from `deceptipot-demo` reached `SRV-IT-QA` over RDP, a trojanized `Coreinfo64.exe`/`ab.exe` was identified in the post-connection file activity, and a PowerShell transcript records an LSASS dump followed by retrieval of the minidump. Prefetch places `psexesvc` at `2025-06-30 19:47:14`, while Pypykatz output provides the authorized lab's NTLM field for `matthew.collins`. The exact overwritten target path and remote PsExec destination remain to be confirmed.

The memory stage on `SRV-DMZ-GW` shows a compatible execution chain: a
PsExec-style service leads to `rundll32.exe`, which loads
`C:\Windows\Tasks\MicrosoftUpdate.dll` and starts the payloads. `notepad.exe`
contains a private executable region beginning with `fc4889ce48`, and PowerShell
has a socket to `172.16.2.9:3389`. These findings are strong pivots for the disk,
filesystem and remote-host rooms, but the dump alone cannot establish the remote
source, exact socket times or completion of the actions.

The disk stage links the stolen Windows activity to a CRM exfiltration: UserAssist
and profile artifacts point to `matthew.collins`, while rclone is configured for
Mega and the CRM exports contain Lucas Rivera's address. The filesystem stage
then shows a Gofile-delivered `pb.exe`, the `.EeUfy` rename wave and the
`HpAgent.exe` pivot; BlackLock remains an OSINT attribution. Finally, the macOS
stage documents a separate user-targeted compromise: DevelopAI is downloaded and
installed, receives TCC access, collects sensitive files, posts them to an HTTP
C2 and persists with a LaunchAgent.

Taken together, the six stages document initial access, privilege escalation,
lateral movement, credential access, payload execution, data staging,
ransomware activity and a separate macOS collection operation. Where the
available artifact demonstrates configuration or intended behavior rather than
successful completion, the corresponding finding states that distinction
directly.
