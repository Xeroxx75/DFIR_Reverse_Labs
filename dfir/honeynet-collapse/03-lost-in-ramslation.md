# Lost in RAMslation - Memory

## Context and Scope

Identify the process responsible for the activity on `SRV-DMZ-GW`, reconstruct the execution chain, characterize the suspicious memory regions in `notepad.exe`, and relate recovered network state to the attack.

## Initial Reconnaissance and Evidence

| Item | Detail |
| --- | --- |
| Host | `SRV-DMZ-GW` |
| Memory image | `SRV-DMZ-GW-evidence.mem` |
| Provenance | Challenge-provided memory image |
| SHA-256 | `87b01071e56cccdffc0abc04f3d21ae7375d2b7d7530ad7f6de7ba5f94a54b07` |
| Observed system | Windows `10.0.17763`, x64, server product type |
| System time in the image | `2025-07-02 01:09:19 UTC` |
| Tool | Volatility 3 Framework `2.26.0` |
| Symbols | `windows.info` resolved `ntkrnlmp.pdb` |

## Evidence Constraints

- A memory image is a partial view of a running system. Terminated processes, missing pages and residual sockets affect the conclusions.
- `windows.info` reports the guest system time stored in the image. It is not an independent acquisition timestamp.
- `malfind` is heuristic. Private executable memory can represent injected code, JIT output or another legitimate mechanism.
- The dump alone does not establish the remote origin of a command or the success of a network action.

## Reusable Methods

- [Windows memory triage](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/03-PRACTICE/forensics/memory-triage.md) - route the investigation by hypothesis before running the full plugin set.
- [Volatility 3](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/01-TOOLS/dfir/details/volatility3.md) - use the commands and version-specific plugin options.
- [Windows internals](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/02-CONCEPTS/windows/windows-internals.md) - interpret process trees, VADs, modules and handles.
- [Case template](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/03-PRACTICE/forensics/case-template.md) - separate observation, interpretation, confidence and constraint.

## Method

The analysis followed the Volatility 3 process flow and kept the PID, PPID, command line, memory address and source for every pivot.

1. Validate the image and symbols with `windows.info`.
2. Reconstruct the process tree with `windows.pstree` and compare it with `windows.psscan`.
3. Recover command lines and console buffers with `windows.cmdline`, `windows.cmdscan` and `windows.consoles`.
4. Inspect modules and objects with `windows.dlllist` and `windows.handles`.
5. Target the final process with `windows.vadinfo` and `windows.malfind`.
6. Associate sockets with processes using `windows.netscan`.

```bash
vol -f SRV-DMZ-GW-evidence.mem windows.info
vol -f SRV-DMZ-GW-evidence.mem windows.pstree
vol -f SRV-DMZ-GW-evidence.mem windows.psscan
vol -f SRV-DMZ-GW-evidence.mem windows.cmdline
vol -f SRV-DMZ-GW-evidence.mem windows.cmdscan
vol -f SRV-DMZ-GW-evidence.mem windows.consoles
vol -f SRV-DMZ-GW-evidence.mem windows.dlllist --pid PID
vol -f SRV-DMZ-GW-evidence.mem windows.handles --pid PID
vol -f SRV-DMZ-GW-evidence.mem windows.vadinfo --pid PID
vol -f SRV-DMZ-GW-evidence.mem windows.malfind --pid PID
vol -f SRV-DMZ-GW-evidence.mem windows.netscan
```

Plugin names and columns depend on the installed version. Check `vol -h` before treating a missing plugin as an evidence problem.

## Analysis Log

| Action | Source | Useful result |
| --- | --- | --- |
| `windows.info` | Kernel and memory layer | Windows x64, build `10.0.17763`, resolved symbols and system time |
| `windows.pstree` and `windows.psscan` | Process structures | `PSEXESVC` -> `cmd` -> `rundll32` -> payload -> `notepad` -> PowerShell |
| `windows.cmdline` | Process arguments | Full `rundll32.exe` command and payload paths |
| `windows.cmdscan` and `windows.consoles` | `conhost.exe` sessions | Buffers containing network, download and operator activity |
| `windows.dlllist` and `windows.handles` | Target processes | `MicrosoftUpdate.dll` mapped in `rundll32`; no useful handle for the terminated process |
| `windows.malfind --pid 836` | `notepad.exe` | Two private executable regions, including a 200 KiB region containing shellcode |
| `windows.netscan` | Recovered sockets | Connections related to ports 4443, 8081, SMB/445 and RDP/3389 |

## Observations

### O-01 - The image is usable with the expected Windows symbols

- **Source:** `windows.info`.
- **Observation:** The `WindowsIntel32e` layer is 64-bit, `NtSystemRoot` is `C:\Windows`, the build is `10.0.17763`, and `ntkrnlmp.pdb` was resolved.
- **Interpretation:** The Windows plugins can be used with this symbol configuration and the output is coherent enough to continue triage.
- **Evidence constraint:** Symbol resolution does not guarantee that every page or structure is present.

### O-02 - The execution chain starts with `rundll32.exe`

- **Sources:** `windows.pstree`, `windows.psscan` and `windows.cmdline`.
- **Observation:** The reconstructed chain is:

  ```text
  PSEXESVC.exe (2996)
  -> cmd.exe (2100)
     -> rundll32.exe (2928)
        -> windows-update.exe (2676)
           -> security-update.exe (1444, terminated)
              -> notepad.exe (836)
                 -> cmd.exe (1652)
                    -> powershell.exe (464)
  ```

  PID `2928` ran `rundll32.exe C:\Windows\Tasks\MicrosoftUpdate.dll, RunMe`. `security-update.exe` was created from Matthew's profile and terminated before acquisition.
- **Interpretation:** `rundll32.exe` loaded `MicrosoftUpdate.dll` and called the `RunMe` export. The chain is consistent with a PsExec service starting an initial stage, followed by a second stage and activity inside `notepad.exe`.
- **Evidence constraint:** The image does not prove that `PSEXESVC.exe` originated on another host or that every relation represents a direct process creation without injection.

### O-03 - Console buffers retain operator activity

- **Sources:** `windows.cmdscan` and `windows.consoles`.
- **Observation:** `cmdscan` recovered console structures with null command counts. `consoles` still recovered a screen buffer for PID `2680` showing port `4443`, a connection, `alive`, exfiltration of `hosts` to `167.172.41.141`, and the download, execution and deletion of `C:\Users\matthew.collins\Downloads\security-update.exe`. Another buffer for PID `600` mentions `ipconfig`, `whoami` and `cmd`.
- **Interpretation:** The buffer preserves payload activity even though a normal command history was unavailable.
- **Evidence constraint:** A reused memory buffer does not necessarily provide reliable timestamps. The displayed messages should be correlated with logs or disk evidence.

### O-04 - The initial DLL is mapped in `rundll32.exe`

- **Sources:** `windows.dlllist --pid 2928` and `windows.handles`.
- **Observation:** PID `2928` lists `C:\Windows\Tasks\MicrosoftUpdate.dll`. Handles from active processes did not provide a distinctive additional object, and the terminated `security-update.exe` had no exploitable handle.
- **Interpretation:** The module list strengthens the link between the `rundll32.exe` command line and the initial payload.
- **Evidence constraint:** An absent handle does not prove that a file or connection was never used.

### O-05 - `notepad.exe` contains two private executable regions

- **Sources:** `windows.malfind --pid 836`, VAD output and the displayed disassembly.
- **Observation:** `malfind` reports two `PAGE_EXECUTE_READWRITE` private regions in PID `836`: one of 4 KiB and one of 200 KiB. The second starts with `fc 48 89 ce 48` and matches the Meterpreter shellcode requested by the room. Executable regions in PowerShell require more caution because the CLR/JIT can create dynamic executable memory.
- **Interpretation:** The combination of private executable memory, the recovered bytes and the process chain is strongly consistent with shellcode injected into `notepad.exe`.
- **Evidence constraint:** Without thread start data, a write event or stronger file/network correlation, the injection conclusion remains a high-confidence interpretation rather than a direct memory write record.

### O-06 - Recovered sockets connect the payload to several actions

- **Source:** `windows.netscan`.
- **Observation:** `windows-update.exe` (PID `2676`) uses port `4443` and communicates with `172.16.8.216`; `security-update.exe` (PID `1444`) connects to `167.172.41.141:8081`; SMB connections to `172.16.8.216:445` appear near `PSEXESVC.exe`; PowerShell (PID `464`) connects to `172.16.2.9:3389`.
- **Interpretation:** `172.16.2.9` is the RDP lateral-movement address requested by the room. The other connections are consistent with C2, download and PsExec activity.
- **Evidence constraint:** `netscan` recovers socket state, not an exact connection time or proof of remote success.

## Findings

### F-01 - Initial payload and execution command

- **Evidence:** O-02 and O-04.
- **Conclusion:** The initial payload is `C:\Windows\Tasks\MicrosoftUpdate.dll`, loaded by PID `2928` with `rundll32.exe C:\Windows\Tasks\MicrosoftUpdate.dll, RunMe`.
- **Confidence:** High for the path, PID and command; medium for attribution to a remote operator.

### F-02 - The final process in the chain is `notepad.exe`

- **Evidence:** O-02, O-03 and O-05.
- **Conclusion:** The chain reaches `notepad.exe` (PID `836`), which contains the executable regions associated with the shellcode.
- **Confidence:** High for the reconstructed chain; medium to high for the injection interpretation.

### F-03 - Recovered shellcode bytes

- **Evidence:** The second `malfind` region in PID `836`.
- **Conclusion:** The first five bytes are `fc4889ce48`. The room identifies the region as Meterpreter shellcode.
- **Confidence:** High for the bytes; the family label remains context-dependent.

### F-04 - RDP lateral-movement address

- **Evidence:** `windows.netscan`, socket associated with PID `464`.
- **Conclusion:** The host contacted over port `3389` is `172.16.2.9`.
- **Confidence:** High for the IP, port and PID association; session success requires logs from the remote host.

## Impact and Remediation

The host contains a multi-stage execution chain, private executable memory in a benign process and network activity toward internal and external addresses. A real response would isolate the host, preserve memory and disk evidence, invalidate credentials used by the chain, and correlate the identified paths, hashes and addresses across endpoint telemetry.

## Events in the Global Timeline

| ID | Timestamp (UTC) | Host | Event | Source | Finding |
| --- | --- | --- | --- | --- | --- |
| T-MEM-01 | 2025-07-02 01:01:37 | `SRV-DMZ-GW` | `PSEXESVC.exe` (PID `2996`) and its `cmd.exe` child appear. | `windows.pstree` | F-01 |
| T-MEM-02 | 2025-07-02 01:04:39 | `SRV-DMZ-GW` | `rundll32.exe` (PID `2928`) launches `MicrosoftUpdate.dll, RunMe`. | `windows.pstree` / `cmdline` | F-01 |
| T-MEM-03 | 2025-07-02 01:04:40 | `SRV-DMZ-GW` | `windows-update.exe` (PID `2676`) is created. | `windows.pstree` | F-01 |
| T-MEM-04 | 2025-07-02 01:05:29 | `SRV-DMZ-GW` | `security-update.exe` (PID `1444`) is created from the user profile. | `windows.pstree` | F-02 |
| T-MEM-05 | 2025-07-02 01:06:07 | `SRV-DMZ-GW` | `notepad.exe` (PID `836`) is created under `security-update.exe`. | `windows.pstree` | F-02 |
| T-MEM-06 | 2025-07-02 01:07:52 | `SRV-DMZ-GW` | `cmd.exe` (PID `1652`) is created under `notepad.exe`. | `windows.pstree` | F-02 |
| T-MEM-07 | 2025-07-02 01:08:03 | `SRV-DMZ-GW` | PowerShell (PID `464`) is created under `cmd.exe`. | `windows.pstree` | F-04 |

The `netscan` connections remain observations because the image does not provide their exact timestamps.

## Handoff to the Next Stage

| Pivot | Value | Next use |
| --- | --- | --- |
| Initial DLL | `C:\Windows\Tasks\MicrosoftUpdate.dll` | Search for the file, persistence and disk traces. |
| Initial execution | PID `2928`, `rundll32.exe ... MicrosoftUpdate.dll, RunMe` | Correlate with logs and process artifacts. |
| Process chain | `windows-update.exe` -> `security-update.exe` -> `notepad.exe` -> PowerShell | Pivot to disk, network and memory evidence. |
| Shellcode | PID `836`, 200 KiB region, bytes `fc4889ce48` | Extract or compare memory content in an authorized lab. |
| C2 and second stage | `167.172.41.141:8081` and `172.16.8.216:4443/445` | Correlate with Linux and Windows hosts. |
| Lateral movement | `172.16.2.9:3389` from PowerShell PID `464` | Search the remote host for RDP evidence. |
| Existing campaign pivot | `167.172.41.141` | Keep the infrastructure pivot when correlating the disk and filesystem stages. |

## What I Learned

- A Volatility workflow becomes more reliable when every process, command line, VAD and socket is tied to a PID and a source plugin.
- `pstree`, console buffers and VAD analysis complement one another when process creation logs are missing.
- `malfind` is a triage signal. Injection claims need process-chain, thread and host correlation.
