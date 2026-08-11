# Elevating Movement - Windows

## Context and Scope

Determine how the attacker used the Windows host during Monday, Day 4:

- identify the RDP connection from DeceptiPot;
- identify the executable replaced for persistence and privilege escalation;
- characterize the replaced binary without treating an antivirus label as proof;
- recover the command used to dump OS credentials;
- identify the lateral-movement time and the recovered NTLM hash.

## Initial Reconnaissance and Evidence

| Item | Detail |
| --- | --- |
| Host | `SRV-IT-QA` (`SRV-IT-QA.deceptitech.thm`) |
| Platform | Windows Server 2019 Datacenter |
| Access method | Live triage through RDP as a local administrator |
| Time convention | UTC |
| Primary sources | Terminal Services and Security EVTX, `$MFT`, `$UsnJrnl:$J`, Prefetch, PowerShell transcripts and `text.txt.dmp` |
| Main parsers | EvtxECmd, MFTECmd, PECmd and Timeline Explorer |

## Evidence Constraints

- The host was investigated live rather than from a forensic image.
- The available MFT/USN evidence identifies the executable but does not preserve the full path of the overwritten persistence target. The confirmed copy is under `C:\Users\emily.ross\Documents`.
- Event coverage depends on audit policy, channel retention and Prefetch availability. A missing event is not proof that an action did not occur.
- The credential material is a challenge artifact. It must not be copied into a real case report or shared outside the authorized lab.

## Reusable Methods

- [Forensic Windows - Méthodologie](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/03-PRACTICE/windows-forensics.md) - select sources from the investigation question;
- [Artefacts Windows](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/03-PRACTICE/forensics/windows-artifacts.md) - interpret RDP, Prefetch, MFT/USN and PowerShell sources;
- [Outils forensic Windows](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/01-TOOLS/dfir/windows-forensic-tools.md) - minimal KAPE, Hayabusa, Zimmerman and Pypykatz procedures;
- [Journaux Windows et Event IDs](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/02-CONCEPTS/windows/event-logs.md) - correlate providers, channels and fields.

## Method

1. Copy the relevant EVTX channels before parsing. Start with `Security.evtx`, `TerminalServices-RemoteConnectionManager/Operational` and `TerminalServices-LocalSessionManager/Operational`; use the noisier RDP CoreTS channel only when the connection sequence requires it.
2. Run EvtxECmd for provider fields and use Hayabusa as a fast rule-based triage pass. Validate an important alert in the original EVTX/XML.
3. Parse `$MFT` and `$UsnJrnl:$J` with MFTECmd. In Timeline Explorer, narrow the USN output to executable extensions and the RDP period before reviewing update reasons and paths.
4. Parse `C:\Windows\Prefetch` with PECmd. Use the normal output to review run count/last-run metadata and the timeline output to place executions among other events.
5. Search all user profiles for PowerShell transcripts, then decode only the Base64 wrapper needed to recover the command. A transcript is more useful here than an empty or later-created PSReadLine history.
6. Treat the LSASS minidump as a sensitive artifact. Parse a copy with Pypykatz and record only the field required by the lab.

## Analysis Log

| Analyst action | Source | Result |
| --- | --- | --- |
| `EvtxECmd.exe -d <RDP exports> --csv <Parsed\RDP>` | Terminal Services and Security EVTX | Provider, channel and payload fields available for correlation |
| Filter `Event ID = 1149` and the 2025-06-30 window | RemoteConnectionManager/Operational | RDP connection from `172.16.8.239` at `16:33:16` |
| `MFTECmd.exe -f 'C:\$MFT' --csv <Parsed\MFT>` and parse `$UsnJrnl:$J` | MFT and USN Journal | `Coreinfo64.exe` activity after the connection; copy under Emily's profile; original filename `ab.exe` |
| `PECmd.exe -d C:\Windows\Prefetch --csv <Parsed\Prefetch>` | Prefetch | `psexesvc` last run at `2025-06-30 19:47:14` |
| `Get-ChildItem C:\ -Filter 'PowerShell_transcript*' -Recurse -ErrorAction SilentlyContinue` | User profiles | Transcript containing the encoded credential-dump command |
| Decode the two Base64 expressions in the Administrator transcript | PowerShell transcript | `pcd.exe /accepteula -ma lsass.exe text.txt`, followed by `download text.txt.dmp` |
| Parse `text.txt.dmp` with Pypykatz | LSASS minidump | NTLM field for `DECEPT\matthew.collins` |

## Observations

### O-01 - RDP connection from DeceptiPot

- **Source:** `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`, Event ID `1149`, parsed with EvtxECmd.
- **Observation:** At `2025-06-30 16:33:16`, the provider recorded `RDP network connection established`, user `\emily.ross@deceptite` and remote host `172.16.8.239` on `SRV-IT-QA.deceptitech.thm`.
- **Interpretation:** A network-level RDP connection was established from the DeceptiPot host. The account field is the value rendered by the event and may be truncated.
- **Limit:** Event 1149 alone is not the complete proof of an authenticated interactive session. Correlate it with Security `4624` (`LogonType = 10`) and LocalSessionManager events when those records are available.

### O-02 - `Coreinfo64.exe` shows post-RDP replacement activity

- **Sources:** `$UsnJrnl:$J`, `$MFT`, Timeline Explorer and the file's PE metadata.
- **Observation:** Filtering executable USN records from `2025-06-30 16:00` to midnight exposed a high-activity sequence for `Coreinfo64.exe` after the RDP connection. The sequence includes creation/data-extension, overwrite, close, basic-information and named-stream changes. The MFT also shows a copy under `C:\Users\emily.ross\Documents`; its PE metadata reports original filename `ab.exe`.
- **Interpretation:** The activity is consistent with a staged or replaced executable. The original filename is a strong identifier for the payload, not proof by itself of which target was overwritten.
- **Limit:** USN reasons describe filesystem changes, not intent. The exact path of the persistence target must be confirmed from the original MFT row/export before treating it as a complete path answer.

### O-03 - The binary is a trojanized ApacheBench sample

- **Source:** SHA-256 `3ae834b3d24e56a5216ca69f8210c4ba92f4315197babeb6e34eacf06952c7de`, original filename `ab.exe`, static triage and VirusTotal Code Insights.
- **Observation:** The sample contains ApacheBench strings and `WS2_32` networking imports but also obfuscated x86 code using uncommon instructions such as `AAA`, `DAS`, `DAA` and `SALC`. Some engines label it `Meterpreter`; other labels include `swrort`, `cryptz` and `marte`.
- **Interpretation:** The defensible description is a trojanized/obfuscated ApacheBench-derived network-capable binary. The labels support a Meterpreter-related hypothesis but do not establish a unique family.
- **Limit:** External scanner labels and automated Code Insights are triage evidence. Confirm family and behavior through controlled static/dynamic analysis before using a family name operationally.

### O-04 - The PowerShell transcript records an LSASS dump

- **Source:** `C:\Users\Administrator\Documents\20250630\PowerShell_transcript.SRV-IT-QA.KSUYD5bK.20250630182641.txt`.
- **Observation:** At approximately `2025-06-30 18:28:30`, a Base64-decoding expression produced the exact command:

  ```powershell
  pcd.exe /accepteula -ma lsass.exe text.txt
  ```

  At approximately `18:28:52`, a second expression produced `download text.txt.dmp`.
- **Interpretation:** The operator used a ProcDump-like executable (the observed name is `pcd.exe`) to create an LSASS minidump and then retrieved it. The transcript preserves the command even though process-creation EVTX coverage starts later.
- **Limit:** The command name alone does not prove which binary `pcd.exe` was or whether the dump completed successfully; validate with the file, Prefetch or process telemetry when available.

### O-05 - PsExec-style lateral movement

- **Source:** PECmd output for `C:\Windows\Prefetch`.
- **Observation:** `psexesvc` has a last-run timestamp of `2025-06-30 19:47:14`.
- **Interpretation:** This is the time required by the room for the lateral-movement action and is consistent with PsExec service execution using the stolen credentials.
- **Limit:** Prefetch establishes execution on this host, not the destination host or the complete success of the remote operation.

### O-06 - The LSASS dump exposed Matthew Collins' NTLM field

- **Sources:** `text.txt.dmp`, Pypykatz output.
- **Observation:** The parsed `msv` record for `DECEPT\matthew.collins` contains an NTLM field. The raw value is intentionally omitted from the public report.
- **Interpretation:** The dump contained reusable credential material for the domain account, which explains how the attacker could attempt lateral movement.
- **Limit:** The dump reflects credentials resident in LSASS at acquisition time; it does not show whether the attacker successfully reused this specific value.

## Findings

### F-01 - RDP access originated from the compromised DeceptiPot host

- **Evidence:** O-01, Event ID 1149, `172.16.8.239`, `2025-06-30 16:33:16`.
- **Conclusion:** The attacker reached `SRV-IT-QA` through RDP from the DeceptiPot host while the `emily.ross` account was associated with the connection.
- **Confidence:** High for the network connection; medium for the authenticated user attribution.
- **Alternative / limit:** Confirm with Security `4624/LogonType 10` and session events if a formal incident report requires authentication proof.

### F-02 - A trojanized `Coreinfo64.exe` was used in the persistence/privesc path

- **Evidence:** O-02 and O-03.
- **Conclusion:** The executable identified as `Coreinfo64.exe`, with original filename `ab.exe`, is the replaced binary relevant to the room's persistence and privilege-escalation question.
- **Confidence:** Medium to high for the binary identity; medium for the exact overwritten target path.
- **Limit:** The current evidence summary does not preserve the complete MFT path of the target. The known copy is `C:\Users\emily.ross\Documents\Coreinfo64.exe`.

### F-03 - The operator dumped LSASS and retrieved the minidump

- **Evidence:** O-04, transcript timestamps and `text.txt.dmp`.
- **Conclusion:** The exact observed command line was `pcd.exe /accepteula -ma lsass.exe text.txt`, followed by retrieval of `text.txt.dmp`.
- **Confidence:** High for the command recorded in the transcript.
- **Limit:** The transcript does not independently identify `pcd.exe` or prove the dump's success without the file/Prefetch correlation.

### F-04 - Stolen credentials were used for lateral movement

- **Evidence:** O-05 and O-06.
- **Conclusion:** The lab's lateral-movement event occurred at `2025-06-30 19:47:14`; the associated credential artifact is Matthew Collins' NTLM field.
- **Confidence:** High for the Prefetch timestamp and extracted hash; medium for the remote destination and outcome.

## Impact and Remediation

Assume the affected Windows accounts and LSASS-resident credentials are compromised. Isolate the server, preserve volatile and disk evidence, rotate exposed credentials, remove the replaced binary and persistence mechanism after acquisition, block the attacker infrastructure and inspect the PsExec destination for the same account and service artifacts.

## Events in the Global Timeline

| ID | Timestamp (UTC) | Host | Event | Source | Finding |
| --- | --- | --- | --- | --- | --- |
| T-WIN-01 | 2025-06-30 16:33:16 | `SRV-IT-QA` | RDP network connection established from `172.16.8.239`, associated with `emily.ross`. | TerminalServices RemoteConnectionManager 1149 | F-01 |
| T-WIN-02 | 2025-06-30 16:55:20 | `SRV-IT-QA` | `Coreinfo64.exe` shows creation, overwrite and named-stream USN activity. | USN Journal / MFT | F-02 |
| T-WIN-03 | 2025-06-30 18:28:30 | `SRV-IT-QA` | Encoded PowerShell expression decodes to `pcd.exe /accepteula -ma lsass.exe text.txt`. | PowerShell transcript | F-03 |
| T-WIN-04 | 2025-06-30 18:28:52 | `SRV-IT-QA` | Encoded expression decodes to `download text.txt.dmp`. | PowerShell transcript | F-03 |
| T-WIN-05 | 2025-06-30 19:47:14 | `SRV-IT-QA` | `psexesvc` last run. | Prefetch | F-04 |

## Handoff to the Next Stage

| Type | Value / conclusion | Why it matters |
| --- | --- | --- |
| RDP source | `172.16.8.239` (`deceptipot-demo`) | Links the Windows activity to the Linux foothold. |
| External attacker IP | `167.172.41.141` | Preserves the infrastructure pivot from the Linux stage. |
| RDP event | `2025-06-30 16:33:16`, TerminalServices Event ID 1149 | Starting point for the Windows timeline. |
| Replaced binary | `Coreinfo64.exe`, original filename `ab.exe` | Pivot for static analysis and file-system correlation. |
| SHA-256 | `3ae834b3d24e56a5216ca69f8210c4ba92f4315197babeb6e34eacf06952c7de` | Stable sample identifier. |
| Credential-dump command | `pcd.exe /accepteula -ma lsass.exe text.txt` | Explains creation of the LSASS minidump. |
| Minidump | `text.txt.dmp` | Sensitive source for credential extraction. |
| Lateral movement | `psexesvc`, `2025-06-30 19:47:14` | Pivot to the next host/room. |
| Account material | `DECEPT\matthew.collins`, NTLM value omitted | Credential pivot for the next stage. |

## What I Learned

- Event 1149 is a connection pivot; Security 4624 and LocalSessionManager provide the stronger session correlation when retained.
- MFT and USN describe file identity and changes, while Prefetch and transcripts provide execution-oriented evidence.
- Credential-dump reporting can preserve the method and affected account without publishing reusable secret material.
