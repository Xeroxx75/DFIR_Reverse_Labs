# CRM Snatch - Disk

## Context and Scope

Determine how CRM data was prepared for exfiltration from `SRV-CRM-01` despite the deletion of Windows event logs. The investigation focuses on the account associated with the remote session, PowerShell activity, the C2 infrastructure, the transfer tool and the data present in the export directory.

## Initial Reconnaissance and Evidence

| Item | Detail |
| --- | --- |
| Host | `SRV-CRM-01` |
| Source | Disk image opened with FTK Imager |
| Tools | FTK Imager, EvtxECmd, Timeline Explorer, Registry Explorer and manual file review |
| Useful date | `2025-07-03` |
| Time convention | UTC in the examined artifacts |
| Primary sources | EVTX, `NTUSER.DAT`, `ConsoleHost_history.txt`, `C:\ProgramData\sync\mega.conf` and CRM exports |

## Evidence Constraints

- The EVTX covering the intrusion period had been deleted, so direct RDP correlation is unavailable in this image.
- UserAssist `Focus Time` measures application focus associated with a profile. It is not an exact process or network-session duration.
- The rclone configuration and local exports demonstrate preparation and capability. They do not prove that the remote upload completed.
- The public report omits the Mega credential recovered from the challenge artifact.

## Reusable Methods

- [Windows forensics](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/03-PRACTICE/windows-forensics.md) - formulate the question before selecting disk artifacts.
- [Windows artifacts](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/03-PRACTICE/forensics/windows-artifacts.md) - interpret UserAssist, PowerShell history and deleted EVTX.
- [Windows forensic tools](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/01-TOOLS/dfir/windows-forensic-tools.md) - use Zimmerman parsers and Timeline Explorer for targeted triage.
- [Event logs](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/02-CONCEPTS/windows/event-logs.md) - distinguish missing coverage from a negative finding.

## Method

1. Add the image to FTK Imager and export targeted artifacts to a working copy. Check the volume root because system files and logs may not appear under the expected tree node.
2. Copy available EVTX and run EvtxECmd. Treat the missing RDP channel as an evidence constraint, not as proof that no session occurred.
3. Load `NTUSER.DAT` in Registry Explorer. Use the available bookmarks to reach UserAssist, then record the decoded value, `Focus Time` and `Last Executed`.
4. Search PowerShell history and `C:\ProgramData\sync` to connect the account, IP and transfer tool.
5. Review `customers_exports.csv` and `Users_export.csv` in the CRM export directory and avoid copying unrelated customer data into the report.

```powershell
Get-ChildItem -Path 'C:\Windows\System32\Winevt\Logs\*' -Exclude '*SystemDataArchiver*' |
  Copy-Item -Destination 'C:\Users\Administrator\Desktop\Extracted\All\' -Force

EvtxECmd.exe -d 'C:\Users\Administrator\Desktop\Extracted\All' `
  --csv 'C:\Users\Administrator\Desktop\Parsed\All' --csvf Evtx_all.csv
```

The Timeline Explorer filter used `Event ID = 1149` and the 3 July 2025 window. With no usable result, the investigation pivoted to user hives, shell history and synchronization configuration.

## Analysis Log

| Action | Source | Useful result |
| --- | --- | --- |
| Add the image in FTK Imager | Disk image | Access to files and logs present in the capture |
| Copy EVTX and run `EvtxECmd` | `C:\Windows\System32\Winevt\Logs` | No usable RDP event for the period; logs had been deleted |
| Open `NTUSER.DAT` and the UserAssist bookmark | Matthew Collins profile | PowerShell, `Focus Time = 0d 0h 57m 35s`, last execution `2025-07-03 10:33:55` |
| Search `ConsoleHost_history.txt` and `mega.conf` | User profile and `C:\ProgramData\sync` | C2 `167.172.41.141`, rclone and Mega configuration |
| Review CRM exports | CRM export directory | User records and Lucas Rivera's address |

## Observations

### O-01 - Available logs cannot reconstruct the RDP session directly

- **Source:** Copied EVTX and EvtxECmd output.
- **Observation:** Filtering `Event ID = 1149` for 3 July produced no usable sequence because the intrusion-period logs had been deleted.
- **Interpretation:** The remote session must be correlated from the remaining profile and scenario artifacts.
- **Evidence constraint:** The deletion does not establish when the cleanup occurred.

### O-02 - UserAssist associates PowerShell with Matthew's profile

- **Source:** `NTUSER.DAT`, UserAssist bookmark and decoded entry `{System}\WindowsPowerShell\v1.0\powershell.exe`.
- **Observation:** `Focus Time` is `0d, 0h, 57m, 35s`, or **3,455 seconds**, with `Last Executed = 2025-07-03 10:33:55`.
- **Interpretation:** Matthew's profile retains substantial PowerShell activity during the relevant window. The account associated with the remote session is `matthew.collins`, consistent with the other artifacts.
- **Evidence constraint:** UserAssist is profile-specific and `Focus Time` is not an exact network-session duration.

### O-03 - The rclone configuration points to the staging infrastructure

- **Sources:** `C:\ProgramData\sync\mega.conf` and PowerShell history.
- **Observation:** The configuration defines a `[crmremote]` remote of type `mega` and an attacker-controlled account. The history and earlier stages associate staging with `167.172.41.141`.
- **Interpretation:** rclone was configured to transfer data to Mega, with `167.172.41.141` used as the staging and exfiltration address.
- **Evidence constraint:** A configuration exposes a destination and account identifier, but does not prove a completed upload. The raw credential is omitted from the public report.

### O-04 - The CRM exports contain Lucas Rivera's address

- **Source:** `Users_export.csv` and `customers_exports.csv` in the CRM export directory.
- **Observation:** The user export associates Lucas Rivera with `lucas.rivera@deceptitech.thm`, and the same address appears in the CRM data.
- **Interpretation:** The prepared data includes an organizational user record and provides the pivot to the macOS stage.
- **Evidence constraint:** The exports show data present in the image, not the exact list of files transferred or the success of exfiltration.

## Findings

### F-01 - The remote session is associated with `matthew.collins`

- **Evidence:** Matthew's profile, UserAssist and the scenario context in the absence of the relevant EVTX.
- **Conclusion:** `matthew.collins` is the domain account associated with the remote activity in this stage.
- **Confidence:** Medium because the direct authentication events were deleted.

### F-02 - PowerShell UserAssist focus time is 3,455 seconds

- **Evidence:** `Focus Time = 57m 35s`, last execution on 3 July.
- **Conclusion:** The recorded UserAssist value converts to `3455` seconds.
- **Confidence:** High for the conversion; medium for treating it as a session duration.

### F-03 - Staging uses `167.172.41.141` and rclone

- **Evidence:** PowerShell history and `C:\ProgramData\sync\mega.conf`.
- **Conclusion:** The C2/staging address is `167.172.41.141`, and rclone is configured for a Mega remote.
- **Confidence:** High for the IP and tool; remote transfer success requires destination-side evidence.

### F-04 - A Mega credential is present in the configuration

- **Evidence:** `[crmremote]` in `mega.conf`.
- **Conclusion:** The configuration contains a usable challenge credential. Its value is intentionally omitted from the public report.
- **Confidence:** High for the presence of the credential material.

### F-05 - The prepared data contains Lucas Rivera's address

- **Evidence:** CRM exports and user records.
- **Conclusion:** Lucas's address is `lucas.rivera@deceptitech.thm`.
- **Confidence:** High for the extracted data; the separately transferred archive is not available in this stage.

## Impact and Remediation

The host retained a transfer configuration and CRM data after event logs had been removed. A real response would isolate the host, revoke the exposed transfer credential, preserve the image and shell history, search for rclone execution and network telemetry, and notify the data owner according to the incident process.

## Events in the Global Timeline

| ID | Timestamp (UTC) | Host | Event | Source | Finding |
| --- | --- | --- | --- | --- | --- |
| T-DISK-01 | 2025-07-03 10:33:55 | `SRV-CRM-01` | UserAssist records the last PowerShell execution in Matthew's profile. | `NTUSER.DAT` / UserAssist | F-02 |
| T-DISK-02 | 2025-07-03 | `SRV-CRM-01` | PowerShell history and `mega.conf` show rclone configured toward a Mega remote. | PowerShell history / `mega.conf` | F-03/F-04 |

The presence of the CRM exports is a finding, not a timestamped execution event, and remains in the observation and correlation sections.

## Handoff to the Next Stage

| Pivot | Value | Next use |
| --- | --- | --- |
| Session account | `matthew.collins` | Correlate with Windows sessions and recovered credential material. |
| C2/staging | `167.172.41.141` | Keep the infrastructure pivot across Linux, memory and filesystem stages. |
| Transfer tool | `rclone` | Search for execution, logs and destination-side artifacts. |
| Remote | `[crmremote]`, type `mega` | Identify the exfiltration destination. |
| CRM pivot | `lucas.rivera@deceptitech.thm` | Connect the data theft to the macOS stage. |
| Previous memory pivot | `172.16.2.9:3389` | Preserve the remote-access context when correlating host activity. |

## What I Learned

- Missing EVTX should redirect the investigation toward user hives, shell history and application configuration, not end it.
- UserAssist is useful for application context, but its focus time must not be presented as an exact session duration.
- Exfiltration claims are strongest when local staging, transfer configuration and destination-side evidence agree.
