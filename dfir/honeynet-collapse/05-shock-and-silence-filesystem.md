# Shock and Silence - Filesystem

## Context and Scope

Analyze the remaining NTFS traces on `DC-01` after the encryption event. The objectives are to identify the download, recover the ransomware's original filename, identify the process associated with the encryption sequence, characterize the appended extension and assess the threat-group pivot.

## Initial Reconnaissance and Evidence

| Item | Detail |
| --- | --- |
| Host | `DC-01` |
| Source | Partial image `Artifacts\\DC-01-NTFS-Logs.ad1` |
| Tools | FTK Imager and MFTECmd |
| Sources | `$UsnJrnl:$J`, `$MFT`, `$LogFile`, `$Boot`, `$Bitmap` and `Zone.Identifier` ADS |
| Useful period | `2025-07-04`, approximately `10:00-12:05 UTC` |
| File system | NTFS; only the listed artifacts were available |

## Evidence Constraints

- The image is partial and does not necessarily contain the payload, EVTX or complete encrypted-file content.
- USN reasons demonstrate file-system changes, not process intent. `HpAgent.exe` is associated with the sequence through temporal correlation rather than a process-creation event.
- MFT and USN timestamps support ordering here, but they should be interpreted with the surrounding metadata and not as an isolated attribution source.
- BlackLock is an OSINT pivot from the ransom note, not an independent binary-family identification.

## Reusable Methods

- [Windows forensics](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/03-PRACTICE/windows-forensics.md) - select file-system artifacts from the investigation question.
- [Windows artifacts](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/03-PRACTICE/forensics/windows-artifacts.md) - interpret MFT, USN, ADS and deleted-file traces.
- [Windows forensic tools](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/01-TOOLS/dfir/windows-forensic-tools.md) - parse `$MFT` and `$UsnJrnl:$J` with MFTECmd.
- [Disk forensics](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/02-CONCEPTS/dfir/disk-forensics-cheatsheet.md) - preserve image identity, hashes and acquisition context.

## Method

1. Open the AD1 in FTK Imager and verify the file list under the volume root. System files may be visible in the content pane without appearing under the expected tree node.
2. Export the NTFS logs to a working copy and produce MFTECmd CSV output for `$UsnJrnl:$J` and `$MFT`.
3. Filter the USN timeline for rename reasons, `README` occurrences and the 4 July window.
4. Search temporary downloads such as `*.crdownload` and names containing `hidden`.
5. Read the `Zone.Identifier` ADS to recover `HostUrl` and `ReferrerUrl`, then correlate the download with the rename wave and executable names.

```powershell
MFTECmd.exe -f 'C:\Users\DFIR Analyst\Desktop\Extracted\USN\$J' `
  --csv 'C:\Users\DFIR Analyst\Desktop\Parsed\USN'

MFTECmd.exe -f 'C:\Users\DFIR Analyst\Desktop\Extracted\MFT\$MFT' `
  --csv 'C:\Users\DFIR Analyst\Desktop\Parsed\MFT'
```

## Analysis Log

| Action | Source | Useful result |
| --- | --- | --- |
| Filter `RenameOldName` and `RenameNewName` | USN Journal | Mass rename sequence on 4 July, compatible with encryption activity |
| Search `README` | USN Journal | `README.EeUfy.txt` around `11:52:41` and `readme_lgpl.txt` around `12:02:22` |
| Search temporary downloads | USN Journal | `HiddenArchive (1).zip.crdownload` around `11:32` and `HiddenFile.zip.crdownload` around `11:35` |
| Search `hidden` and the ADS | MFT | `pb.exe` under `Downloads\\HiddenFile` and `tzfcpxvv.EeUfy:Zone.Identifier` |
| Read the ADS | `Zone.Identifier` | Full Gofile URL and download provenance |
| Correlate events before the README files | USN and MFT | `HpAgent.exe` precedes the notes and the rename wave |

## Observations

### O-01 - Mass renames bound the encryption phase

- **Source:** `$UsnJrnl:$J`, MFTECmd output.
- **Observation:** A large `RenameOldName` and `RenameNewName` sequence is concentrated on 4 July. `README.EeUfy.txt` at `11:52:41` and `readme_lgpl.txt` at `12:02:22` bound the preceding activity.
- **Interpretation:** The rename wave is consistent with an encryption or post-processing stage.
- **Evidence constraint:** A rename does not prove that file content was encrypted. It must be correlated with the extension, process and ransom note.

### O-02 - The download provenance points to Gofile

- **Sources:** `$MFT` and `tzfcpxvv.EeUfy:Zone.Identifier`.
- **Observation:** The ADS contains:

  ```text
  [ZoneTransfer]
  ZoneId=3
  ReferrerUrl=https://gofile.io/
  HostUrl=https://store5.gofile.io/download/web/e23cb33f-0e4d-4a5f-8c55-ea2d78057d40/HiddenFile.zip
  ```

- **Interpretation:** The file was downloaded from the recorded Gofile URL, and `HiddenFile` is a pivot to the archive and payload.
- **Evidence constraint:** `Zone.Identifier` records Windows provenance and can be removed, copied or modified. It does not identify the person who triggered the download.

### O-03 - The downloaded file contains an executable named `pb.exe`

- **Source:** `$MFT`, search for `hidden`.
- **Observation:** The MFT contains `pb.exe` under `Downloads\\HiddenFile` and the associated `Zone.Identifier` stream.
- **Interpretation:** `pb.exe` is the ransomware filename recovered from the extracted directory.
- **Evidence constraint:** The MFT does not provide the binary content or signature. Its role is established through the surrounding file and rename sequence.

### O-04 - `HpAgent.exe` precedes the rename wave

- **Source:** USN timeline filtered before the README files.
- **Observation:** `HpAgent.exe` appears before the ransom notes and the rename sequence that adds `.EeUfy`.
- **Interpretation:** `HpAgent.exe` is the executable associated with the encryption sequence in this scenario.
- **Evidence constraint:** USN establishes proximity and file changes, not a process call. Process creation telemetry would provide stronger attribution.

### O-05 - The ransom note supports a BlackLock OSINT pivot

- **Sources:** Ransom note supplied by the room and public search.
- **Observation:** The note contains the distinctive wording `Ehe decryptor will be destroyed`. Searching that phrase and the associated hash leads to a public page connected to **BlackLock**.
- **Interpretation:** BlackLock is the group identified by the room's OSINT pivot.
- **Evidence constraint:** A ransom note can be copied or imitated. This is an OSINT attribution lead, not a cryptographic identification of the binary.

## Findings

### F-01 - The ransomware was downloaded from Gofile

- **Evidence:** O-02.
- **Conclusion:** The ADS preserves the URL `https://store5.gofile.io/download/web/e23cb33f-0e4d-4a5f-8c55-ea2d78057d40/HiddenFile.zip`.
- **Confidence:** High for the URL recorded in the ADS.

### F-02 - The recovered ransomware filename is `pb.exe`

- **Evidence:** O-03.
- **Conclusion:** The executable was located under `Downloads\\HiddenFile\\pb.exe`.
- **Confidence:** High for the filename and MFT path; the binary content was not recovered in this stage.

### F-03 - `HpAgent.exe` is associated with the encryption sequence

- **Evidence:** O-01 and O-04.
- **Conclusion:** `HpAgent.exe` appears before the ransom notes and the USN rename wave.
- **Confidence:** Medium to high because the available evidence is temporal and file-system based.

### F-04 - The appended extension is `.EeUfy`

- **Evidence:** USN rename records and `README.EeUfy.txt`.
- **Conclusion:** The renamed files received the `.EeUfy` extension.
- **Confidence:** High for the observed extension.

### F-05 - The OSINT pivot identifies BlackLock

- **Evidence:** O-05.
- **Conclusion:** The ransom-note pivot leads to BlackLock.
- **Confidence:** Medium because the attribution relies on the note and public source rather than a verified binary signature.

## Impact and Remediation

The filesystem shows a downloaded payload, a rename wave and ransom-note artifacts on a domain controller. A real response would isolate the host, preserve the image and unallocated space, recover process and event telemetry from other sources, protect backups, and validate restoration before reconnecting the system.

## Events in the Global Timeline

| ID | Timestamp (UTC) | Host | Event | Source | Finding |
| --- | --- | --- | --- | --- | --- |
| T-FS-01 | 2025-07-04 11:32-11:35 | `DC-01` | `*.zip.crdownload` entries associated with `HiddenArchive` and `HiddenFile` appear. | USN Journal | F-01 |
| T-FS-02 | 2025-07-04 11:52:41 | `DC-01` | `README.EeUfy.txt` appears during the rename and encryption sequence. | USN Journal | F-04 |
| T-FS-03 | 2025-07-04 12:02:22 | `DC-01` | `readme_lgpl.txt` appears after the main rename wave. | USN Journal | F-04 |

The relative position of `HpAgent.exe` remains in the observations because the available evidence does not provide a precise event timestamp.

## Handoff to the Next Stage

| Pivot | Value | Next use |
| --- | --- | --- |
| Download | Gofile URL for `HiddenFile.zip` | Correlate browser and network provenance. |
| Payload | `Downloads\\HiddenFile\\pb.exe` | Search for the binary or related traces. |
| Trigger | `HpAgent.exe` | Search Prefetch, process creation telemetry and memory. |
| Extension | `.EeUfy` | Search renamed files and ransom notes. |
| OSINT attribution | BlackLock | Compare the note and infrastructure with external reporting. |
| Shared infrastructure | `167.172.41.141` | Preserve the attacker pivot from the earlier stages. |
| Target user | `lucas.rivera@deceptitech.thm` | Carry the CRM-to-macOS correlation into the final stage. |

## What I Learned

- USN and MFT are strongest when used to establish a sequence and then correlated with content, provenance and process evidence.
- A downloaded archive, its ADS and the rename wave can identify a delivery path even when the executable is missing.
- Threat-group attribution from a ransom note should remain explicitly separate from binary identification.
