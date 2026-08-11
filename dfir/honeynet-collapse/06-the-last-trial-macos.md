# The Last Trial - macOS

## Context and Scope

Reconstruct the delivery, installation, data collection, command-and-control endpoint and persistence of the `DevelopAI` application on Lucas Rivera's Mac.

## Initial Reconnaissance and Evidence

| Item | Detail |
| --- | --- |
| Evidence | `Lucas_Disk.img` |
| Platform | macOS 15.4 recorded in `InstallHistory.plist` |
| Filesystem | APFS exposed with `apfs-fuse` |
| Main sources | Safari `Downloads.plist`, `InstallHistory.plist`, TCC.db, `DevelopAI.app`, LaunchAgents |
| Time convention | UTC |

## Evidence Constraints

- The notes do not document the source-image hashes, FileVault state or complete Unified Logs.
- Safari records the download, Installer records package installation and TCC records permission decisions. These sources do not independently prove file access or successful exfiltration.
- A LaunchAgent on disk proves configured persistence; its execution requires launchd or Unified Log correlation.

## Reusable Methods

- [macOS forensics](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/03-PRACTICE/macos-forensics.md) - APFS, plist, TCC and persistence sources.
- [Disk forensics](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/03-PRACTICE/forensics/disk-forensics-cheatsheet.md) - image handling and read-only examination.

## Method

1. Mount the APFS image at a dedicated evidence path.
2. Parse Safari downloads and Installer history to separate delivery from installation.
3. Query a copy of TCC.db and order permission decisions by `last_modified`.
4. Inspect the application bundle and its resource scripts for collection, staging and network behavior.
5. Inspect the user's LaunchAgents and correlate their program arguments with the bundle.

```bash
sudo apfs-fuse -v 4 Lucas_Disk.img /evidence/mac_mount

plistutil -p '/evidence/mac_mount/root/Users/lucasrivera/Library/Safari/Downloads.plist'
plistutil -p '/evidence/mac_mount/root/Library/Receipts/InstallHistory.plist'

find '/evidence/mac_mount/root/Applications/DevelopAI.app/Contents/Resources' \
  -maxdepth 1 -type f -print
grep -Eo 'https?://[^"[:space:]]+' \
  '/evidence/mac_mount/root/Applications/DevelopAI.app/Contents/Resources/script'
```

```sql
SELECT service, client, auth_value,
       datetime(last_modified, 'unixepoch') AS modified
FROM access
WHERE client = 'org.aiArt.DevelopAI'
ORDER BY last_modified ASC;
```

## Analysis Log

| Action | Source | Useful result |
| --- | --- | --- |
| Mount the APFS image | `Lucas_Disk.img` | User and system volumes accessible |
| Parse Safari downloads | `Downloads.plist` | Source URL, destination and download times |
| Parse Installer history | `InstallHistory.plist` | Package identity and installation time |
| Sort TCC entries | TCC.db | Desktop, Downloads and Documents permission order |
| Inspect the application resources | `DevelopAI.app` | Targeted collection, ZIP staging and HTTP POST |
| Inspect user persistence | `~/Library/LaunchAgents` | DevelopAI plist and script |

## Observations

### O-01 - Safari records the installer download

- **Source:** `/Users/lucasrivera/Library/Safari/Downloads.plist`.
- **Observation:** Safari records `DevelopAIInstaller.pkg` from `http://developai.thm/DevelopAIInstaller.pkg`, starting at `2025-07-04 10:08:23 UTC` and ending at `10:08:25 UTC`.
- **Interpretation:** The package was delivered through Safari from `developai.thm`.
- **Limit:** The record establishes the browser download, not the user's intent.

### O-02 - Installer records the package at 10:09:03

- **Source:** `/Library/Receipts/InstallHistory.plist`.
- **Observation:** `DevelopAIInstaller`, package identifier `com.developai.app`, was registered by Installer at `2025-07-04 10:09:03 UTC`.
- **Interpretation:** Installation followed the Safari download.

### O-03 - Desktop was the first recorded TCC permission

- **Source:** TCC.db, client `org.aiArt.DevelopAI`.
- **Observation:** The permission decisions appear in this order:

  | Service | Time (UTC) |
  | --- | --- |
  | `kTCCServiceSystemPolicyDesktopFolder` | `2025-07-04 10:10:33` |
  | `kTCCServiceSystemPolicyDownloadsFolder` | `2025-07-04 10:10:41` |
  | `kTCCServiceSystemPolicyDocumentsFolder` | `2025-07-04 10:10:46` |

- **Interpretation:** Desktop was the first protected folder authorized for the application.
- **Limit:** A TCC decision does not identify the files actually read.

### O-04 - The application collects and uploads selected files

- **Source:** `DevelopAI.app/Contents/Resources/script`.
- **Observation:** The script creates `~/.developai_temp`, selects recent `.pdf`, `.docx`, `.aws`, `.env`, `.key` and `.pem` files larger than 9 KiB from Desktop, Downloads and Documents, creates `project.zip`, sends it with an HTTP POST, then removes the staging directory.
- **Interpretation:** DevelopAI implements targeted collection, temporary archiving and exfiltration.
- **Limit:** Static script content does not establish which files or how many bytes reached the server.

### O-05 - Persistence is configured as a user LaunchAgent

- **Source:** `/Users/lucasrivera/Library/LaunchAgents`.
- **Observation:** `com.developai.agent.plist` and `DevelopAI.sh` are present in the user's LaunchAgents directory.
- **Interpretation:** Persistence is configured in Lucas Rivera's user context.
- **Limit:** The plist and Unified Logs are needed to demonstrate launchd execution.

## Findings

### F-01 - DevelopAI was downloaded and installed

- **Evidence:** O-01 and O-02.
- **Conclusion:** `DevelopAIInstaller.pkg` came from `developai.thm` and Installer registered it at `2025-07-04 10:09:03 UTC`.
- **Confidence:** High.

### F-02 - The application received protected-folder access

- **Evidence:** O-03.
- **Conclusion:** Desktop was authorized first, followed by Downloads and Documents.
- **Confidence:** High for the recorded TCC order.

### F-03 - DevelopAI implements collection and HTTP exfiltration

- **Evidence:** O-04.
- **Conclusion:** The script stages selected files in a ZIP and posts it to `http://c7.macos-updatesupport.info:8080`.
- **Confidence:** High for implemented behavior; transfer success is not established.

### F-04 - DevelopAI configures user-level persistence

- **Evidence:** O-05.
- **Conclusion:** The persistence mechanism is `~/Library/LaunchAgents/com.developai.agent.plist` with `DevelopAI.sh`.
- **Confidence:** High for configuration presence.

## Impact and Remediation

Treat the user's protected folders and any credentials stored in matching file types as exposed. Isolate the host, preserve the APFS image and Unified Logs, remove the package and LaunchAgent after acquisition, block both DevelopAI domains, rotate affected credentials and review other endpoints for the same bundle identifier, plist label and C2.

## Events in the Global Timeline

| ID | Timestamp (UTC) | Host | Event | Source | Finding |
| --- | --- | --- | --- | --- | --- |
| T-MAC-01 | 2025-07-04 10:08:23 to 10:08:25 | Lucas Rivera's Mac | Safari downloads `DevelopAIInstaller.pkg` from `developai.thm`. | Safari `Downloads.plist` | F-01 |
| T-MAC-02 | 2025-07-04 10:09:03 | Lucas Rivera's Mac | Installer registers `DevelopAIInstaller`. | `InstallHistory.plist` | F-01 |
| T-MAC-03 | 2025-07-04 10:10:33 | Lucas Rivera's Mac | DevelopAI receives Desktop access. | TCC.db | F-02 |
| T-MAC-04 | 2025-07-04 10:10:41 | Lucas Rivera's Mac | DevelopAI receives Downloads access. | TCC.db | F-02 |
| T-MAC-05 | 2025-07-04 10:10:46 | Lucas Rivera's Mac | DevelopAI receives Documents access. | TCC.db | F-02 |

## Final Correlation

| Pivot | Value | Relevance |
| --- | --- | --- |
| Target | Lucas Rivera, `lucas.rivera@deceptitech.thm` | Connects the macOS victim with the CRM export |
| Delivery | `developai.thm/DevelopAIInstaller.pkg` | Browser and infrastructure pivot |
| Bundle ID | `org.aiArt.DevelopAI` | TCC and endpoint search pivot |
| C2 | `http://c7.macos-updatesupport.info:8080` | Network and threat-intelligence pivot |
| Persistence | `~/Library/LaunchAgents/com.developai.agent.plist` | Endpoint and launchd pivot |

## What I Learned

- Separate Safari download, Installer receipt and TCC permission times instead of treating them as one execution event.
- Query TCC.db chronologically to reconstruct protected-folder access decisions.
- Inspect a macOS application as a bundle: resources and persistence scripts may expose behavior more directly than the main executable.
