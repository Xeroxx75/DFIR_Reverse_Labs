# Initial Access Pot - Linux

## Context and Scope

Determine how the Internet-facing `deceptipot-demo` Linux server was compromised and reconstruct the attack from initial access through privilege escalation, internal reconnaissance and persistence.

The room required identifying:

- the brute-forced WordPress page;
- the backdoored PHP file;
- the file used to obtain root access;
- the internally scanned IP address;
- the hash of the persistent malware;
- the recovery-mode result.

## Initial Reconnaissance and Evidence

| Item            | Detail                                                                                                                       |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Host            | `deceptipot-demo`                                                                                                            |
| Platform        | Linux                                                                                                                        |
| Exposed service | WordPress over HTTP/80                                                                                                       |
| Access method   | Live SSH triage as `ubuntu`, with `sudo` access                                                                              |
| Primary sources | Apache access logs, auditd, filesystem metadata, PHP source, SSH files, root shell history, systemd files and service status |
| Time convention | UTC for incident events                                                                                                      |

## Evidence Constraints

- The system was investigated live rather than from an acquired image.
- `.bash_history` preserves command order but no usable timestamps were present.
- File modification times may support a timeline but do not identify the responsible process or user by themselves.
- The deleted second-stage archive was not recovered, so its functionality could not be established directly.

## Reusable Methods

This case uses the following reusable procedures from the vault:

- [Linux internals and auditd triage](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/02-CONCEPTS/linux/linux-internals.md) - reduce logs to a time window and correlate audit records by serial;
- [Linux persistence](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/02-CONCEPTS/binaries/persistence-techniques.md) - distinguish an enabled systemd unit, its current state and restart behavior;
- [ELF triage](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/02-CONCEPTS/binaries/elf-format.md) - hash, identify and inspect a Linux payload before execution;
- [Case template](https://github.com/Xeroxx75/dfir-reverse-notes/blob/main/03-PRACTICE/forensics/case-template.md) - separate observations, interpretation, confidence and limitations.

## Method

1. Establish the attack window from Apache access logs.
2. Correlate authenticated WordPress activity with modified PHP files.
3. Use auditd serials to reconstruct commands executed from the web-service context.
4. Review root history for post-compromise sequencing, then validate persistence through systemd configuration, enablement and payload hashing.

## Analysis Log

| Analyst time | Command / action                                                                                                                                                  | Useful result                                                                                                                                  |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| 03/08 22:47  | `cat ~/.ssh/authorized_keys`                                                                                                                                      | Two SSH public keys were present in the `ubuntu` profile, including one with the comment `maksym.varnakov`.                                    |
| 03/08 22:52  | `sudo cat /root/deceptipot/README.md`                                                                                                                             | The deployment instructions explicitly required deletion of the plaintext configuration after initialization.                                  |
| 03/08 22:52  | `sudo cat /root/deceptipot/deceptipot.conf`                                                                                                                       | The undeleted configuration exposed credentials, an SSH-key path, a root password, a recovery key, disabled monitoring options and debug mode. |
| 03/08 23:35  | `sudo ausearch -m EXECVE -i` and targeted audit review                                                                                                            | Reconstructed commands issued through the compromised application, including key copy, permission change and SSH execution.                    |
| 03/08 23:38  | Review of `/var/log/apache2/access.log`                                                                                                                           | Identified the WordPress brute force, successful login pattern and access to the theme editor.                                                 |
| 03/08 23:58  | `sudo find /var/www -type f -name '*.php' -newermt '2025-06-27 21:20:00 UTC' ! -newermt '2025-06-27 22:10:00 UTC' -printf '%TY-%Tm-%Td %TH:%TM:%TS %p\n' \| sort` | Identified the Blocksy `404.php` file as modified during the attack window.                                                                    |
| 04/08 00:02  | `sudo sed -n '1,240p' /var/www/html/wordpress/wp-content/themes/blocksy/404.php`                                                                                  | Confirmed a hidden PHP command-execution webshell.                                                                                             |
| 04/08 00:33  | Correlation of audit events for `cp`, `chmod`, `ssh`, `LOGIN` and `USER_LOGIN`                                                                                    | Identified `/etc/ssh/id_ed25519.bak` as the key source and confirmed successful root login through localhost.                                  |
| 04/08 01:10  | `sudo cat /root/.bash_history`                                                                                                                                    | Identified internal scanning, payload download, execution and deletion after root compromise.                                                  |
| 04/08 02:15  | `sudo find /etc/systemd/system /usr/lib/systemd/system -name '*.service' -newermt '2025-06-27' ! -newermt '2025-06-28' -ls`                                       | Identified `kworker.service` as created during the compromise date.                                                                            |
| 04/08 02:17  | `sudo systemctl status kworker.service`                                                                                                                           | Confirmed the service was enabled and running at examination time, with repeated outbound connection attempts.                                 |
| 04/08 02:20  | `sudo systemctl cat kworker.service`                                                                                                                              | Confirmed execution of `/usr/sbin/kworker` and automatic restart behavior.                                                                     |
| 04/08 02:22  | `sudo md5sum /usr/sbin/kworker`                                                                                                                                   | Obtained the challenge-required malware hash.                                                                                                  |

## Observations

### O-01 - Unsafe DeceptiPot deployment left sensitive material on disk

- **Sources:** `/root/deceptipot/README.md`, `/root/deceptipot/deceptipot.conf`
- **Observation:** The product instructions required the plaintext configuration to be deleted after initialization, but it remained on disk. It contained service credentials, a root password, an SSH-key path, a recovery key, disabled monitoring options and `debugmode = true`.
- **Interpretation:** The deployed honeypot was materially misconfigured and exposed information that could facilitate further compromise.
- **Limitation:** The configuration proves exposure, not that the attacker read or reused each value.

### O-02 - SSH public key comment provides a contextual lead

- **Source:** `/home/ubuntu/.ssh/authorized_keys`
- **Observation:** One public key contained the comment `maksym.varnakov`; another was labelled `eu-west-3-vuln-vms`.
- **Interpretation:** These labels may identify an operator or deployment context relevant to later investigation.
- **Limitation:** SSH key comments are user-controlled metadata. They do not establish ownership, attribution or successful use.

### O-03 - Automated brute force targeted `/wp-login.php`

- **Source:** `/var/log/apache2/access.log`
- **Observation:** The log contains a high volume of `GET` and `POST` requests to `/wp-login.php` from `167.172.41.141`, using the user agent `Mozilla/5.0 (Hydra)`, beginning at `2025-06-27 21:20:27 UTC`.
- **Interpretation:** The pattern is consistent with automated WordPress password brute forcing.
- **Limitation:** The access log does not reveal the credentials attempted.

### O-04 - The attacker obtained WordPress administrative access

- **Source:** `/var/log/apache2/access.log`
- **Observation:** At `2025-06-27 21:21:27 UTC`, a `POST /wp-login.php` request returned HTTP `302`, immediately followed by `GET /wp-admin/` returning HTTP `200` from the same IP.
- **Interpretation:** The redirect and subsequent access to the administration area strongly indicate successful authentication.
- **Limitation:** The successful username and password are not present in the access log.

### O-05 - The attacker selected and modified the Blocksy `404.php` template

- **Sources:** Apache access log; filesystem metadata for `/var/www/html/wordpress/wp-content/themes/blocksy/404.php`
- **Observation:** The same source IP accessed the WordPress theme editor and selected `theme=blocksy&file=404.php`. The file modification time falls immediately after this activity.
- **Interpretation:** The temporal and behavioral correlation indicates that the file was modified through the authenticated theme editor session.
- **Limitation:** The HTTP access log does not retain the submitted POST body, and the modification timestamp alone cannot identify the writer.

### O-06 - `404.php` contains a command-execution webshell

- **Source:** `/var/www/html/wordpress/wp-content/themes/blocksy/404.php`
- **Observation:** Added PHP code checks whether `doing_wp_corn=t`, presents a form using the POST parameter `cmd`, and passes the submitted value to `system()`.
- **Interpretation:** The backdoor provides remote operating-system command execution to any requester who knows the activation parameter.
- **Limitation:** File content alone does not identify which commands were executed or when.

### O-07 - The web-service context copied and used a root SSH private key

- **Source:** `/var/log/audit/audit.log`
- **Observation:** auditd recorded:
  - `cp /etc/ssh/id_ed25519.bak /tmp/key` at `2025-06-27 22:07:53 UTC`;
  - `chmod 400 /tmp/key` at `22:08:00 UTC`;
  - `ssh -o StrictHostKeyChecking=no -i /tmp/key root@localhost` at `22:08:07 UTC`.
  The recorded working directory was `/var/www/html/wordpress`.
- **Interpretation:** Commands issued from the compromised web application staged and used an exposed root private key for local privilege escalation.
- **Limitation:** The evidence does not establish why the backup key existed or how its path became known to the attacker.

### O-08 - Root authentication succeeded

- **Source:** `/var/log/audit/audit.log`
- **Observation:** Immediately after the SSH command, auditd recorded `LOGIN` and `USER_LOGIN` events for account `root`, source address `127.0.0.1`, with a successful result at approximately `2025-06-27 22:08:08 UTC`.
- **Interpretation:** The copied private key was accepted and the attacker obtained a root SSH session on the host.
- **Limitation:** The logs confirm the session, but not the real-world identity of the person controlling it.

### O-09 - Root-level activity targeted an internal host and executed a second stage

- **Source:** `/root/.bash_history`
- **Observation:** The command sequence:
  - scanned `172.16.8.200-254` with ICMP;
  - probed `172.16.8.216` on ports 22, 80 and 3389;
  - downloaded `5841.tar.gz` from `167.172.41.141` using `scp`;
  - extracted it and executed `bash run.sh`;
  - deleted the extracted directory and archive.
- **Interpretation:** After root compromise, the actor performed internal reconnaissance and executed a staged payload, likely supporting lateral movement or expansion of the intrusion.
- **Limitation:** The shell history has no reliable timestamps, does not prove each command completed successfully and does not reveal the deleted payload's contents.

### O-10 - A persistent systemd service launches `/usr/sbin/kworker`

- **Sources:** `/etc/systemd/system/kworker.service`, service enablement state, `systemctl status kworker.service`
- **Observation:** `kworker.service` was created on the compromise date, was enabled and running at examination time, executed `/usr/sbin/kworker`, used `Restart=always`, and repeatedly attempted to connect to `167.172.41.141:10443`.
- **Interpretation:** The service is a persistence mechanism for a malicious outbound client communicating with attacker-controlled infrastructure.
- **Limitation:** `Restart=always` controls relaunch after termination; it is not itself the mechanism that enables startup at boot. The exact binary capabilities require separate analysis, and current service status is not historical proof of every prior execution.

### O-11 - Persistent payload hash

- **Source:** `/usr/sbin/kworker`
- **Observation:** The challenge-required MD5 was `d6f2d80e78f264aff8c7aea21acb6ca6`.
- **Interpretation:** The hash is a stable pivot for cross-stage correlation and threat-intelligence searches.

## Findings

### F-01 - The attacker brute-forced WordPress and obtained administrative access

- **Evidence:** O-03, O-04
- **Confidence:** High
- **Limitations:** The successful credentials and human operator remain unknown.

### F-02 - The attacker implanted a PHP command-execution webshell through the WordPress theme editor

- **Evidence:** O-05, O-06
- **Confidence:** High
- **Limitations:** The theme-update POST body was not recovered; the conclusion relies on strong temporal and content correlation.

### F-03 - The attacker escalated from the web-service context to root using an exposed SSH private key

- **Evidence:** O-07, O-08
- **Confidence:** High
- **Limitations:** The origin and intended administrative purpose of the backup key remain unresolved.

### F-04 - The attacker performed internal reconnaissance and executed a second-stage payload

- **Evidence:** O-09
- **Confidence:** High for command sequence; medium for successful outcomes and timing
- **Limitations:** The payload was deleted, shell history lacked timestamps and no output from the scan or installer was recovered in this room.

### F-05 - The attacker established persistent C2 access using a malicious systemd service

- **Evidence:** O-10, O-11
- **Confidence:** High
- **Limitations:** The binary was not reverse engineered, and the exact installation command was not identified.

### F-06 - DeceptiPot was deployed with security-critical misconfigurations

- **Evidence:** O-01
- **Confidence:** High
- **Limitations:** It remains unproven which exposed values were used during the intrusion.

## Impact and Remediation

The compromise exposed WordPress administration, root access and an internal network path. Preserve logs and payloads, remove the webshell and malicious unit after acquisition, rotate WordPress and host credentials, remove the exposed SSH key, rebuild the host from trusted media and review internal systems contacted from this server.

## Events in the Global Timeline

| ID | Timestamp (UTC) | Event | Source | Finding |
| --- | --- | --- | --- | --- |
| T-LNX-01 | 2025-06-27 21:20:27 | Automated brute-force activity begins against `/wp-login.php`. | Apache access log | F-01 |
| T-LNX-02 | 2025-06-27 21:21:27 | WordPress authentication succeeds and `/wp-admin/` is accessed. | Apache access log | F-01 |
| T-LNX-03 | 2025-06-27 21:21:50 | The attacker opens the theme editor. | Apache access log | F-02 |
| T-LNX-04 | 2025-06-27 21:22:46 | The attacker selects the Blocksy `404.php` template. | Apache access log | F-02 |
| T-LNX-05 | 2025-06-27 21:23 | `404.php` is modified and contains a command-execution webshell. | File metadata and content | F-02 |
| T-LNX-06 | 2025-06-27 22:07:53 | `/etc/ssh/id_ed25519.bak` is copied to `/tmp/key`. | auditd | F-03 |
| T-LNX-07 | 2025-06-27 22:08:00 | `/tmp/key` permissions are changed to `400`. | auditd | F-03 |
| T-LNX-08 | 2025-06-27 22:08:07 to 22:08:08 | The key is used to authenticate successfully as root on localhost. | auditd | F-03 |

## Handoff to the Next Stage

| Type                         | Value / conclusion                                          |
| ---------------------------- | ----------------------------------------------------------- |
| Attacker / infrastructure IP | `167.172.41.141`                                            |
| Initial access               | WordPress password brute force using Hydra                  |
| Successful login             | `2025-06-27 21:21:27 UTC`                                   |
| Backdoored file              | `/var/www/html/wordpress/wp-content/themes/blocksy/404.php` |
| Webshell activation          | `doing_wp_corn=t`                                           |
| Command parameter            | `cmd`                                                       |
| Root escalation source       | `/etc/ssh/id_ed25519.bak`                                   |
| Root login                   | Confirmed at approximately `2025-06-27 22:08:08 UTC`        |
| Internal target              | `172.16.8.216`                                              |
| Second-stage archive         | `5841.tar.gz`                                               |
| Persistence                  | `/etc/systemd/system/kworker.service` → `/usr/sbin/kworker` |
| C2 endpoint                  | `167.172.41.141:10443`                                      |
| Malware MD5                  | `d6f2d80e78f264aff8c7aea21acb6ca6`                          |

## What I Learned

- Apache access logs, PHP modification times and file content together provide a stronger webshell conclusion than any one source alone.
- auditd serial correlation can reconstruct a privilege-escalation command chain even when shell history has no timestamps.
- systemd persistence should be described through the unit, enablement link, executed binary and runtime behavior as separate observations.
