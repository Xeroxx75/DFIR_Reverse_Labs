# Windows Memory Forensics Lab – Summary Report

## 1. Context and objective

As part of my training in memory forensics, I worked on a practical lab based on a Windows 7 memory dump.  
The scenario: a user has hidden sensitive information on their workstation. The only artifact available is a **memory dump**, and the goal is to **recover the final secret**.

---

## 2. Environment and tools

* Analysis OS: Kali Linux  
* Main tool: **Volatility 3** (memory forensics)  
* Encryption tool used by the user: **TrueCrypt** (later mounted on my analysis machine)  
* Additional tools: `strings`, `grep`, file exploration (TrueCrypt container, ODT), basic encoding handling (base64), KeePass (for the password database).

---

## 3. Overall approach

I deliberately followed a workflow close to a **real-world forensic investigation**:

1. **Memory reconnaissance**  
   I started by identifying the appropriate Windows profile with Volatility, then built an initial process overview using `windows.pstree`. The goal was to quickly spot atypical elements in the context of concealment or compromise. At this stage, the presence of an active `TrueCrypt.exe` process stood out, which drove the rest of the analysis toward the hypothesis of an encrypted volume being manipulated by the user.

   ```bash
    3224  1956    TrueCrypt.exe   …    C:\Program Files\TrueCrypt\TrueCrypt.exe
   ```
    Additionally, in the same process tree, I noticed that notepad.exe was opened with a file named findme:
    ```bash
    3716   3684   notepad.exe   …   C:\Users\info\Desktop\findme
    ```

2. **TrueCrypt passphrase extraction**  
   Since Windows 7 can leave TrueCrypt keys in clear text inside memory, I ran the specific plugin:
    ```bash
    vol -f dump windows.truecrypt.Passphrase
    ```
    It returned a 32-character passphrase associated with TrueCrypt’s process memory. This indicated that a volume had been mounted recently and that the key was still present in RAM.

3. **Locating the encrypted container**  
   The next phase was to locate the corresponding container file. To do this, I relied on the observation made earlier in the process tree: **notepad.exe** was interacting with a file called findme. To verify whether this file existed in memory, I used:
    ```bash
    vol -f dump windows.filescan | grep -i findme
    ```
    This returned an entry showing the physical memory address at which the file was stored:
    ```bash
    0x1ee20110   \Users\info\Desktop\findme
    ```
    I then dumped this file from memory using:
    ```bash
    vol -f dump windows.dumpfiles --physaddr 0x1ee20110
    ```

4. **Mounting the container**  
   I installed TrueCrypt, then provided the previously recovered passphrase to mount the extracted .dat file. The volume mounted successfully and exposed three files:
    - `readme.txt`
    - `flag.png`
    - `readme.odt`

    The first two contained no useful clues, so the investigation continued inside the .odt document.

5. **Analysis of files inside the volume**  
   Knowing that an ODT file is a ZIP-based container, I opened `readme.odt` as an archive.
    Inside, I found an unusual internal structure: a hidden folder containing a file whose format matched a **KeePass database**, disguised within the ODT package.

    This discovery aligned with browser artefacts previously recovered from memory (Firefox searches related to KeePass and password cracking), reinforcing the hypothesis that a password vault was being used to hide the final secret.

    To access this vault, I extracted the Windows `SAM` and `SYSTEM` hives from memory and used `windows.hashdump` to recover NTLM hashes. After cracking the user’s password, I used it to unlock the KeePass database.

    The database contained thousands of entries, so I exported them to CSV and filtered them. One entry stood out due to its unusually long password ending with `=`, indicative of base64 encoding.
    A multi-stage decoding sequence eventually revealed the final string expected by the challenge.

---

## 4. Outcome

By the end of the investigation, I had reconstructed the full chain from the memory dump to the recovery of the final secret: identification of the TrueCrypt process, extraction of the passphrase from memory, discovery and mounting of the encrypted container, identification of a hidden password vault inside an ODT file, unlocking the KeePass database, and extraction/decoding of the final encoded string. This string, once decoded, provided the final secret.

---

## 5. Skills demonstrated

This practical case allowed me to apply and strengthen:

* Memory forensics with **Volatility 3** on Windows.  
* Understanding of artifacts related to **TrueCrypt** and its configuration/history files.  
* Extraction and handling of files from a memory dump (e.g. `filescan`, `dumpfiles`).  
* Mounting and analyzing an encrypted volume.  
* Advanced inspection of “container” file formats (ODT/ZIP, password vaults).  
* Hypothesis-driven reasoning, confirmation/invalidation of leads, handling of dead ends.  
* Simple automation (script to repeatedly decode a multi-encoded base64 string).
