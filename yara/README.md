# YARA Rules (Educational)

This folder contains YARA rules written during my reverse engineering and malware analysis practice.  
They are **educational** and derived from the labs in this repository.

> ⚠️ These rules are not meant for production use.  
> They are designed to illustrate pattern extraction, string selection and basic signature writing.

---

## Files

- `crackme_sallos_keylicense.yar`  
  Detects the **“Sallos's Key License”** crackme used in the `crackme key-license/` folder.  
  The rule leverages:
  - characteristic strings such as `"Invalid user login!"`, `"Invalid license key!"`, `"key.license"`,
  - and API names like `GetUserNameExA`, `CheckRemoteDebuggerPresent`, `DialogBoxParamA`.

- `gpgcrypt_encrypted_file.yar`  
  Detects **files encrypted** by the academic GPGcryptor ransomware:
  - magic string `GPGcrypt` at offset `0x00`,
  - tag `_SECRET_` at offset `0x08`,
  - minimum filesize to exclude false positives.

- `gpgcrypt_ransomware_binary.yar`  
  Detects the **GPGcryptor lab ransomware binary** analysed in `malware-lab-gpgcryptor/`:
  - strings such as `GPGcryptorV3.2!!!`, ransom note messages,
  - artefacts like `SecurityHealth.exe` and the IV marker `#GPC0DEMAGICVAL`.

---

## Example Usage

From the repository root:

```bash
# Scan recursively for encrypted files from the lab
yara -r yara/gpgcrypt_encrypted_file.yar /path/to/directory

# Scan a specific binary (e.g. the crackme)
yara -s yara/crackme_sallos_keylicense.yar "crackme key-license/keylicense.exe"
````

---

## Purpose

These rules demonstrate:

* how to derive signatures from reverse engineering work,
* how to combine meaningful strings in YARA conditions,
* and how to document rules with clear `meta` information.

