rule GPGcryptor_Encrypted_File
{
    meta:
        description = "Detects files encrypted by the academic GPGcryptor ransomware lab"
        author = "Ibrahim Diallo"
        context = "Academic malware analysis lab"
        reference = "dfir-reverse-labs/malware-lab-gpgcryptor"

    strings:
        $magic = "GPGcrypt" ascii
        $tag   = "_SECRET_" ascii

    condition:
        filesize > 0x48 and
        $magic at 0 and
        $tag   at 0x08
}
