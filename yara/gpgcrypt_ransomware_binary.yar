rule GPGcryptor_Ransomware_Lab
{
    meta:
        description = "Detects the lab ransomware SecurityHealth.exe (GPGcryptorV3.2)"
        author = "Ibrahim Diallo"
        context = "Academic malware analysis lab"
        reference = "dfir-reverse-labs/dfir-malware-lab"

    strings:
        $s1 = "GPGcryptorV3.2!!!" ascii
        $s2 = "Some files are protected ." ascii
        $s3 = "Help me !" ascii
        $s4 = "SecurityHealth.exe" ascii
        $s5 = "#GPC0DEMAGICVAL" ascii

    condition:
        3 of ($s*)
}
