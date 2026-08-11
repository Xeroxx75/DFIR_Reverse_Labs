rule Crackme_Sallos_KeyLicense
{
    meta:
        author = "Ibrahim Diallo"
        description = "Educational rule for Sallos's Key License crackme"
        reference = "dfir-reverse-labs/crackme key-license"

    strings:
        $s1 = "Invalid user login!" ascii
        $s2 = "Invalid license key!" ascii
        $s3 = "key.license" ascii
        $s4 = "DialogBoxParamA" ascii
        $s5 = "GetUserNameExA" ascii
        $s6 = "CheckRemoteDebuggerPresent" ascii

    condition:
        3 of ($s*)
}
