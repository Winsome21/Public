rule gootloader_zip
{
    strings:
        $r1 = /((\(|\s|\[|\{)\d{3,6}(\)|\s|\]|\})?|\([a-zA-Z]{2,5}\))\.js/
        $s1 = "agree" ascii wide nocase
        $s2 = "form" ascii wide nocase
        $s3 = "contract" ascii wide nocase
        $s4 = "family" ascii wide nocase
        $s5 = "pay" ascii wide nocase
        $s6 = "separat" ascii wide nocase
        $s7 = "service" ascii wide nocase
        $s8 = "level" ascii wide nocase
        $s9 = "mutual" ascii wide nocase
        $s10 = "require" ascii wide nocase
        $s11 = "access" ascii wide nocase
        $s12 = "addendum" ascii wide nocase
        $s13 = "categor" ascii wide nocase
        $s14 = "lease" ascii wide nocase
        $s15 = "license" ascii wide nocase
        $s16 = "manage" ascii wide nocase
        $s17 = "privilege" ascii wide nocase
        $s18 = "memorandum" ascii wide nocase
        $s19 = "mentor" ascii wide nocase
        $s20 = "mobility" ascii wide nocase
        $s21 = "telework" ascii wide nocase
        $s22 = "medical" ascii wide nocase
        $s23 = "antivirus" ascii wide nocase
        $s24 = "award" ascii wide nocase
        $s25 = "example" ascii wide nocase
        $s27 = "labor" ascii wide nocase
        $s28 = "sample" ascii wide nocase
        $s29 = "security" ascii wide nocase
        $s30 = "sharing" ascii wide nocase
        $s31 = "software" ascii wide nocase
        $s32 = "status" ascii wide nocase
        $s33 = "terminate" ascii wide nocase
        $s34 = "letter" ascii wide nocase
        $s35 = "legal" ascii wide nocase
    condition:
        uint32(0) == 0x04034b50 and ((for all of ($r*) : ( $ in (0..200)) and for any of ($s*) : ( $ in (0..200)))) and filesize > 1MB
}