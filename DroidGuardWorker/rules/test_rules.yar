rule Test_Internet_Permission {
    meta:
        description = "Pipeline Test: Detects standard Android internet permission"
        author = "Anastasia"
        threat_level = "low"
    strings:
        // 'ascii wide' ensures it catches the string regardless of text encoding
        $manifest_string = "android.permission.INTERNET" ascii wide
    condition:
        $manifest_string
}

rule Test_Fake_Malware {
    meta:
        description = "Pipeline Test: Detects a fake malicious signature"
        author = "Anastasia"
        threat_level = "critical"
    strings:
        $fake_sig = "DROIDGUARD_EVIL_HACKER_STRING_9999" ascii wide
    condition:
        $fake_sig
}