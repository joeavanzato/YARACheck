# YARACheck
 Update and use YARA rules from across the Internet against targeted files or directories.


## Instructions
1. If you want to update rules, run yara_updater.py.
2. yara_scan will look for 'compiled_rules.bin' in current working directory if none is specified in provided arguments.
3. yara_scan can operate against individual files, single directories or recursively against a directory tree
   1. Single File Usage: yara_scan.py <target_file>
   2. Directory (Non-Recursive): yara_scan.py <target_dir>
   3. Directory (Recursive): yara_scan.py <target_dir> -recursive
4. If you want a report output on top of console output, add "-report <json|csv>" to specify a format and "-out <file_path>", otherwise a report is generated in the current working directory.

## Arguments
```
-recursive : Recursively scan directory if target is a directory.
-report : Generate an output report in either CSV or JSON format.
-out : Specify a file path for the generated report.
```

## Rules Pulled from Following Locations
    "GCTI": 'https://github.com/chronicle/GCTI/archive/refs/heads/main.zip',
    "ESET": 'https://api.github.com/repos/eset/malware-ioc/zipball/master',
    "Elastic": 'https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip',
    "ReversingLabs": 'https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip',
    "Neo23x0": 'https://api.github.com/repos/Neo23x0/signature-base/zipball/master',
    "Qu1cksc0pe": 'https://api.github.com/repos/CYB3RMX/Qu1cksc0pe/zipball/master',
    "bartblaze": 'https://api.github.com/repos/bartblaze/Yara-rules/zipball/master',
    "blackorbird": 'https://api.github.com/repos/blackorbird/APT_REPORT/zipball/master', # This one is rather large (~1.3 Gigabytes) - comment out if you lack space/bandwidth.
    "yara-rules": 'https://api.github.com/repos/Yara-Rules/rules/zipball/master',
    "BinaryAlert": 'https://api.github.com/repos/airbnb/binaryalert/zipball/master',
    "CodeWatch": 'https://api.github.com/repos/codewatchorg/Burp-Yara-Rules/zipball/master',
    "CAPE": 'https://api.github.com/repos/kevoreilly/CAPEv2/zipball/master',
    "CyberDefenses": 'https://api.github.com/repos/CyberDefenses/CDI_yara/zipball/master',
    "CitizenLab": 'https://api.github.com/repos/citizenlab/malware-signatures/zipball/master',
    "ConventionEngine": 'https://api.github.com/repos/stvemillertime/ConventionEngine/zipball/master',
    "deadbits": 'https://api.github.com/repos/deadbits/yara-rules/zipball/master',
    "delivr-to": 'https://github.com/delivr-to/detections/archive/refs/heads/main.zip',
    "fidelis": 'https://api.github.com/repos/fideliscyber/indicators/zipball/master',
    "f0wl": 'https://github.com/f0wl/yara_rules/archive/refs/heads/main.zip',
    "fboldewin": 'https://api.github.com/repos/fboldewin/YARA-rules/zipball/master',
    "EmersonElectric": 'https://api.github.com/repos/EmersonElectricCo/fsf/zipball/master',
    "h3x2b": 'https://api.github.com/repos/h3x2b/yara-rules/zipball/master',
    "icewater.io": 'https://api.github.com/repos/SupportIntelligence/Icewater/zipball/master',
    "intezer": 'https://api.github.com/repos/intezer/yara-rules/zipball/master',
    "imp0rtp3": 'https://github.com/imp0rtp3/yara-rules/archive/refs/heads/main.zip',
    "InQuest": 'https://api.github.com/repos/InQuest/yara-rules/zipball/master',
    "jeFF0Falltrades": 'https://api.github.com/repos/jeFF0Falltrades/YARA-Signatures/zipball/master',
    "kevthehermit": 'https://api.github.com/repos/kevthehermit/YaraRules/zipball/master',
    "MalGamy": 'https://github.com/MalGamy/YARA_Rules/archive/refs/heads/main.zip',
    "malice": 'https://api.github.com/repos/malice-plugins/yara/zipball/master',
    "malpedia": 'https://github.com/malpedia/signator-rules/archive/refs/heads/main.zip',
    "trellix": 'https://api.github.com/repos/advanced-threat-research/Yara-Rules/zipball/master',
    "mikesxrs": 'https://github.com/mikesxrs/Open-Source-YARA-rules/archive/refs/heads/master.zip',
    "securitymagic": 'https://github.com/securitymagic/yara/archive/refs/heads/main.zip',
    "t4d": 'https://api.github.com/repos/t4d/PhishingKit-Yara-Rules/zipball/master',
    "tenable": 'https://api.github.com/repos/tenable/yara-rules/zipball/master',
    "VectraThreatLab": 'https://api.github.com/repos/VectraThreatLab/reyara/zipball/master',
    "volexity": 'https://github.com/volexity/threat-intel/archive/refs/heads/main.zip',