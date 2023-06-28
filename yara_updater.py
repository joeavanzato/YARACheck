import yara
import os
import requests
import shutil
import zipfile
import traceback
import sys

# TODO - Inefficient right now because we are cloning entire repos and then extracting and scanning for rules -
#  the alternative is cloning specific folders from a repo or scanning for files individually which results in significantly more API requests.

ZIP_URLS = {
    "Daily IOC": 'https://api.github.com/repos/StrangerealIntel/DailyIOC/zipball/master',
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
}
RULE_DIR = 'rules'
TEMP_ZIP_DIR = 'temp'
RULE_OUTPUT_FILE = "compiled_rules.bin"


def get_zips():
    '''
    Download and Extract all ZIPs from remote locations.
    :return:
    '''
    for k, v in ZIP_URLS.items():
        try:
            print(f"[+] Updating Rules: {k}")
            request = requests.get(v, stream=True)
            zip_path = f"{TEMP_ZIP_DIR}\\{k}.zip"
            with open(zip_path, 'wb') as f:
                for chunk in request.iter_content(chunk_size=128):
                    f.write(chunk)
            extract_zip(zip_path)
        except:
            print(f"[!] Error Processing {v}")
            print(traceback.format_exc())

def find_yara_files():
    '''
    Find all YARA files inside extracted directories.
    :return:
    '''
    print("[+] Finding YARA Rules...")
    yara_files = []
    for root, dirs, files in os.walk(TEMP_ZIP_DIR):
        for file in files:
            if file.endswith('.yar'):
                yara_files.append(os.path.join(root, file))
    return yara_files

def extract_zip(zip_path):
    '''
    Extract a provided ZIP file to the temporary ZIP directory.
    :param zip_path:
    :return:
    '''
    zip_reference = zipfile.ZipFile(zip_path)
    zip_reference.extractall(TEMP_ZIP_DIR)
    zip_reference.close()


def setup_dirs():
    '''
    Create temporary directories for ZIP and RULE storage.
    :return:
    '''
    if not os.path.exists(TEMP_ZIP_DIR):
        os.makedirs(TEMP_ZIP_DIR)
    if not os.path.exists(RULE_DIR):
        os.makedirs(RULE_DIR)


def copy_rules(yara_rules):
    '''
    Copy each detected YARA rule from the temporary ZIP directory to the RULES directory.
    :param yara_rules:
    :return:
    '''
    print(f"[+] Copying Detected Rules: {len(yara_rules)}")
    for i in yara_rules:
        shutil.copy(i, RULE_DIR)

def get_yara_files():
    '''
    Helper function for retrieving all existing YARA files in the Rules directory.
    :return:
    '''
    yara_rules = {}
    for root, dirs, files in os.walk(RULE_DIR):
        for file in files:
            if file.endswith('.yar'):
                yara_rules[file] = (os.path.join(root, file))
    return yara_rules


def compile_rules():
    '''
    Test each rule individually to determine if it compiles - if it does not, rename with .error appended.
    Take valid rules and compile to a single output file for use with yara_scan.py.
    :return:
    '''
    print("[+] Testing Rules")
    yara_rules = get_yara_files()
    for k, v in yara_rules.items():
        try:
            rules = yara.compile(v)
        except yara.Error:
            print(f"[!] Error Compiling: {v}")
            shutil.move(v, v+".error")
    yara_rules = get_yara_files()
    print("[+] Compiling Valid Rules")
    rules = yara.compile(filepaths=yara_rules)
    rules.save(RULE_OUTPUT_FILE)
    print(f"[!] Rules Saved to {RULE_OUTPUT_FILE}")


def clean_up():
    '''
    Clean up temporary zip and rules directories.
    :return:
    '''
    try:
        shutil.rmtree(TEMP_ZIP_DIR)
    except OSError:
        pass
    try:
        shutil.rmtree(RULE_DIR)
    except OSError:
        pass


def main():
    print("[!] YARACheck Rule Updater")
    setup_dirs()
    get_zips()
    yara_rules = find_yara_files()
    copy_rules(yara_rules)
    compile_rules()
    clean_up()


main()
