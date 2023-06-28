
import argparse
import os
import sys
import datetime
import traceback
import json

import yara

DEFAULT_RULE_FILE = 'compiled_rules.bin'
DEFAULT_EXTENSIONS = ['exe', 'scr', 'lnk', 'hta', 'doc', 'xls', 'pdf', 'vbs', 'rtf', 'js', 'jar', 'cpl', 'crt', 'ins',
                      'isp', 'ade', 'adp', 'ldb', 'mad', 'mda', 'mdb', 'mdz', 'snp', 'bas', 'mde', 'mst', 'docm',
                      'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ps1', 'vba', 'psm1', 'bat', 'dll']


def parse_args():
    parser = argparse.ArgumentParser(usage=f'''
    YARACheck 
    https://github.com/joeavanzato/YARACheck
    Easily Scan Files or Directories with YARA Rules from across the Internet
    
    yaracheck.py --target <Target_File>
    yaracheck.py --target <Target_Directory>
    yaracheck.py --target <Target_Directory> --recursive
    yaracheck.py --target <Target_Directory> --report csv
    yaracheck.py --target <Target_Directory> --report json
    yaracheck.py --target <Target_Directory> --recursive --report json --out <Report_File>
    yaracheck.py --target <Target_File> --extensions exe,bat
    yaracheck.py --target <Target_File> --rules <Rules_File>
    
    --target : Target File/Directory
    --recursive : Recursively scan directory if target is a directory.
    --report : Generate an output report in either CSV or JSON format.
    --out : Specify a file path for the generated report.
    --rules : Specify path to compiled rules file.
    --extensions : Specify which file-extensions to scan - defaults to {DEFAULT_EXTENSIONS}.
    ''')
    parser.add_argument("-r", "--report", help="Specify a report type for saving data - json,csv.", required=False, nargs=1, type=str)
    parser.add_argument("-o", "--out", help="Specify the custom file path where reporting should be stored.", required=False, nargs=1, type=str)
    parser.add_argument("-t", "--target", help="Specify a file or directory target.", required=True, nargs=1, type=str)
    parser.add_argument("-re", "--recursive", help="Enable recursive directory scanning.", required=False, action="store_true")
    parser.add_argument("-ru", "--rules", help="Path to compiled YARA rules file.", required=False, nargs=1, type=str)
    parser.add_argument("-ext", "--extensions", help="Comma-Delimited list of extensions to scan for.", required=False, nargs=1, type=str)
    args = parser.parse_args()

    target = args.target[0]
    current_time = datetime.datetime.now()
    arguments = {
        'target': target,
        'is_file': False,
        'is_dir': False,
        'recursive': False,
        'csv_report': False,
        'json_report': False,
        'output_path': f'yaracheck_report_{target}_{current_time}'.replace(':','_').replace("\\","_"),
        'rules_file': DEFAULT_RULE_FILE,
        'extensions': DEFAULT_EXTENSIONS
    }
    if args.extensions:
        extensions = args.extensions
        if ',' in extensions:
            arguments['extensions'] = extensions.split(',')
        else:
            arguments['extensions'] = [extensions]

    if target:
        if os.path.isfile(target):
            arguments['is_file'] = True
            print(f"[+] Valid File Target: {target}")
        elif os.path.isdir(target):
            arguments['is_dir'] = True
            print(f"[+] Valid Directory Target: {target}")
        else:
            print(f"[!] Target ('{target}') is not a valid file or directory!")
            sys.exit(1)
    if args.recursive:
        arguments['recursive'] = True
        print("[+] Recursive Scanning Enabled for Directory Scans")
    if args.report:
        report = args.report[0]
        if report == 'csv':
            arguments['csv_report'] = True
            arguments['output_path'] = arguments['output_path']+".csv"
            print("[+] Generating CSV Report")
        elif report == 'json':
            arguments['json_report'] = True
            arguments['output_path'] = arguments['output_path']+".json"
            print("[+] Generating JSON Report")
        else:
            print(f"Unknown Report Format: {report}")
    if args.out:
        output_path = args.out[0]
        arguments['output_path'] = output_path
    if args.rules:
        arguments['rules_file'] = args.rules[0]

    if os.path.isfile(arguments['rules_file']):
        print(f"[+] Valid Rule File: {arguments['rules_file']}")
    else:
        print(f"[!] Invalid Rule File: {arguments['rules_file']}")
        sys.exit(1)

    try:
        with open(arguments['output_path'], 'w') as f:
            pass
    except OSError:
        print(f"[!] Error Creating Report at Specified Location: {arguments['output_path']}")
        print(traceback.format_exc())
        sys.exit(1)

    return arguments


def load_rules(arguments):
    '''
    Load compiled YARA rules into memory.
    :param arguments:
    :return:
    '''
    print("[+] Loading YARA Rules")
    rules = yara.load(arguments['rules_file'])
    return rules


def yara_callback(data):
  print(f"[!] {data}")
  return yara.CALLBACK_CONTINUE


def write_to_report(data, arguments):
    '''
    Append provided data to report file.
    :param data: String object representing data to be written.
    :param arguments:
    :return:
    '''
    with open(arguments['output_path'], 'a') as f:
        f.write(data)


def scan_file(rules, file, arguments):
    '''
    Attempt to scan an arbitrary file with the loaded YARA rules if the files extension (minus the '.') is present in the currently loaded allow-list.
    :param rules:
    :param file:
    :param arguments:
    :return:
    '''
    if not os.path.splitext(file)[1][1:] in arguments['extensions']:
        return
    print(f"[+] Scanning: {file}")
    try:
        #matches = rules.match(file, callback=yara_callback, which_callbacks=yara.CALLBACK_MATCHES)
        matches = rules.match(file)
    except yara.Error:
        print(f"[!] Error Scanning: {file}")
        return
    if len(matches) == 0:
        return
    rules = ''
    for match in matches:
        rules += match.rule
        rules += ", "
    print(f"[!] Rule Matches: {rules}")
    if arguments['csv_report']:
        data = f"{file},\""
        data += rules
        data += "\"\n"
        write_to_report(data, arguments)
    elif arguments['json_report']:
        data = {}
        data[file] = []
        for match in matches:
            temp = {}
            temp['rule'] = match.rule
            temp['rule_file'] = match.namespace
            temp['tags'] = match.tags
            temp['meta'] = match.meta
            data[file].append(temp)
        json_data = json.dumps(data, indent=4)
        write_to_report(json_data, arguments)


def scan_directory(rules, arguments):
    '''
    Crawl directories for passing files to the scanning function.
    :param rules:
    :param arguments:
    :return:
    '''
    if arguments['recursive']:
        print(f"[+] Recursively Scanning: {arguments['target']}")
        for root, dirs, files in os.walk(arguments['target']):
            for file in files:
                scan_file(rules, os.path.join(root, file), arguments)
    else:
        print(f"[+] Scanning: {arguments['target']}")
        files = os.listdir(arguments['target'])
        for file in files:
            scan_file(rules, arguments['target']+"\\"+file, arguments)


def main():
    print("[!] Starting YARACheck Scanner [https://github.com/joeavanzato/YARACheck]")
    arguments = parse_args()
    rules = load_rules(arguments)
    if arguments['json_report']:
        with open(arguments['output_path'], 'w') as f:
            f.write('[')
    if arguments['is_file']:
        scan_file(rules, arguments['target'], arguments)
    else:
        scan_directory(rules, arguments)
    if arguments['json_report']:
        with open(arguments['output_path'], 'a') as f:
            f.write(']')
    print("[+] Done Scanning!")


main()

#  C:\Users\Joe\Downloads\GenshinImpact_install_20221122150037.exe