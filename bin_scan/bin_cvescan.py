#!/usr/bin/python3

import sys
import json
import pyfiglet
import argparse
import requests
from pathlib import Path
from collections import defaultdict

sys.path.append('..')
from utils import shell_cmd, Color


def analysis(bin_path: Path):
    report_path = bin_path.parent.joinpath(f'SecScan/{bin_path.stem}-cvescan.json')
    report_path.unlink(missing_ok=True)

    cmd = f'cve-bin-tool {bin_path} --report -f json -o {report_path}'
    output, ret_code = shell_cmd(cmd)

    if ret_code > 1:
        with open(f'{report_path}.error', 'w+') as f:
            f.write(output)
            return 1

    result = defaultdict(list)
    with open(report_path, 'r') as f:
        data = json.load(f)

        for item in data:
            cve_number = item['cve_number']
            if cve_number == 'UNKNOWN':
                continue

            try:
                r = requests.get(f'https://cve.circl.lu/api/cve/{cve_number}')
                summary = r.json()['summary']
            except Exception as e:
                summary = ''

            result[f"{item['vendor']}|{item['product']}|{item['version']}|{item['paths']}"].append(
                {'cve': cve_number,
                'severity': item['severity'],
                'score': item['score'],
                'summary': summary,
                'url': f'https://www.cvedetails.com/cve/{cve_number}'})

    with open(report_path, 'w') as f:
        f.write(json.dumps(result, indent=4))
    return 0


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing ELF path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('bin_cvescan'))
    elf_dirs = open(argument().config, 'r').read().splitlines()

    for elf in elf_dirs:
        Color.print_focus(f'[+] [cvescan] {elf}')
        elf_path = Path(elf)

        report_path = elf_path.parent.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        if ret := analysis(elf_path):
            Color.print_failed('[-] [cvescan] failed')
        else:
            Color.print_success('[+] [cvescan] success')
