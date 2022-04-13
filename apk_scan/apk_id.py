#!/usr/bin/python3

import sys
import json
import pyfiglet
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


def analysis(apk_path: Path):
    report_file = apk_path.parent.joinpath('SecScan/apkid.json')

    cmd = f'apkid {apk_path} -j'
    output, ret_code = shell_cmd(cmd)
    if ret_code == 0:
        with open(report_file, 'w+') as f:
            f.write(json.dumps(json.loads(output), indent=4))

    if not report_file.exists():
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('apk_id'))
    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        Color.print_focus(f'[+] [apkid] {apk}')

        apk_path = Path(apk)
        report_path = apk_path.parent.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        if ret := analysis(apk_path):
            Color.print_failed('[-] [apkid] failed')
        else:
            Color.print_success('[+] [apkid] success')
