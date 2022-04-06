#!/usr/bin/python3

import sys
import pyfiglet
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


def analysis(apk_path: Path, tools_path: Path):
    report_file = apk_path.parent.joinpath('SecScan/keyfinder.txt')

    scanner = tools_path.joinpath('keyfinder-master/keyfinder.py')
    cmd = f'python3 {scanner} -v -k {apk_path.parent.joinpath("apktool_smali")}'
    output, ret_code = shell_cmd(cmd, {'cwd': scanner.parent})

    if ret_code == 0:
        with open(report_file, 'w+') as f:
            f.write(output)
    else:
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('apk_keyfinder'))
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')

    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        Color.print_focus(f'[+] [keyfinder] {apk}')
        apk_path = Path(apk)

        report_path = apk_path.parent.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        ret = analysis(apk_path, tools_path)
        if ret:
            Color.print_failed('[-] [keyfinder] failed')
        else:
            Color.print_success('[+] [keyfinder] success')
