#!/usr/bin/python3

import sys
import pyfiglet
import argparse
from pathlib import Path

sys.path.append('..')
from utils import *


def analysis(apk_path: Path, tools_path: Path):
    report_file = apk_path.parent.joinpath('SecScan/hunt.txt')

    scanner = tools_path.joinpath('apkhunt')
    cmd = f'{scanner} -p {apk_path} -l'
    output, ret_code = shell_cmd(cmd)

    if not report_file.exists():
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('apk_hunt'))
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')

    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        print_focus(f'[hunt] {apk}')
        apk_path = Path(apk)

        report_path = apk_path.parent.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        if ret := analysis(apk_path, tools_path):
            print_failed('[hunt] failed')
        else:
            print_success('[hunt] success')
