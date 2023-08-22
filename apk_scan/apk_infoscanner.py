#!/usr/bin/python3

import sys
import shutil
import pyfiglet
import argparse
from pathlib import Path

sys.path.append('..')
from utils import *


def analysis(apk_path: Path, tools_path: Path):
    report_dir = apk_path.parent.joinpath('SecScan/infoscanner')
    report_file = report_dir.joinpath('output.txt')

    scanner = tools_path.joinpath('AppInfoScanner-master/app.py')
    cmd = f'python3 {scanner} android -i {apk_path} -o {report_dir}'
    output, ret_code = shell_cmd(cmd)

    if ret_code == 0:
        with open(report_file, 'w+') as f:
            f.write(output)
    else:
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    shutil.rmtree(report_dir.joinpath('out'), ignore_errors=True)
    shutil.rmtree(report_dir.joinpath('download'), ignore_errors=True)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('apk_infoscanner'))
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')

    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        print_focus(f'[infoscanner] {apk}')
        apk_path = Path(apk)

        report_path = apk_path.parent.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        if ret := analysis(apk_path, tools_path):
            print_failed('[infoscanner] failed')
        else:
            print_success('[infoscanner] success')
