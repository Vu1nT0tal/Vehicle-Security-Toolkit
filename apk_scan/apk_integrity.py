#!/usr/bin/python3

import sys
import shutil
import pyfiglet
import argparse
import tempfile
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


def analysis(apk_path: Path, tools_path: Path):
    report_file = apk_path.parent.joinpath('SecScan/integrity.html')
    tmp_dir = tempfile.mkdtemp()

    apktool = tools_path.joinpath('apktool.jar')
    scanner = tools_path.joinpath('DISintegrity-main/DISintegrity.py')
    cmd = f'python3 {scanner} -apk {apk_path} --apktool {apktool} -o {tmp_dir}'
    output, ret_code = shell_cmd(cmd)
    shutil.copyfile(f'{tmp_dir}/output.html', report_file)

    if ret_code != 0 or not report_file.exists():
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    shutil.rmtree(tmp_dir)
    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('apk_integrity'))
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')

    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        Color.print_focus(f'[+] [integrity] {apk}')
        apk_path = Path(apk)

        report_path = apk_path.parent.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        if ret := analysis(apk_path, tools_path):
            Color.print_failed('[-] [integrity] failed')
        else:
            Color.print_success('[+] [integrity] success')
