#!/usr/bin/python3

import sys
import shutil
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


def analysis(src_path: Path, tools_path: Path):
    report_dir = src_path.joinpath('SecScan/fireline')
    if report_dir.exists():
        shutil.rmtree(report_dir, ignore_errors=True)
    report_dir.mkdir()

    fireline = tools_path.joinpath('fireline.jar')
    cmd = f'java -jar {fireline} -s {src_path} -r {report_dir}'
    output, ret_code = shell_cmd(cmd, {'java': 8})

    if ret_code != 0:
        with open(report_dir.joinpath('report.error'), 'w+') as f:
            f.write(output)
    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing source code path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('****************** src_fireline.py *******************')
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')
    src_dirs = open(argument().config, 'r').read().splitlines()

    for src in src_dirs:
        Color.print_focus(f'[+] [fireline] {src}')
        src_path = Path(src)

        report_path = src_path.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        ret = analysis(src_path, tools_path)
        if ret:
            Color.print_failed('[-] [fireline] failed')
        else:
            Color.print_success('[+] [fireline] success')
