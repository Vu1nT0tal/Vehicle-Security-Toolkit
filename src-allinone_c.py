#!/usr/bin/python3

import argparse
from pathlib import Path

from utils import Color, shell_cmd


def flawfinder(src_path: Path):
    Color.print_focus('[+] flawfinder ...')
    report_file = report_path.joinpath('flawfinder.html')

    scanner = tools_path.joinpath('flawfinder-env/bin/flawfinder')
    cmd = f'{scanner} --context --quiet --html {src_path} > {report_file}'
    shell_cmd(cmd)


def tscancode(src_path: Path):
    Color.print_focus('[+] tscancode ...')
    report_file = report_path.joinpath('tscancode.xml')

    scanner = tools_path.joinpath('TscanCode/TscanCode/tscancode')
    cmd = f'{scanner} --enable=all --xml {src_path} 2>{report_file} >/dev/null'
    shell_cmd(cmd)


def cppcheck(src_path: Path):
    Color.print_focus('[+] cppcheck ...')
    report_file1 = report_path.joinpath('cppcheck.txt')
    report_file2 = report_path.joinpath('cppcheck-bug.txt')

    scanner = tools_path.joinpath('cppcheck/bin/cppcheck')
    cmd1 = f'{scanner} {src_path} 2>&1 | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" > {report_file1}'
    shell_cmd(cmd1)

    cmd2 = f'{scanner} --bug-hunting {src_path} 2>&1 | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" > {report_file2}'
    shell_cmd(cmd2)

def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--src', help='Source code path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('****************** src-allinone_c.py *****************')
    src_path = Path(argument().src).absolute()
    tools_path = Path(__file__).absolute().parent.joinpath('tools')

    report_path = src_path.joinpath('SecScan')
    report_path.mkdir(parents=True, exist_ok=True)

    plugin = {
        'flawfinder': 1,
        'tscancode': 1,
        'cppcheck': 1
    }

    if 'flawfinder' in plugin:
        flawfinder(src_path)

    if 'tscancode' in plugin:
        tscancode(src_path)

    if 'cppcheck' in plugin:
        cppcheck(src_path)

    print(f'报告地址：{report_path}')
