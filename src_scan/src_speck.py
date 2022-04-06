#!/usr/bin/python3

import sys
import pyfiglet
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


def analysis(src_path: Path, tools_path: Path):
    report_file = src_path.joinpath('SecScan/speck.txt')

    scanner = tools_path.joinpath('SPECK-main/server/Scan.py')
    cmd = f'python3 {scanner} -g -s {src_path} | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g"'
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
    parser.add_argument('--config', help='A config file containing source code path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('src_speck'))
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')
    src_dirs = open(argument().config, 'r').read().splitlines()

    for src in src_dirs:
        Color.print_focus(f'[+] [speck] {src}')
        src_path = Path(src)

        report_path = src_path.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        ret = analysis(src_path, tools_path)
        if ret:
            Color.print_failed('[-] [speck] failed')
        else:
            Color.print_success('[+] [speck] success')
