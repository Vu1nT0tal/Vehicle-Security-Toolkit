#!/usr/bin/python3

import sys
import pyfiglet
import argparse
from pathlib import Path

sys.path.append('..')
from utils import *


def analysis(src_path: Path, tools_path: Path):
    report_file = src_path.joinpath('SecScan/keyfinder.txt')

    scanner = tools_path.joinpath('keyfinder-master/keyfinder.py')
    cmd = f'python3 {scanner} -v -k {src_path}'
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
    print(pyfiglet.figlet_format('src_keyfinder'))
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')
    src_dirs = open(argument().config, 'r').read().splitlines()

    for src in src_dirs:
        print_focus(f'[keyfinder] {src}')
        src_path = Path(src)

        report_path = src_path.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        if ret := analysis(src_path, tools_path):
            print_failed('[keyfinder] failed')
        else:
            print_success('[keyfinder] success')
