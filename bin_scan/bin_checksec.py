#!/usr/bin/python3

import sys
import pyfiglet
import argparse
from pathlib import Path

sys.path.append('..')
from utils import *


def analysis(bin_path: Path):
    report_path = bin_path.parent.joinpath(f'SecScan/{bin_path.stem}-checksec.txt')
    report_path.unlink(missing_ok=True)

    cmd = f'checksec {bin_path} 2> {report_path}'
    output, ret_code = shell_cmd(cmd)

    if ret_code != 0:
        with open(f'{report_path}.error', 'w+') as f:
            f.write(output)
    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing ELF path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('bin_checksec'))
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')
    elf_dirs = open(argument().config, 'r').read().splitlines()

    for elf in elf_dirs:
        print_focus(f'[checksec] {elf}')
        elf_path = Path(elf)

        report_path = elf_path.parent.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        if ret := analysis(elf_path):
            print_failed('[checksec] failed')
        else:
            print_success('[checksec] success')
