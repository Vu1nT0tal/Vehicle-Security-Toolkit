#!/usr/bin/python3

import sys
import pyfiglet
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


def analysis(bin_path: Path):
    report_file = bin_path.parent.joinpath(f'SecScan/{bin_path.stem}-absinspector.txt')

    cmd = f'docker run --rm -v {bin_path.parent}:/data/workspace absinspector "@@ -K 10" -import {bin_path.name}'
    output, ret_code = shell_cmd(cmd)

    if ret_code == 0:
        with open(report_file, 'w+') as f:
            f.write(output)
    else:
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing ELF path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('bin_absinspector'))
    elf_dirs = open(argument().config, 'r').read().splitlines()

    for elf in elf_dirs:
        Color.print_focus(f'[+] [absinspector] {elf}')
        elf_path = Path(elf)

        report_path = elf_path.parent.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        if ret := analysis(elf_path):
            Color.print_failed('[-] [absinspector] failed')
        else:
            Color.print_success('[+] [absinspector] success')
