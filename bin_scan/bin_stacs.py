#!/usr/bin/python3

import sys
import pyfiglet
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


def analysis(bin_path: Path, tools_path: Path):
    report_path = bin_path.parent.joinpath(f'SecScan/{bin_path.stem}-stacs.json')
    report_path.unlink(missing_ok=True)

    rule_path = tools_path.joinpath('stacs-rules/credential.json')
    cmd = f'stacs --rule-pack {rule_path} {bin_path} > {report_path}'
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
    print(pyfiglet.figlet_format('bin_stacs'))
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')
    elf_dirs = open(argument().config, 'r').read().splitlines()

    for elf in elf_dirs:
        Color.print_focus(f'[+] [stacs] {elf}')
        elf_path = Path(elf)

        report_path = elf_path.parent.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        ret = analysis(elf_path, tools_path)
        if ret:
            Color.print_failed('[-] [stacs] failed')
        else:
            Color.print_success('[+] [stacs] success')
