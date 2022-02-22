#!/usr/bin/python3

import argparse
from pathlib import Path
from collections import defaultdict

from utils import Color
from bin_scan.bin_cvescan import analysis as cvescan
from bin_scan.bin_cwechecker import analysis as cwechecker


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing ELF path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************* bin-allinone.py ******************')
    args = argument()
    tools_path = Path(__file__).absolute().parent.joinpath('tools')

    plugin = {
        'cvescan': defaultdict(list),
        'cwechecker': defaultdict(list)
    }
    elf_dirs = open(args.config, 'r').read().splitlines()

    for elf in elf_dirs:
        Color.print_focus(f'[+] {elf}')

        elf_path = Path(elf)
        report_path = elf_path.parent.joinpath('SecScan')
        if not report_path.exists():
            report_path.mkdir()

        # bin_cvescan
        if 'cvescan' in plugin:
            ret = cvescan(elf_path)
            if ret:
                plugin['cvescan']['failed'].append(elf)
                Color.print_failed('[-] [cvescan] failed')
            else:
                plugin['cvescan']['success'].append(elf)
                Color.print_success('[+] [cvescan] success')

        # bin_cwechecker
        if 'cwechecker' in plugin:
            ret = cwechecker(elf_path)
            if ret:
                plugin['cwechecker']['failed'].append(elf)
                Color.print_failed('[-] [cwechecker] failed')
            else:
                plugin['cwechecker']['success'].append(elf)
                Color.print_success('[+] [cwechecker] success')

    print(plugin)
