#!/usr/bin/python3

import pyfiglet
import argparse
from pathlib import Path
from collections import defaultdict

from utils import Color
from bin_scan.bin_stacs import analysis as stacs
from bin_scan.bin_capa import analysis as capa
from bin_scan.bin_cvescan import analysis as cvescan
from bin_scan.bin_cwechecker import analysis as cwechecker
from bin_scan.bin_absinspector import analysis as absinspector


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing ELF path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('bin-allinone'))
    args = argument()
    tools_path = Path(__file__).absolute().parent.joinpath('tools')

    plugin = {
        'stacs': defaultdict(list),
        'capa': defaultdict(list),
        'cvescan': defaultdict(list),
        'cwechecker': defaultdict(list),
        'absinspector': defaultdict(list)
    }
    elf_dirs = open(args.config, 'r').read().splitlines()

    for elf in elf_dirs:
        Color.print_focus(f'[+] {elf}')

        elf_path = Path(elf)
        report_path = elf_path.parent.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        # bin_stacs
        if 'stacs' in plugin:
            if ret := stacs(elf_path, tools_path):
                plugin['stacs']['failed'].append(elf)
                Color.print_failed['[-] [stacs] failed']
            else:
                plugin['stacs']['success'].append(elf)
                Color.print_success('[+] [stacs] success')

        # bin_capa
        if 'capa' in plugin:
            if ret := capa(elf_path, tools_path):
                plugin['capa']['failed'].append(elf)
                Color.print_failed('[-] [capa] failed')
            else:
                plugin['capa']['success'].append(elf)
                Color.print_success('[+] [capa] success')

        # bin_cvescan
        if 'cvescan' in plugin:
            if ret := cvescan(elf_path):
                plugin['cvescan']['failed'].append(elf)
                Color.print_failed('[-] [cvescan] failed')
            else:
                plugin['cvescan']['success'].append(elf)
                Color.print_success('[+] [cvescan] success')

        # bin_cwechecker
        if 'cwechecker' in plugin:
            if ret := cwechecker(elf_path):
                plugin['cwechecker']['failed'].append(elf)
                Color.print_failed('[-] [cwechecker] failed')
            else:
                plugin['cwechecker']['success'].append(elf)
                Color.print_success('[+] [cwechecker] success')

        # bin_absinspector
        if 'absinspector' in plugin:
            if ret := absinspector(elf_path):
                plugin['absinspector']['failed'].append(elf)
                Color.print_failed('[-] [absinspector] failed')
            else:
                plugin['absinspector']['success'].append(elf)
                Color.print_success('[+] [absinspector] success')

    print(plugin)
