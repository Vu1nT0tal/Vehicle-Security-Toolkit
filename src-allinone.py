#!/usr/bin/python3

import argparse
from pathlib import Path
from collections import defaultdict
from apk_scan.apk_androbugs import analysis

from utils import Color
from src_scan.src_fireline import analysis as fireline
from src_scan.src_mobsf import analysis as mobsf
from src_scan.src_qark import analysis as qark
from src_scan.src_speck import analysis as speck
from src_scan.src_depcheck import analysis as depcheck


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing source code path', type=str, required=True)
    parser.add_argument('--build', help='Build the APK before analysis', action='store_true')
    return parser.parse_args()


if __name__ == '__main__':
    print('******************* src-allinone.py ******************')
    args = argument()
    tools_path = Path(__file__).absolute().parent.joinpath('tools')

    plugin = {
        'depcheck': defaultdict(list),
        'fireline': defaultdict(list),
        'mobsf': defaultdict(list),
        #'qark': defaultdict(list),          # 需要环境
        'speck': defaultdict(list),
    }
    src_dirs = open(args.config, 'r').read().splitlines()

    for src in src_dirs:
        Color.print_focus(f'[+] {src}')

        src_path = Path(src)
        report_path = src_path.joinpath('SecScan')
        if not report_path.exists():
            report_path.mkdir()

        # src_depcheck
        if 'depcheck' in plugin:
            if src_path.joinpath('gradlew').exists():
                ret = depcheck(src_path, tools_path, 'gradle')
            else:
                ret = depcheck(src_path, tools_path, 'cli')
            if ret:
                plugin['depcheck']['failed'].append(src)
                Color.print_failed('[-] [depcheck] failed')
            else:
                plugin['depcheck']['success'].append(src)
                Color.print_success('[-] [depcheck] success')

        # src_fireline
        if 'fireline' in plugin:
            ret = fireline(src_path, tools_path)
            if ret:
                plugin['fireline']['failed'].append(src)
                Color.print_failed('[-] [fireline] failed')
            else:
                plugin['fireline']['success'].append(src)
                Color.print_success('[+] [fireline] success')

        # src_mobsf
        if 'mobsf' in plugin:
            ret = mobsf(src_path)
            if ret:
                plugin['mobsf']['failed'].append(src)
                Color.print_failed('[-] [mobsf] failed')
            else:
                plugin['mobsf']['success'].append(src)
                Color.print_success('[+] [mobsf] success')

        # src_qark
        if 'qark' in plugin:
            ret = qark(src_path)
            if ret:
                plugin['qark']['failed'].append(src)
                Color.print_failed('[-] [qark] failed')
            else:
                plugin['qark']['success'].append(src)
                Color.print_success('[+] [qark] success')

        # src_speck
        if 'speck' in plugin:
            ret = speck(src_path, tools_path)
            if ret:
                plugin['speck']['failed'].append(src)
                Color.print_failed('[-] [speck] failed')
            else:
                plugin['speck']['success'].append(src)
                Color.print_success('[+] [speck] success')

    print(plugin)
