#!/usr/bin/python3

import sys
import json
import pyfiglet
import argparse
from pathlib import Path
from quark.report import Report

sys.path.append('..')
from utils import *


def analysis(apk_path: Path):
    rule_path = str(Path('~/.quark-engine/quark-rules/').expanduser())
    report_file = apk_path.parent.joinpath('SecScan/quark.json')

    report = Report()
    report.analysis(apk_path, rule_path)
    json_report = report.get_report("json")
    with open(report_file, 'w+') as f:
        json.dump(json_report, f, indent=4)


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('apk_quark'))

    success_num = 0
    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        print_focus(f'[quark] {apk}')
        apk_path = Path(apk)

        report_path = apk_path.parent.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        analysis(apk_path)
        success_num += 1

    print_success(f'[quark] {success_num}')
