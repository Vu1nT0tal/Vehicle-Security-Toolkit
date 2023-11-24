#!/usr/bin/python3

import sys
import json
import pyfiglet
import argparse
from pathlib import Path
from quark.report import Report
from quark.script import runQuarkAnalysis, Rule

sys.path.append('..')
from utils import *


def analysis(apk_path: Path, tools_path: Path):
    rules_path = tools_path.joinpath('quark/rules/rules')
    scripts_path = tools_path.joinpath('quark/scripts')
    rules_report_file = apk_path.parent.joinpath('SecScan/quark_rules.json')
    scripts_report_file = apk_path.parent.joinpath('SecScan/quark_scripts.json')

    rules_report = Report()
    rules_report.analysis(apk_path, rules_path)
    json_report = rules_report.get_report("json")
    with open(rules_report_file, 'w+') as f:
        json.dump(json_report, f, indent=4)


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('apk_quark'))
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')

    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        print_focus(f'[quark] {apk}')
        apk_path = Path(apk)

        report_path = apk_path.parent.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        analysis(apk_path, tools_path)

    print_success('[quark] success')
