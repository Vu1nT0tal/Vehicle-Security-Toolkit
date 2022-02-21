#!/usr/bin/python3

import json
import argparse
from pathlib import Path
from quark.report import Report


def analysis(apk_path: Path):
    rule_path = str(Path('~/.quark-engine/quark-rules/').expanduser())
    report_file = apk_path.parent.joinpath('SecScan/quark.json')

    report = Report()
    report.analysis(apk_path, rule_path)
    json_report = report.get_report("json")
    with open(report_file, 'w+') as f:
        f.write(json.dumps(json_report, indent=4))


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************** apk_quark.py ********************')

    success_num = 0
    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        print(f'[+] [quark] {apk}')
        apk_path = Path(apk)

        report_path = apk_path.parent.joinpath('SecScan')
        if not report_path.exists():
            report_path.mkdir()

        analysis(apk_path)
        success_num += 1

    print(f'扫描完成: {success_num}')
