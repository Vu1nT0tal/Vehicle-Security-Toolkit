#!/usr/bin/python3

import json
import argparse
from pathlib import Path
from quark.report import Report

RULE_PATH = str(Path('~/.quark-engine/quark-rules/').expanduser())

def analysis(apk_path: Path):
    print(f'[+] {apk_path}')
    report_file = apk_path.parent.joinpath(f'{apk_path.stem}-quark.json')

    report = Report()
    report.analysis(apk_path, RULE_PATH)
    json_report = report.get_report("json")
    with open(report_file, 'w+') as f:
        f.write(json.dumps(json_report, indent=4))


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", help="A directory containing APK to run static analysis", type=str, required=True)
    arg = parser.parse_args()
    return arg


if __name__ == '__main__':
    print('******************** apk-quark.py ********************')

    success_num = 0
    apk_dir = argument().apk
    if apk_dir:
        for apk in Path(apk_dir).rglob('*.apk'):
            ret = analysis(apk)
            success_num += 1
    else:
        print('[!] 参数错误: python3 apk-quark.py --help')

    print(f'扫描完成: {success_num}')
