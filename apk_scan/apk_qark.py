#!/usr/bin/python3

import sys
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd


def analysis(apk_path: Path, report_type: str=None):
    report_type = 'html' if report_type is None else report_type
    report_file = apk_path.parent.joinpath(f'report.{report_type}')
    new_report_file = apk_path.parent.joinpath(f'SecScan/qark.{report_type}')

    cmd = f'qark --java {apk_path.parent.joinpath("jadx_java")} --report-type {report_type} --report-path {apk_path.parent}'
    output, ret_code = shell_cmd(cmd)

    if report_file.exists():
        report_file.rename(new_report_file)
    else:
        with open(f'{new_report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    parser.add_argument("--report", help="Type of report to generate [html|xml|json|csv]", type=str, required=False)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************** apk_qark.py *********************')

    failed = []
    success_num = 0
    args = argument()
    apk_dirs = open(args.config, 'r').read().splitlines()

    for apk in apk_dirs:
        print(f'[+] [qark] {apk}')
        apk_path = Path(apk)

        report_path = apk_path.parent.joinpath('SecScan')
        if not report_path.exists():
            report_path.mkdir()

        ret = analysis(apk_path, args.report)
        if ret:
            failed.append(apk)
        else:
            success_num += 1

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
