#!/usr/bin/python3

import sys
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


def analysis(src_path: Path, report: str=None):
    report_type = 'html' if report is None else report
    report_file = src_path.joinpath(f'report.{report_type}')
    new_report_file = src_path.joinpath(f'SecScan/qark.{report_type}')

    cmd = f'qark --java {src_path} --report-type {report_type} --report-path {src_path}'
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
    parser.add_argument('--report', help='Type of report to generate [html|xml|json|csv]', type=str, required=False)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************** src_qark.py *********************')
    args = argument()
    src_dirs = open(args.config, 'r').read().splitlines()

    for src in src_dirs:
        Color.print_focus(f'[+] [qark] {src}')
        src_path = Path(src)

        report_path = src_path.joinpath('SecScan')
        if not report_path.exists():
            report_path.mkdir()

        ret = analysis(src_path, args.report)
        if ret:
            Color.print_failed('[-] [qark] failed')
        else:
            Color.print_success('[+] [qark] success')
