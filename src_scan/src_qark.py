#!/usr/bin/python3

import sys
import pyfiglet
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


def analysis(src_path: Path, tools_path: Path, report_type: str=None):
    report_type = 'html' if report_type is None else report_type
    report_file = src_path.joinpath(f'report.{report_type}')
    new_report_file = src_path.joinpath(f'SecScan/qark.{report_type}')

    scanner = tools_path.joinpath('qark-env/bin/qark')
    cmd = f'{scanner} --java {src_path} --report-type {report_type} --report-path {src_path}'
    output, ret_code = shell_cmd(cmd)

    if report_file.exists():
        report_file.rename(new_report_file)
    else:
        with open(f'{new_report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing source code path', type=str, required=True)
    parser.add_argument('--report', help='Type of report to generate [html|xml|json|csv]', type=str, required=False)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('src_qark'))
    tools_path = Path(__file__).absolute().parent.joinpath('tools')

    args = argument()
    src_dirs = open(args.config, 'r').read().splitlines()

    for src in src_dirs:
        Color.print_focus(f'[+] [qark] {src}')
        src_path = Path(src)

        report_path = src_path.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        ret = analysis(src_path, args.report)
        if ret:
            Color.print_failed('[-] [qark] failed')
        else:
            Color.print_success('[+] [qark] success')
