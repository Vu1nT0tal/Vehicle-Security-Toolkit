#!/usr/bin/python3

import argparse
from pathlib import Path
from utils import shell_cmd


def analysis(src_path: Path, report: str = None):
    print(f'[+] {src_path}')

    report_type = 'html' if report is None else report
    report_file = secscan_path.joinpath(f'report.{report_type}')
    new_report_file = secscan_path.joinpath(f'qark.{report_type}')

    cmd = f'qark --java {src_path} --report-type {report_type} --report-path {secscan_path}'
    output, ret_code = shell_cmd(cmd)

    if report_file.exists():
        report_file.rename(new_report_file)
    else:
        with open(f'{new_report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="A config file containing APK path", type=str, required=True)
    parser.add_argument("--report", help="Type of report to generate [html|xml|json|csv]", type=str, required=False)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************** src-qark.py *********************')

    failed = []
    success_num = 0
    args = argument()
    src_dirs = open(args.config, 'r').read().splitlines()

    for src in src_dirs:
        src_path = Path(src)
        secscan_path = src_path.joinpath('SecScan')
        if not secscan_path.exists():
            secscan_path.mkdir()

        ret = analysis(src_path, args.report)
        if ret == 0:
            success_num += 1
        else:
            failed.append(src)

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
