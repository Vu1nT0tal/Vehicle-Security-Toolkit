#!/usr/bin/python3

import argparse
from pathlib import Path
from utils import shell_cmd


def analysis(apk_path: Path, report: str = None):
    print(f'[+] {apk_path}')

    report_type = 'html' if report is None else report
    report_file = apk_path.parent.joinpath(f'report.{report_type}')
    new_report_file = apk_path.parent.joinpath(f'{apk_path.stem}-qark.{report_type}')

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
    parser.add_argument("--config", help="A config file containing APK path", type=str, required=True)
    parser.add_argument("--report", help="Type of report to generate [html|xml|json|csv]", type=str, required=False)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************** apk-qark.py *********************')

    failed = []
    success_num = 0
    args = argument()
    apk_dirs = open(args.config, 'r').read().splitlines()

    for apk in apk_dirs:
        ret = analysis(Path(apk), args.report)
        if ret == 0:
            success_num += 1
        else:
            failed.append(apk)

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
