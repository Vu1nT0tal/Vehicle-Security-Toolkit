#!/usr/bin/python3

import sys
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd


def analysis(apk_path: Path, tools_path: Path):
    report_file = apk_path.parent.joinpath('SecScan/speck.txt')

    scanner = tools_path.joinpath('SPECK-main/server/Scan.py')
    cmd = f'python3 {scanner} -g -s {apk_path.parent.joinpath("jadx_java")} | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g"'
    output, ret_code = shell_cmd(cmd, {'cwd': scanner.parent})

    if ret_code == 0:
        with open(report_file, 'w+') as f:
            f.write(output)
    else:
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************** apk_speck.py ********************')
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')

    failed = []
    success_num = 0
    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        print(f'[+] [scanner] {apk}')
        apk_path = Path(apk)

        report_path = apk_path.parent.joinpath('SecScan')
        if not report_path.exists():
            report_path.mkdir()

        ret = analysis(apk_path, tools_path)
        if ret:
            failed.append(apk)
        else:
            success_num += 1

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
