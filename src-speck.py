#!/usr/bin/python3

import argparse
from pathlib import Path

from utils import shell_cmd


def analysis(src_path: Path, tools_path: Path):
    report_file = src_path.joinpath('SecScan/speck.txt')

    scanner = tools_path.joinpath('SPECK-main/server/Scan.py')
    cmd = f'python3 {scanner} -g -s {src_path} | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g"'
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
    print('******************** src-speck.py ********************')
    tools_path = Path(__file__).absolute().parent.joinpath('tools')

    failed = []
    success_num = 0
    src_dirs = open(argument().config, 'r').read().splitlines()

    for src in src_dirs:
        print(f'[+] [speck] {src}')
        src_path = Path(src)

        report_path = src_path.joinpath('SecScan')
        if not report_path.exists():
            report_path.mkdir()

        ret = analysis(src_path, tools_path)
        if ret:
            failed.append(src)
        else:
            success_num += 1

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
