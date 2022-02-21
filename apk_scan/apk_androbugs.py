#!/usr/bin/python3

import sys
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd


def analysis(apk_path: Path):
    report_file = apk_path.parent.joinpath('SecScan/androbugs.txt')

    cmd = f'docker run --rm -v {apk_path.parent}:/apk danmx/docker-androbugs -f /apk/{apk_path.name} -o /tmp'
    output, ret_code = shell_cmd(cmd)

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
    print('****************** apk_androbugs.py ******************')

    failed = []
    success_num = 0
    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        print(f'[+] [androbugs] {apk}')
        apk_path = Path(apk)

        report_path = apk_path.parent.joinpath('SecScan')
        if not report_path.exists():
            report_path.mkdir()

        ret = analysis(apk_path)
        if ret:
            failed.append(apk)
        else:
            success_num += 1

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
