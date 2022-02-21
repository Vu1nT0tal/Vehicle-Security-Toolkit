#!/usr/bin/python3

import shutil
import argparse
from pathlib import Path
from utils import shell_cmd


def analysis(src_path: Path):
    print(f'[+] {src_path}')
    report_dir = secscan_path.joinpath('fireline')
    if report_dir.exists():
        shutil.rmtree(report_dir, ignore_errors=True)
    report_dir.mkdir()

    fireline = Path(__file__).parent.joinpath('tools/fireline.jar')
    cmd = f'java -jar {fireline} -s {src_path} -r {report_dir}'
    output, ret_code = shell_cmd(cmd, {'java': 8})

    if ret_code != 0:
        with open(report_dir.joinpath('report.error'), 'w+') as f:
            f.write(output)
    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="A config file containing source code path", type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('****************** src-fireline.py *******************')

    failed = []
    success_num = 0
    src_dirs = open(argument().config, 'r').read().splitlines()

    for src in src_dirs:
        src_path = Path(src)
        secscan_path = src_path.joinpath('SecScan')
        if not secscan_path.exists():
            secscan_path.mkdir()

        ret = analysis(src_path)
        if ret == 0:
            success_num += 1
        else:
            failed.append(src)

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
