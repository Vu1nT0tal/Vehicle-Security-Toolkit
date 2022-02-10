#!/usr/bin/python3

import json
import argparse
from pathlib import Path
from utils import shell_cmd_ret_code


def analysis(apk_path: Path):
    print(f'[+] {apk_path}')
    report_file = apk_path.parent.joinpath(f'{apk_path.stem}-id.json')

    cmd = f'apkid {apk_path} -j'
    output, ret_code = shell_cmd_ret_code(cmd)
    if ret_code == 0:
        with open(report_file, 'w+') as f:
            f.write(json.dumps(json.loads(output), indent=4))

    if not report_file.exists():
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", help="A directory containing APK to run static analysis", type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('********************* apk-id.py **********************')

    failed = []
    success_num = 0
    apk_dir = argument().apk

    for apk in Path(apk_dir).rglob('*.apk'):
        ret = analysis(apk)
        if ret == 0:
            success_num += 1
        else:
            failed.append(str(apk))

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
