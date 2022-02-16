#!/usr/bin/python3

import argparse
from pathlib import Path
from utils import shell_cmd


def analysis(apk_path: Path):
    print(f'[+] {apk_path}')
    report_file = apk_path.parent.joinpath(f'{apk_path.stem}-scanner.txt')

    scanner = Path(__file__).parent.joinpath('tools/ApplicationScanner-main/AppScanner.py')
    cmd = f'python3 {scanner} -i {apk_path} > {report_file}'
    output, ret_code = shell_cmd(cmd)

    if not report_file.exists():
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", help="A directory containing APK to run static analysis", type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************* apk-scanner.py *******************')

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
