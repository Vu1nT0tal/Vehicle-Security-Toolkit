#!/usr/bin/python3

import argparse
from pathlib import Path
from utils import shell_cmd


def analysis(apk_path: Path):
    print(f'[+] {apk_path}')
    report_file = apk_path.parent.joinpath(f'{apk_path.stem}-androbugs.txt')

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
    parser.add_argument("--config", help="A config file containing APK path", type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('****************** apk-androbugs.py ******************')

    failed = []
    success_num = 0
    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        ret = analysis(Path(apk).absolute())
        if ret == 0:
            success_num += 1
        else:
            failed.append(apk)

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
