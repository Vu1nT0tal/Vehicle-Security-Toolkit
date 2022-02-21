#!/usr/bin/python3

import argparse
from pathlib import Path
from utils import shell_cmd


def analysis(src_path: Path):
    print(f'[+] {src_path}')
    mobsf_file = secscan_path.joinpath('mobsf.json')

    cmd = f'docker run --rm -v {src_path}:/src opensecurity/mobsfscan --json -o /src/SecScan/mobsf.json /src'
    output, ret_code = shell_cmd(cmd)

    if mobsf_file.exists():
        return 0
    else:
        with open(f'{mobsf_file}.error', 'w+') as f:
            f.write(output)
        return 1


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="A config file containing source code path", type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************** src-mobsf.py ********************')

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
