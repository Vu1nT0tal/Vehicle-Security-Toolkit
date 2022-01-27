#!/usr/bin/python3

import argparse
from pathlib import Path
from utils import shell_cmd_ret_code


def analysis(src_path: Path):
    print(f'[+] {src_path}')
    mobsf_file = src_path.joinpath('mobsf.json')

    cmd = f'docker run --rm -v {src_path}:/src opensecurity/mobsfscan --json -o /src/mobsf.json /src'
    output, ret_code = shell_cmd_ret_code(cmd)

    if mobsf_file.exists():
        return 0
    else:
        with open(f'{mobsf_file}.error', 'w+') as f:
            f.write(output)
        return 1


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="A config file containing source code paths to run analysis", type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************** src-mobsf.py ********************')

    failed = []
    success_num = 0
    config_file = argument().config
    if config_file:
        src_dirs = open(config_file, 'r').read().splitlines()

        for src in src_dirs:
            ret = analysis(Path(src))
            if ret == 0:
                success_num += 1
            else:
                failed.append(src)
    else:
        print('[!] 参数错误: python3 src-mobsf.py --help')

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
