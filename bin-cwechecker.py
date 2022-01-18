#!/usr/bin/python3

import argparse
from pathlib import Path
from utils import shell_cmd_ret_code


def analysis(bin_path: Path):
    print(f'[+] {bin_path}')
    report_file = bin_path.parent.joinpath(f'{bin_path.stem}-cwechecker.txt')

    cmd = f'docker run --rm -v {bin_path}:/elf fkiecad/cwe_checker -q /elf'
    output, ret_code = shell_cmd_ret_code(cmd)

    if ret_code == 0:
        with open(report_file, 'w+') as f:
            f.write(output)
    else:
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", help="A directory containing bin files to run static analysis", type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('***************** bin-cwechecker.py ******************')

    failed = []
    success_num = 0
    bin_dir = argument().dir
    if bin_dir:
        cmd = 'find '+bin_dir+' -type f ! -path "*jadx_java*" \
            ! -regex ".*\(apk\|java\|smali\|dex\|xml\|yml\|json\|ini\|txt\|png\|jpg\|wav\|webp\|svg\|kcm\|version\|SF\|RSA\|MF\|data\|dat\|pak\|zip\|kotlin.*\|lifecycle.*\)$" \
            -exec file {} + | grep "ELF" | cut -d ":" -f 1'
        output, ret_code = shell_cmd_ret_code(cmd)
        elf_list = output.split('\n')[:-1]
        for elf in elf_list:
            ret = analysis(Path(elf).absolute())
            if ret == 0:
                success_num += 1
            else:
                failed.append(elf)
    else:
        print('[!] 参数错误: python3 bin-cwechecker.py --help')

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
