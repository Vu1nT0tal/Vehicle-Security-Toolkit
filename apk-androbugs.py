#!/usr/bin/python3

import shutil
import argparse
from pathlib import Path
from subprocess import Popen, PIPE, STDOUT, TimeoutExpired


def shell_cmd_ret_code(cmd: str, timeout: int = None):
    """执行shell命令，返回元组 (output, ret_code)，其中output包括STDOUT和STDERR。"""
    pl = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
    try:
        output = pl.communicate(timeout=timeout)[0].decode('utf-8', errors='replace')
        ret_code = pl.returncode
    except TimeoutExpired:
        print('Execution timeout!')
        pl.kill()
        output = pl.communicate()[0].decode('utf-8', errors='replace')
        output += '\n\nERROR: execution timed out!'
        ret_code = 1
    return output, ret_code


def analysis(path: Path):
    print(f'[+] {path}')
    report_file = path.parent.joinpath(f'{path.stem}-androbugs.txt')

    cmd = f'docker run --rm -v {str(path.parent)}:/apk danmx/docker-androbugs -f /apk/{path.name} -o /tmp > {str(report_file)}'
    output, ret_code = shell_cmd_ret_code(cmd)

    if not report_file.exists():
        with open(str(report_file)+'.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", help="A directory containing APK to run static analysis", type=str, required=True)
    arg = parser.parse_args()
    return arg


if __name__ == '__main__':
    print('****************** apk-androbugs.py ******************')

    failed = []
    success_num = 0
    apk_dir = argument().apk
    if apk_dir:
        for apk in Path(apk_dir).rglob('*.apk'):
            ret = analysis(apk)
            if ret == 0:
                success_num += 1
            else:
                failed.append(str(apk))
    else:
        print('[!] 参数错误: python3 apk-androbugs.py --help')

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
