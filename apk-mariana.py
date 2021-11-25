#!/usr/bin/python3

import shutil
import argparse
import tempfile
from pathlib import Path
from utils import shell_cmd_ret_code


def analysis(apk_path: Path):
    print(f'[+] {apk_path}')
    source_dir = apk_path.parent.joinpath('jadx_java/sources')
    report_file = apk_path.parent.joinpath(f'{apk_path.stem}-mariana.db')
    tmp_dir = tempfile.mkdtemp()

    cmd = f'mariana-trench --system-jar-configuration-path `find ~ -name "android.jar" | grep Sdk` \
        --apk-path {apk_path} --source-root-directory {source_dir} --output-directory {tmp_dir}'
    output, ret_code = shell_cmd_ret_code(cmd)

    cmd = f'sapp --tool mariana-trench --database-name {report_file} analyze {tmp_dir}'
    output, ret_code = shell_cmd_ret_code(cmd)

    if not report_file.exists():
        with open(str(report_file)+'.error', 'w+') as f:
            f.write(output)

    shutil.rmtree(tmp_dir)
    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", help="A directory containing APK to run static analysis", type=str, required=True)
    arg = parser.parse_args()
    return arg


if __name__ == '__main__':
    print('******************* apk-mariana.py *******************')

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
        print('[!] 参数错误: python3 apk-mariana.py --help')

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
    print('查看报告：sapp --database-name {sample-mariana.db} server --source-directory {jadx_java/sources}')
