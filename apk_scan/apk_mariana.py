#!/usr/bin/python3

import sys
import shutil
import argparse
import tempfile
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


def analysis(apk_path: Path):
    source_dir = apk_path.parent.joinpath('jadx_java/sources')
    report_file = apk_path.parent.joinpath('SecScan/mariana.db')
    tmp_dir = tempfile.mkdtemp()

    cmd = f'mariana-trench --system-jar-configuration-path `find ~/Android/Sdk -name "android.jar" | head -n1` \
        --apk-path {apk_path} --source-root-directory {source_dir} --output-directory {tmp_dir}'
    output, ret_code = shell_cmd(cmd)
    if ret_code != 0:
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)
        shutil.rmtree(tmp_dir)
        return ret_code

    cmd = f'sapp --tool mariana-trench --database-name {report_file} analyze {tmp_dir}'
    output, ret_code = shell_cmd(cmd)
    if ret_code != 0:
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    shutil.rmtree(tmp_dir)
    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************* apk_mariana.py *******************')
    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        Color.print_focus(f'[+] [mariana] {apk}')
        apk_path = Path(apk)

        report_path = apk_path.parent.joinpath('SecScan')
        if not report_path.exists():
            report_path.mkdir()

        ret = analysis(apk_path)
        if ret:
            Color.print_failed('[-] [mariana] failed')
        else:
            Color.print_success('[+] [mariana] success')

    print('查看报告：sapp --database-name {sample-mariana.db} server --source-directory {jadx_java/sources}')
