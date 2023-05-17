#!/usr/bin/python3

import sys
import shutil
import pyfiglet
import argparse
import tempfile
from pathlib import Path

sys.path.append('..')
from utils import *


def analysis(apk_path: Path, tools_path: Path):
    source_dir = apk_path.parent.joinpath('jadx_java/sources')
    report_file = apk_path.parent.joinpath('SecScan/mariana.db')
    tmp_dir = tempfile.mkdtemp()

    scanner = tools_path.joinpath('mariana-trench-env/bin/mariana-trench')
    cmd = f'{scanner} --system-jar-configuration-path `find ~/Android/Sdk -name "android.jar" | head -n1` \
        --apk-path {apk_path} --source-root-directory {source_dir} --output-directory {tmp_dir}'
    output, ret_code = shell_cmd(cmd)
    if ret_code != 0:
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return ret_code

    scanner = tools_path.joinpath('mariana-trench/bin/sapp')
    cmd = f'{scanner} --tool mariana-trench --database-name {report_file} analyze {tmp_dir}'
    output, ret_code = shell_cmd(cmd)
    if ret_code != 0:
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    shutil.rmtree(tmp_dir, ignore_errors=True)
    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('apk_mariana'))
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')
    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        print_focus(f'[mariana] {apk}')
        apk_path = Path(apk)

        report_path = apk_path.parent.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        if ret := analysis(apk_path, tools_path):
            print_failed('[mariana] failed')
        else:
            print_success('[mariana] success')

    print('查看报告：sapp --database-name {sample-mariana.db} server --source-directory {jadx_java/sources}')
