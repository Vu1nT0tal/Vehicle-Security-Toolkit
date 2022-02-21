#!/usr/bin/python3

import os
import shutil
import argparse
from pathlib import Path


def apktool(apk_path: Path, tools_path: Path):
    apktool_jar = tools_path.joinpath('apktool.jar')
    output = apk_path.parent.joinpath('apktool_smali')
    cmd = f'java -jar {apktool_jar} d {apk_path} -f -o {output} > /dev/null'
    os.system(cmd)


def jadx(apk_path: Path, tools_path: Path):
    jadx_bin = tools_path.joinpath('jadx/bin/jadx')
    output = apk_path.parent.joinpath('jadx_java')
    cmd = f'{jadx_bin} {apk_path} -q -d {output} > /dev/null'
    os.system(cmd)


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    parser.add_argument("--apktool", help="Use apktool get smali", action='store_true')
    parser.add_argument("--jadx", help="Use jadx get java", action='store_true')
    parser.add_argument("--clean", help="Clean all file above", action='store_true')
    return parser.parse_args()


if __name__ == '__main__':
    print('****************** apk_decompile.py ******************')
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')

    args = argument()
    apk_dirs = open(args.config, 'r').read().splitlines()

    for apk in apk_dirs:
        print(f'[+] [decompile] {apk}')
        apk_path = Path(apk)

        if args.clean:
            shutil.rmtree(apk_path.parent.joinpath('apktool_smali'), ignore_errors=True)
            shutil.rmtree(apk_path.parent.joinpath('jadx_java'), ignore_errors=True)
        else:
            if args.apktool:
                apktool(apk_path, tools_path)
            if args.jadx:
                jadx(apk_path, tools_path)
