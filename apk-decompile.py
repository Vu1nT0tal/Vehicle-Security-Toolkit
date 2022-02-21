#!/usr/bin/python3

import os
import shutil
import argparse
from pathlib import Path


def apktool(apk_path: Path):
    apktool_jar = Path(__file__).parent.joinpath('tools/apktool.jar')
    output = apk_path.parent.joinpath('apktool_smali')
    cmd = f'java -jar {apktool_jar} d {apk_path} -f -o {output}'
    os.system(cmd)
    print()


def jadx(apk_path: Path):
    jadx_bin = Path(__file__).parent.joinpath('tools/jadx/bin/jadx')
    output = apk_path.parent.joinpath('jadx_java')
    cmd = f'{jadx_bin} {apk_path} -q -d {output}'
    os.system(cmd)
    print()


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="A config file containing APK path", type=str, required=True)
    parser.add_argument("--apktool", help="Use apktool get smali", action='store_true')
    parser.add_argument("--jadx", help="Use jadx get java", action='store_true')
    parser.add_argument("--clean", help="Clean all file above", action='store_true')
    return parser.parse_args()


if __name__ == '__main__':
    print('****************** apk-decompile.py ******************')

    args = argument()
    apk_dirs = open(args.config, 'r').read().splitlines()

    for apk in apk_dirs:
        apk_path = Path(apk)
        if args.clean:
            shutil.rmtree(apk_path.parent.joinpath('apktool_smali'), ignore_errors=True)
            shutil.rmtree(apk_path.parent.joinpath('jadx_java'), ignore_errors=True)
            print('[+] 清理完成')
        else:
            if args.apktool:
                apktool(apk_path)
            if args.jadx:
                jadx(apk_path)
