#!/usr/bin/python3

import os
import shutil
import argparse
from pathlib import Path


def apktool(apk_path: Path):
    apktool_jar = Path(__file__).parent.joinpath('tools/apktool_2.5.0.jar')
    output = apk_path.parent.joinpath('apktool_smali')
    cmd = f'java -jar {apktool_jar} d {str(apk_path)} -f -o {output}'
    os.system(cmd)
    print()


def jadx(apk_path: Path):
    jadx_bin = Path(__file__).parent.joinpath('tools/jadx/bin/jadx')
    output = apk_path.parent.joinpath('jadx_java')
    cmd = f'{jadx_bin} {str(apk_path)} -q -d {output}'
    os.system(cmd)
    print()


def cleanup(target: Path):
    for smali in target.rglob('apktool_smali'):
        shutil.rmtree(smali, ignore_errors=True)
    for java in target.rglob('jadx_java'):
        shutil.rmtree(java, ignore_errors=True)
    print('[+] 清理完成')


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--apktool", help="Use apktool get smali", action='store_true')
    parser.add_argument("-j", "--jadx", help="Use jadx get java", action='store_true')
    parser.add_argument("-d", "--dir", help="Target directory", type=str, required=True)
    parser.add_argument("-c", "--clean", help="Clean all file above", action='store_true')
    arg = parser.parse_args()
    return arg


if __name__ == '__main__':
    print('****************** apk-decompile.py ******************')
    args = argument()
    target = Path(args.dir)

    if args.clean:
        cleanup(target)
    else:
        for apk in target.rglob('*.apk'):
            if args.apktool:
                apktool(apk)
            if args.jadx:
                jadx(apk)
