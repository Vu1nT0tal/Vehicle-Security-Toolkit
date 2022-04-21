#!/usr/bin/python3

import sys
import shutil
import pyfiglet
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


def apktool(apk_path: Path, tools_path: Path):
    apktool_jar = tools_path.joinpath('apktool.jar')
    output_path = apk_path.parent.joinpath('apktool_smali')
    cmd = f'java -jar {apktool_jar} d "{apk_path}" -f -o {output_path}'
    output, ret_code = shell_cmd(cmd)

    if output_path.joinpath('AndroidManifest.xml').exists():
        return 0
    print(output)
    return 1


def jadx(apk_path: Path, tools_path: Path):
    jadx_bin = tools_path.joinpath('jadx/bin/jadx')
    output_path = apk_path.parent.joinpath('jadx_java')
    cmd = f'{jadx_bin} "{apk_path}" -d {output_path}'
    output, ret_code = shell_cmd(cmd)
    apk_path.parent.joinpath(f'{apk_path.stem}.jobf').unlink(missing_ok=True)

    if output_path.joinpath('resources/AndroidManifest.xml').exists():
        return 0
    print(output)
    return 1


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    parser.add_argument("--apktool", help="Use apktool get smali", action='store_true')
    parser.add_argument("--jadx", help="Use jadx get java", action='store_true')
    parser.add_argument("--clean", help="Clean all file above", action='store_true')
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('apk_decompile'))
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')

    args = argument()
    apk_dirs = open(args.config, 'r').read().splitlines()

    for apk in apk_dirs:
        Color.print_focus(f'[+] [decompile] {apk}')
        apk_path = Path(apk)

        if args.clean:
            shutil.rmtree(apk_path.parent.joinpath('apktool_smali'), ignore_errors=True)
            shutil.rmtree(apk_path.parent.joinpath('jadx_java'), ignore_errors=True)
        else:
            ret = []
            if args.apktool:
                ret1 = apktool(apk_path, tools_path)
                ret.append(ret1)
            if args.jadx:
                ret2 = jadx(apk_path, tools_path)
                ret.append(ret2)

            if 1 in ret:
                Color.print_failed('[-] [decompile] failed')
            else:
                Color.print_success('[+] [decompile] success')
