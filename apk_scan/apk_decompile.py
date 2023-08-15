#!/usr/bin/python3

import sys
import yaml
import shutil
import pyfiglet
import argparse
from pathlib import Path
import xml.etree.ElementTree as ET

sys.path.append('..')
from utils import *


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
    cmd = f'{jadx_bin} --deobf "{apk_path}" -d {output_path}'
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
        print_focus(f'[decompile] {apk}')
        apk_path = Path(apk)

        smali_path = apk_path.parent.joinpath('apktool_smali')
        java_path = apk_path.parent.joinpath('jadx_java')
        if args.clean:
            shutil.rmtree(smali_path, ignore_errors=True)
            shutil.rmtree(java_path, ignore_errors=True)
        else:
            ret = []
            if args.apktool:
                ret1 = apktool(apk_path, tools_path)
                ret.append(ret1)
            if args.jadx:
                ret2 = jadx(apk_path, tools_path)
                ret.append(ret2)

            if 1 in ret:
                print_failed('[decompile] failed')
            else:
                print_success('[decompile] success')

                if java_path.exists():
                    manifest_path = java_path.joinpath('resources/AndroidManifest.xml')
                    root = ET.parse(manifest_path).getroot()
                    namespace = '{http://schemas.android.com/apk/res/android}'

                    package = root.get('package')
                    versionName = root.get(f'{namespace}versionName')
                    versionCode = root.get(f'{namespace}versionCode')

                    uses_sdk = root.find('uses-sdk')
                    minSdkVersion = uses_sdk.get(f'{namespace}minSdkVersion')
                    targetSdkVersion = uses_sdk.get(f'{namespace}targetSdkVersion')

                elif smali_path.exists():
                    manifest_path = smali_path.joinpath('AndroidManifest.xml')
                    root = ET.parse(manifest_path).getroot()
                    package = root.get('package')

                    yml_path = smali_path.joinpath('apktool.yml')
                    yml_data = {}
                    if yml_path.exists():
                        data = yml_path.read_text().splitlines()[1:]
                        yml_data = yaml.safe_load('\n'.join(data))
                    versionName = yml_data.get('versionInfo', {}).get('versionName')
                    versionCode = yml_data.get('versionInfo', {}).get('versionCode')
                    minSdkVersion = yml_data.get('sdkInfo', {}).get('minSdkVersion')
                    targetSdkVersion = yml_data.get('sdkInfo', {}).get('targetSdkVersion')

                print(f'package:\t{package}\nversionName:\t{versionName}\nversionCode:\t{versionCode}\nminSdkVersion:\t{minSdkVersion}\ntargetSdkVersion:\t{targetSdkVersion}')
