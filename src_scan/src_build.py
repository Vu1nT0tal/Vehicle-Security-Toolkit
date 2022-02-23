#!/usr/bin/python3

import sys
import json
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


env = {
    'ANDROID_HOME': Path('~').expanduser().joinpath('Android/Sdk'),
    'ANDROID_SDK_ROOT': Path('~').expanduser().joinpath('Android/Sdk'),
}


def gradlew(src_path: Path, java: int, clean: bool=False):
    """gradlew 编译"""

    report_path = src_path.joinpath('build.error')
    local_env = env.copy()
    local_env.update({'cwd': src_path, 'java': java})

    cmd = 'chmod +x gradlew && ./gradlew clean' if clean else 'chmod +x gradlew && ./gradlew clean build'
    output, ret_code = shell_cmd(cmd, local_env)
    if ret_code != 0:
        with open(report_path, 'w+') as f:
            f.write(output)
    return ret_code


def gradle(src_path: Path, java: int, gradle: int, clean: bool=False):
    """gradle 编译"""

    report_path = src_path.joinpath('build.error')
    local_env = env.copy()
    local_env.update({'cwd': src_path, 'java': java, 'gradle': gradle})

    cmd = 'gradle clean' if clean else 'gradle clean build'
    output, ret_code = shell_cmd(cmd, local_env)
    if ret_code != 0:
        with open(report_path, 'w+') as f:
            f.write(output)
    return ret_code


def make(src_path: Path, java: int, clean: bool=False):
    """Android.mk 编译"""

    report_path = src_path.joinpath('build.error')
    local_env = env.copy()
    local_env.update({'cwd': src_path, 'java': java})

    cmd = 'make clean' if clean else 'make'
    output, ret_code = shell_cmd(cmd, local_env)
    if ret_code != 0:
        with open(report_path, 'w+') as f:
            f.write(output)
    return ret_code


def build(src_path: Path, item: dict, clean: bool=False):
    if item['build'] == 'gradlew':
        ret = gradlew(src_path, item['java'], clean)
    elif item['build'] == 'gradle':
        ret = gradle(src_path, item['java'], item['gradle'], clean)
    elif item['build'] == 'make':
        ret = make(src_path, item['java'], clean)
    else:
        ret = 1
    return ret


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing source code path', type=str, required=True)
    parser.add_argument("--build_config", help="A build config file", type=str, required=True)
    parser.add_argument("--clean", help="Clean all file above", action='store_true')
    return parser.parse_args()


if __name__ == '__main__':
    print('******************** src_build.py ********************')
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')

    args = argument()
    src_dirs = open(args.config, 'r').read().splitlines()
    with open(args.build_config, 'r') as f:
        build_config = json.load(f)

    for src in src_dirs:
        Color.print_focus(f'[+] [build] {src}')
        src_path = Path(src)
        item = build_config.get(src_path.name)
        if item:
            ret = build(src_path, item, args.clean)
            if ret:
                Color.print_failed('[-] [build] failed')
            else:
                Color.print_success('[+] [build] success')
        else:
            Color.print_focus(f'[-] [build] 发现新APK：{src}')
