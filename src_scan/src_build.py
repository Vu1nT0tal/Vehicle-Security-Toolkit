#!/usr/bin/python3

import re
import sys
import json
import pyfiglet
import argparse
from pathlib import Path

sys.path.append('..')
from utils import *

stop_flag = 0
env = {
    'ANDROID_HOME': Path('~').expanduser().joinpath('Android/Sdk'),
    'ANDROID_SDK_ROOT': Path('~').expanduser().joinpath('Android/Sdk'),
    'java': 11
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
    """有 build_config 输入时"""

    if item['build'] == 'gradlew':
        return gradlew(src_path, item['java'], clean)
    elif item['build'] == 'gradle':
        return gradle(src_path, item['java'], item['gradle'], clean)
    elif item['build'] == 'make':
        return make(src_path, item['java'], clean)
    else:
        return 1


def check_output(output: str, local_env: dict):
    """检查错误输出，返回正确的环境参数"""
    global stop_flag

    # gradle 版本低
    if 'Minimum supported Gradle version is 6' in output:
        local_env['gradle'] = 6
    elif 'Minimum supported Gradle version is 7' in output:
        local_env['gradle'] = 7

    elif 'No version of NDK matched' in output:
        ndk_version = ''
        for line in output.splitlines():
            if 'No version of NDK matched' in line:
                ndk_version = re.search(r'\d+\.(?:\d+\.)*\d+', line).group()

        if ndk_version:
            sdkmanager = Path('~').expanduser().joinpath('Android/Sdk/cmdline-tools/latest/bin/sdkmanager')
            cmd = f'{sdkmanager} --install "ndk;{ndk_version}'
            output, ret_code = shell_cmd(cmd, local_env)

    else:
        stop_flag += 1
        local_env['java'] = 8 if local_env['java'] == 11 else 11
    return local_env if stop_flag != 2 else None


def build2(src_path: Path, clean: bool=False, local_env: dict=env.copy()):
    """没有 build_config 输入时"""
    local_env['cwd'] = src_path
    print(local_env)

    if src_path.joinpath('gradlew').exists():
        cmd = 'chmod +x gradlew && ./gradlew clean' if clean else 'chmod +x gradlew && ./gradlew clean build'
    elif src_path.joinpath('build.gradle').exists():
        cmd = 'gradle clean' if clean else 'gradle clean build'
    else:
        print_focus('Android.mk')
    output, ret_code = shell_cmd(cmd, local_env)
    if ret_code != 0:
        local_env = check_output(output, local_env)
        if local_env:
            return build2(src_path, clean, local_env)

    return ret_code, clean, local_env


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing source code path', type=str, required=True)
    parser.add_argument("--build_config", help="A build config file", type=str, required=False)
    parser.add_argument("--clean", help="Clean all file above", action='store_true')
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('src_build'))
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')
    args = argument()
    src_dirs = open(args.config, 'r').read().splitlines()

    for src in src_dirs:
        print_focus(f'[build] {src}')
        src_path = Path(src)

        # 有build_config
        if args.build_config:
            with open(args.build_config, 'r') as f:
                build_config = json.load(f)
            if item := build_config.get(src_path.name):
                ret = build(src_path, item, args.clean)
                if ret:
                    print_failed('[build] failed')
                else:
                    print_success('[build] success')
                continue
            else:
                print_focus(f'[build] 发现新APK：{src}')

        # 没有build_config或发现新APK
        ret, _, data = build2(src_path, args.clean)
        if ret:
            print_failed('[build2] failed')
        else:
            print_success(f'[build2] success java:{data.get("java")} gradle:{data.get("gradle")}')
