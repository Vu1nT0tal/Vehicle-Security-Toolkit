#!/usr/bin/python3

import json
import pyfiglet
import argparse
from pathlib import Path
from collections import defaultdict

from utils import Color
from src_scan.src_build import build, build2
from src_scan.src_fireline import analysis as fireline
from src_scan.src_mobsf import analysis as mobsf
from src_scan.src_qark import analysis as qark
from src_scan.src_speck import analysis as speck
from src_scan.src_keyfinder import analysis as keyfinder
from src_scan.src_depcheck import analysis as depcheck
from src_scan.src_sonarqube import analysis as sonarqube
from src_scan.src_sonarqube import init_sonarqube, create_project

# 配置项
sonarqube_key = ''
env = {
    'ANDROID_HOME': Path('~').expanduser().joinpath('Android/Sdk'),
    'ANDROID_SDK_ROOT': Path('~').expanduser().joinpath('Android/Sdk'),
}


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing source code path', type=str, required=True)
    parser.add_argument("--build_config", help="A build config file", type=str, required=False)
    parser.add_argument('--build', help='Build the APK before analysis', action='store_true')
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('src-allinone_java'))
    args = argument()
    tools_path = Path(__file__).absolute().parent.joinpath('tools')

    plugin = {
        # 必选插件
        'build': defaultdict(list),

        # 可选插件
        'fireline': defaultdict(list),
        'mobsf': defaultdict(list),
        'qark': defaultdict(list),
        'speck': defaultdict(list),
        'keyfinder': defaultdict(list),
        'depcheck': defaultdict(list),
        'sonarqube': defaultdict(list)
    }
    src_dirs = open(args.config, 'r').read().splitlines()
    if args.build_config:
        with open(args.build_config, 'r') as f:
            build_config = json.load(f)
    else:
        build_config = {}

    for src in src_dirs:
        Color.print_focus(f'[+] {src}')

        src_path = Path(src)
        report_path = src_path.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        # src_build
        if args.build:
            print(f'[+] Building ...')
            item = build_config.get(src_path.name)
            if item:
                ret = build(src_path, item)
                if ret:
                    plugin['build']['faild'].append(src)
                    Color.print_failed('[-] [build] faild')
                else:
                    plugin['build']['success'].append(src)
                    Color.print_success('[+] [build] success')
            else:
                Color.print_focus(f'[-] [build] 发现新APK：{src}')
                ret, _, data = build2(src_path)
                if ret:
                    plugin['build']['faild'].append(src)
                    Color.print_failed('[-] [build2] failed')
                else:
                    plugin['build']['success'].append(src)
                    Color.print_success(f'[+] [build2] success java:{data.get("java")} gradle:{data.get("gradle")}')

        # src_fireline
        if 'fireline' in plugin:
            ret = fireline(src_path, tools_path)
            if ret:
                plugin['fireline']['failed'].append(src)
                Color.print_failed('[-] [fireline] failed')
            else:
                plugin['fireline']['success'].append(src)
                Color.print_success('[+] [fireline] success')

        # src_mobsf
        if 'mobsf' in plugin:
            ret = mobsf(src_path)
            if ret:
                plugin['mobsf']['failed'].append(src)
                Color.print_failed('[-] [mobsf] failed')
            else:
                plugin['mobsf']['success'].append(src)
                Color.print_success('[+] [mobsf] success')

        # src_qark
        if 'qark' in plugin:
            ret = qark(src_path, tools_path)
            if ret:
                plugin['qark']['failed'].append(src)
                Color.print_failed('[-] [qark] failed')
            else:
                plugin['qark']['success'].append(src)
                Color.print_success('[+] [qark] success')

        # src_speck
        if 'speck' in plugin:
            ret = speck(src_path, tools_path)
            if ret:
                plugin['speck']['failed'].append(src)
                Color.print_failed('[-] [speck] failed')
            else:
                plugin['speck']['success'].append(src)
                Color.print_success('[+] [speck] success')

        # src_keyfinder
        if 'keyfinder' in plugin:
            ret = keyfinder(src_path, tools_path)
            if ret:
                plugin['keyfinder']['failed'].append(src)
                Color.print_failed('[-] [keyfinder] failed')
            else:
                plugin['keyfinder']['success'].append(src)
                Color.print_success('[+] [keyfinder] success')

        # src_depcheck
        if 'depcheck' in plugin:
            if src_path.joinpath('gradlew').exists():
                ret = depcheck(src_path, tools_path, 'gradle')
            else:
                ret = depcheck(src_path, tools_path, 'cli')
            if ret:
                plugin['depcheck']['failed'].append(src)
                Color.print_failed('[-] [depcheck] failed')
            else:
                plugin['depcheck']['success'].append(src)
                Color.print_success('[-] [depcheck] success')

        # src_sonarqube
        if 'sonarqube' in plugin:
            sonar, sonarqube_key = init_sonarqube(sonarqube_key)
            if create_project(sonar):
                ret = sonarqube(src_path, 'cli', sonarqube_key)
                if ret:
                    plugin['sonarqube']['failed'].append(src)
                    Color.print_failed('[-] [sonarqube] failed')
                else:
                    plugin['sonarqube']['success'].append(src)
                    Color.print_success('[+] [sonarqube] success')
            else:
                Color.print_focus('[+] [sonarqube] pass')

    print(plugin)
