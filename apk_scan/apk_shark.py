#!/usr/bin/python3

import sys
import json
import shutil
import pyfiglet
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


def analysis(apk_path: Path, tools_path: Path):
    report_path = apk_path.parent.joinpath('SecScan/apkshark')
    report_path.mkdir(parents=True, exist_ok=True)

    config = {
        "apkPath": str(apk_path),
        "out": str(report_path),
        "rules": "ContentProviderPathTraversal.json,PendingIntentMutable.json,broadcastIMEI.json,logSerial.json,unZipSlip.json",
        "maxPointerAnalyzeTime": 600,
        "javaSource": True
    }
    config_file = report_path.joinpath('config.json5')
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)

    scanner = tools_path.joinpath('appshark-main/AppShark.jar')
    cmd = f'java -jar {scanner} {config_file}'
    output, ret_code = shell_cmd(cmd, env={'cwd': tools_path.joinpath('appshark-main')})

    shutil.rmtree(report_path.joinpath('java'))
    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('apk_shark'))
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')

    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        Color.print_focus(f'[+] [shark] {apk}')
        apk_path = Path(apk)

        if ret := analysis(apk_path, tools_path):
            Color.print_failed('[-] [shark] failed')
        else:
            Color.print_success('[+] [shark] success')
