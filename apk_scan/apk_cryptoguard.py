#!/usr/bin/python3

import sys
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


def analysis(apk_path: Path,):
    report_file = apk_path.parent.joinpath('SecScan/cryptoguard.json')

    env = {'sdkman': '/home/runner/.sdkman/candidates'}
    cmd = f'docker run --rm -v {apk_path.parent}:/apk frantzme/cryptoguard $sdkman/java/current/bin/java -jar /Notebook/cryptoguard.jar \
            -android $sdkman/android/current -java $sdkman/java/7.0.322-zulu/ -in apk -s /apk/{apk_path.name} -o /apk/SecScan/cryptoguard.json -n'
    output, ret_code = shell_cmd(cmd, env)

    if not report_file.exists():
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('***************** apk_cryptoguard.py *****************')
    apk_dirs = open(argument().config, 'r').read().splitlines()

    for apk in apk_dirs:
        Color.print_focus(f'[+] [cryptoguard] {apk}')
        apk_path = Path(apk)

        report_path = apk_path.parent.joinpath('SecScan')
        if not report_path.exists():
            report_path.mkdir()

        ret = analysis(apk_path)
        if ret:
            Color.print_failed('[-] [cryptoguard] failed')
        else:
            Color.print_success('[+] [cryptoguard] success')
