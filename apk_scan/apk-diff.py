#!/usr/bin/python3

import re
import sys
import pyfiglet
import argparse
import difflib
from filecmp import dircmp
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd


pwd = Path(__file__).parent
tools_path = Path(__file__).absolute().parents[1].joinpath('tools')
ignore_name = 'R\$|.*(align|apktool.yml|pak|MF|RSA|SF|bin|so)'
ignore_file = '.*(google|androidx|kotlin|apktool_smali/res|apktool_smali/original)'
count = 0
result = ''


def diff_apk(apk1, apk2):
    report_file = pwd.joinpath('diff_apk.txt')

    diffuse = tools_path.joinpath('diffuse.jar')
    cmd = f'java -jar {diffuse} diff {apk1} {apk2} --text {report_file}'
    output, ret_code = shell_cmd(cmd)

    if not report_file.exists():
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    print('[+] Diffing APKs -> diff_apk.txt')
    return ret_code


def diff_code(folder1, folder2):
    compared = dircmp(folder1, folder2)
    diff(compared)
    with open(pwd.joinpath('diff_smali.txt'), 'w+') as f:
        f.write(result)
    print(f'[+] Diffing smali -> diff_smali.txt\t{str(count)} files are different')


def diff(compared):
    for name in compared.diff_files:
        if not re.match(ignore_name, name) and not re.match(ignore_file, str(compared.left)):

            with open(f'{compared.left}/{name}', 'r', encoding='utf8', errors='ignore') as f:
                content1 = f.read().splitlines(True)
            with open(f'{compared.right}/{name}', 'r', encoding='utf8', errors='ignore') as f:
                content2 = f.read().splitlines(True)

            lines = []
            for line in difflib.unified_diff(content1, content2):
                line = line.strip()
                if line[:1] in ['+', '-'] and len(line) != 1 and line[:3] not in ['+++', '---'] \
                        and not re.match('.*(\.line\s\d|return-void)', line):
                    lines.append(line)
            if all('const' in i or '0x7f' in i for i in lines):
                continue

            global result, count
            result += f'[{name}] {compared.right}\n'+'\n'.join(lines)+'\n\n'
            count += 1

    for sd in compared.subdirs.values():
        diff(sd)


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('apk1', metavar='apk1', help='Location of the first APK.')
    parser.add_argument('apk2', metavar='apk2', help='Location of the second APK.')
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('apk-diff'))
    args = argument()

    diff_apk(args.apk1, args.apk2)

    smali1 = Path(args.apk1).parent.joinpath('apktool_smali')
    smali2 = Path(args.apk2).parent.joinpath('apktool_smali')
    diff_code(smali1, smali2)

    # java1 = Path(args.apk1).parent.joinpath('jadx_java')
    # java2 = Path(args.apk2).parent.joinpath('jadx_java')
    # diff_code(java1, java2)
