#!/usr/bin/python3

import sys
import argparse
import pyfiglet

sys.path.append('..')
from utils import *


def update(args=None):
    """更新规则库"""
    # output, ret_code = shell_cmd('cvehound_update_metadata')
    # if ret_code == 0:
    #     print_success('[update_metadata] success')
    # else:
    #     print_failed('[update_metadata] failed')

    output, ret_code = shell_cmd('cvehound_update_rules')
    if ret_code == 0:
        print_success('[update_rules] success')
    else:
        print_failed('[update_rules] failed')


def scan(args):
    """扫描未修复CVE"""
    cmd = f'cvehound --kernel {args.repo} --kernel-config --cve assigned --report {report_file} --verbose'
    print(cmd)
    output, ret_code = shell_cmd(cmd)
    if ret_code == 0:
        print_success('[cvehound] success')
        print_success(f'Results saved in {report_file}')
    else:
        print_failed('[cvehound] failed')


def argument():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_update = subparsers.add_parser('update', help='update CVE rules and metadata')
    parser_update.set_defaults(func=update)

    parser_scan = subparsers.add_parser('scan', help='scan CVE in kernel repository')
    parser_scan.add_argument('--repo', help='kernel git repository path', type=str, required=True)
    parser_scan.set_defaults(func=scan)

    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('cve_source_linux'))
    report_path = Path(__file__).absolute().parents[1].joinpath('data/SecScan')
    report_path.mkdir(parents=True, exist_ok=True)
    report_file = report_path.joinpath('cve_source_linux.json')

    args = argument()
    if args.func.__name__ == 'scan':
        repo_path = Path(args.repo).expanduser().absolute()

    args.func(args)
