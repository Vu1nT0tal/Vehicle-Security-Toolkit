#!/usr/bin/python3

import re
import sys
import requests
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


base_url = 'https://www.qualcomm.com/company/product-security/bulletins'


def get_latest_bulletin():
    latest_date = ''
    r = requests.get(base_url)
    if r.status_code == 200:
        latest_date = re.findall('href="/company/product-security/bulletins/(.+?)-bulletin"', r.text)[0]
    return latest_date, f'{base_url}/{latest_date}-bulletin'


def argument():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_update = subparsers.add_parser('update', help='update CVE patch data')
    parser_update.set_defaults(func=update)

    parser_scan = subparsers.add_parser('scan', help='scan CVE patch in Android repository')
    parser_scan.add_argument('--repo', help='Android git repository path', type=str, required=True)
    parser_scan.add_argument('--version', help='Android version number', type=str, required=True)
    parser_scan.set_defaults(func=scan)

    return parser.parse_args()


if __name__ == '__main__':
    print('**************** poc_patch_qualcomm.py ****************')
    print(get_latest_bulletin())
