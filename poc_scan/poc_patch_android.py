#!/usr/bin/python3

import sys
import requests
from pathlib import Path
from datetime import datetime

sys.path.append('..')
from utils import shell_cmd, Color


base_url = 'https://source.android.com/security/bulletin'


def get_latest_bulletin():
    current_time = datetime.now()
    r = requests.get(f'{base_url}/{ymd_to_date(current_time.year, current_time.month, 1)}')
    if r.status_code == 200:
        latest_date = ymd_to_date(current_time.year, current_time.month, 1)
    else:
        latest_date = find_last_bulletin_date(current_time.year, current_time.month, 1)

    return latest_date, f'{base_url}/{latest_date}'


def find_last_bulletin_date(year: int, month: int, day: int):
    if month == 1:
        year -= 1
        month = 12
    else:
        month -= 1
    r = requests.get(f'{base_url}/{ymd_to_date(year, month, day)}')
    if r.status_code == 200:
        new_date = ymd_to_date(year, month, day)
        return new_date
    else:
        return find_last_bulletin_date(year, month, day)


def ymd_to_date(year: int, month: int, day: int):
    req_month = f'0{month}' if 0 < month < 10 else month
    req_day = f'0{day}' if 0 < month < 10 else day
    return f'{year}-{req_month}-{req_day}'


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
    print('***************** poc_patch_android.py ****************')
    print(get_latest_bulletin())
