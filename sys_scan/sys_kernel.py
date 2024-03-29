#!/usr/bin/python3

import sys
import json
import pyfiglet
import argparse
from pathlib import Path

sys.path.append('..')
from utils import *


def analysis(config_path: Path, report_path: Path):
    report_file = report_path.joinpath('sys_kernel.json')
    output, ret_code = shell_cmd(f'kconfig-hardened-check -m json -c {config_path}')
    with open(report_file, 'w+') as f:
        json.dump(json.loads(output), f, indent=4)
        print_success(f'Results saved in {report_file}')


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='Kernel kconfig file', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('sys_kernel'))
    config_path = Path(argument().config).expanduser().absolute()
    report_path = Path(__file__).absolute().parents[1].joinpath('data/SecScan')
    report_path.mkdir(parents=True, exist_ok=True)

    analysis(config_path, report_path)
