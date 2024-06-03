#!/usr/bin/python3

import sys
import pyfiglet
import argparse

from pathlib import Path

from cve_utils import *
sys.path.append('..')
from utils import *


# 在扫描时排除的漏洞
CVE_EXCLUDE = {
    'uboot': [],
}

# 手动指定commit
CVE_COMMIT = {
    
}


def update(args):
    """更新CVE补丁库"""
    items = search_cve('cpe:2.3:a:denx:u-boot')
    cves_data[version] = items
    for cve_data in items.values():
        print(cve_data)
        patcher.download_and_write_patches(version, cve_data)

    patcher.write_sec_data(cves_data)


def format(args):
    """为仓库生成补丁"""
    # 生成补丁
    target_path = patcher.patch_all_path.joinpath(version)
    patcher.gen_patches_one_repo(repo_path, target_path, args.commit)

    # 处理生成的补丁
    patcher.process_patches()


def scan(args):
    """对比所有CVE补丁与所有补丁"""
    patches = patcher.patch_sec_path.joinpath(version).glob('*.diff')
    patcher.scan_patches(patches, patcher.scanThread)


def argument():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_update = subparsers.add_parser('update', help='update CVE patch data')
    parser_update.set_defaults(func=update)

    parser_format = subparsers.add_parser('format', help='format local patch data')
    parser_format.add_argument('--repo', help='U-Boot git repository path', type=str, required=True)
    parser_format.add_argument('--commit', help='U-Boot git commit id', type=str, default=None)
    parser_format.set_defaults(func=format)

    parser_scan = subparsers.add_parser('scan', help='scan CVE patch data')
    parser_scan.add_argument('--strict', help='Strict mode', action='store_true', default=False)
    parser_scan.set_defaults(func=scan)

    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('cve_patch_uboot'))
    report_path = Path(__file__).absolute().parents[1].joinpath('data/SecScan')
    report_path.mkdir(parents=True, exist_ok=True)

    args = argument()
    version = 'uboot'
    strict_mode = getattr(args, 'strict', False)
    repo_path = Path(getattr(args, 'repo', '')).expanduser().absolute()

    patcher = Patcher(
        'uboot', report_path,
        version, repo_path, strict_mode,
        CVE_EXCLUDE
    )

    # 第一步：更新CVE补丁库
    if args.func.__name__ == 'update':
        cves_data = {}

    # 第二步：为仓库生成补丁
    elif args.func.__name__ == 'format':
        if not patcher.sec_cves.exists():
            print_failed('Please update first')
            sys.exit(1)

    # 第三步：对比所有CVE补丁与所有补丁
    elif args.func.__name__ == 'scan':
        if not patcher.all_patches.exists():
            print_failed('Please format first')
            sys.exit(1)

    args.func(args)
