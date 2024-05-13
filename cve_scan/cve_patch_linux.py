#!/usr/bin/python3

import sys
import json
import pyfiglet
import argparse

from tqdm import tqdm
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from cve_utils import *
sys.path.append('..')
from utils import *


# 在扫描时排除的漏洞
CVE_EXCLUDE = {
    
}

# https://kernel.org/category/releases.html
KERNEL_VERSION = {
    # LTS
    '4.14': 'bebc6082da0a9f5d47a1ea2edc099bf671058bd4',
    '4.19': '84df9525b0c27f3ebc2ebb1864fa62a97fdedb7d',
    '5.4': '219d54332a09e8d8741c1e1982f5eae56099de85',
    '5.10': '2c85ebc57b3e1817b6ce1a6b703928e113a90442',
    '5.15': '8bb7eca972ad531c9b149c0a51ab43a417385813',
    '6.1': '830b3c68c1fb1e9176028d02ef86f3cf76aa2476',
    '6.6': 'ffc253263a1375a65fa6c9f62a893e9767fbebfa',

    # others
    '4.4': 'afd2ff9b7e1b367172f18ba7f693dfb62bdcb2dc',
    '4.9': '69973b830859bc6529a7a0468ba0d80ee5117826',
    '5.4.147': '48a24510c328b3b3d7775377494b4ad4f58d189a',
    '5.11': 'f40ddce88593482919761f74910f42f4b84c004b',
    '5.12': '9f4ad9e425a1d3b6a34617b8ea226d56a119a717',
    '5.13': '62fb9874f5da54fdb243003b386128037319b219',
    '5.14': '7d2a07b769330c34b4deabeed939325c77a7ec2f',
    '5.15.104': '115472395b0a9ea522ba0e106d6dfd7a73df8ba6',
    '5.16': 'df0cc57e057f18e44dac8e6c18aba47ab53202f9',
}


def format_version(version: str):
    version_list = version.split('-')[0].split('.')                 # 5.4-rc1 -> 5.4
    version_list.append('0') if len(version_list) == 2 else None    # 5.4 -> 5.4.0
    return version_list


def update(args):
    """更新CVE补丁库"""
    def update_cves_data(cve_data):
        cvss = cvssVector = severity = None
        if 'cvss3' in cve_data:
            cvss = float(cve_data['cvss3']['score'])
            cvssVector = cve_data['cvss3'].get('raw')
            severity = get_severity(cvss)
        elif 'cvss2' in cve_data:
            cvss = float(cve_data['cvss2']['score'])
            cvssVector = cve_data['cvss2'].get('raw')
            severity = get_severity(cvss, version=2)
        cve_data['cvss'] = cvss
        cve_data['cvssVector'] = cvssVector
        cve_data['severity'] = severity

        for key in ['cvss3', 'cvss2', 'ref_urls']:
            cve_data.pop(key, None)

        return cve_data

    if cves_path.exists():
        output, ret_code = shell_cmd('git pull', env={'cwd': cves_path})
    else:
        output, ret_code = shell_cmd(f'git clone --depth=1 https://github.com/nluedtke/linux_kernel_cves.git {cves_path}')
    if ret_code != 0:
        print_failed(f'Update linux_kernel_cves Error: {output}')
        return False
    print_success(f'Update linux_kernel_cves: {cves_path}')

    stream_fixes = json.load(open(cves_path.joinpath('data/stream_fixes.json')))
    cves_data = json.load(open(cves_path.joinpath('data/kernel_cves.json')))
    new_cves_data = {version: {}}

    version1 = format_version(version)
    tasks = []
    executor = ThreadPoolExecutor(10)#os.cpu_count()-1)
    for cve_id, value in stream_fixes.items():
        for version2, commit in value.items():
            cmt_id = commit['cmt_id']
            fixed_version = format_version(commit['fixed_version'])
            # 筛选对应版本漏洞
            if '.'.join(version1[:2]) != version2:
                continue
            if int(version1[-1]) > int(fixed_version[-1]):
                continue

            # 去掉被撤回的漏洞
            cve_data = update_cves_data(cves_data[cve_id])
            cve_data['cve_id'] = cve_id
            cve_data['url'] = f'{base_url}/commit/?h=linux-{version2}.y&id={cmt_id}'
            cve_data['fixes'] = [f'{base_url}/patch/?id={cmt_id}']
            if cve_data.get('rejected', False) is True:
                continue

            # 更新cves_data
            new_cves_data[version][cve_id] = cve_data

            # 下载补丁
            tasks.append(executor.submit(patcher.download_and_write_patches, version, cve_data))

    with tqdm(total=len(tasks)) as pbar:
        for _ in as_completed(tasks):
            pbar.update()

    patcher.write_sec_data(new_cves_data)


def format(args):
    """为仓库生成补丁"""
    # 生成补丁
    commit = args.commit or KERNEL_VERSION[version]
    target_path = patcher.patch_all_path.joinpath(version)
    patcher.gen_patches_one_repo(repo_path, target_path, commit)

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
    parser_update.add_argument('--version', help='Kernel version number', type=str, required=True)
    parser_update.set_defaults(func=update)

    parser_format = subparsers.add_parser('format', help='format local patch data')
    parser_format.add_argument('--repo', help='Kernel git repository path', type=str, required=True)
    parser_format.add_argument('--version', help='Kernel version number', type=str, required=True)
    parser_format.add_argument('--commit', help='Kernel git commit id', type=str, default=None)
    parser_format.set_defaults(func=format)

    parser_scan = subparsers.add_parser('scan', help='scan CVE patch data')
    parser_scan.add_argument('--version', help='Kernel version number', type=str, required=True)
    parser_scan.add_argument('--strict', help='Strict mode', action='store_true', default=False)
    parser_scan.set_defaults(func=scan)

    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('cve_patch_linux'))
    base_url = 'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git'
    cves_path = Path(__file__).absolute().parents[1].joinpath('tools/linux_kernel_cves')
    report_path = Path(__file__).absolute().parents[1].joinpath('data/SecScan')
    report_path.mkdir(parents=True, exist_ok=True)

    args = argument()
    version = args.version
    strict_mode = getattr(args, 'strict', False)
    repo_path = Path(getattr(args, 'repo', '')).expanduser().absolute()

    patcher = Patcher(
        'linux', report_path,
        version, repo_path, strict_mode,
        CVE_EXCLUDE
    )

    # 第一步：更新CVE补丁库
    if args.func.__name__ == 'update':
        pass

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
