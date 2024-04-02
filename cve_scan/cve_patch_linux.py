#!/usr/bin/python3

import os
import sys
import json
import requests
import pyfiglet
import argparse

from tqdm import tqdm
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

from cve_utils import *
sys.path.append('..')
from utils import *

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
    version = version.split('-')[0].split('.')          # 5.4-rc1 -> 5.4
    version.append('0') if len(version) == 2 else None  # 5.4 -> 5.4.0
    return version


def update(args):
    """更新CVE补丁库"""
    def updateThread(url: str, patch: Path):
        """更新线程"""
        try:
            patch_data = requests.get(url, headers=requests_headers).text
            meta, diff = parse_patch(patch_data)
            with open(patch.with_suffix('.meta'), 'w+') as f:
                f.write(meta)
            with open(patch.with_suffix('.diff'), 'w+') as f:
                f.write(diff)
        except Exception as e:
            print_failed(f'Download failed: {url}\n{patch}')
            print(e)

    version1 = format_version(args.version) if args.version else None
    print_focus(f'Update version: {version1}')

    if cves_path.exists():
        output, ret_code = shell_cmd('git pull', env={'cwd': cves_path})
    else:
        output, ret_code = shell_cmd(f'git clone --depth=1 https://github.com/nluedtke/linux_kernel_cves.git {cves_path}')
    if ret_code != 0:
        print_failed(f'Update linux_kernel_cves Error: {output}')
        return False
    print_success(f'Update linux_kernel_cves: {cves_path}')

    stream_fixes = json.load(open(cves_path.joinpath('data/stream_fixes.json')))
    tasks = []
    executor = ThreadPoolExecutor(10)#os.cpu_count()-1)
    for cve, value in stream_fixes.items():
        for version2, commit in value.items():
            if version1 and '.'.join(version1[:2]) != version2:
                continue

            patch_sec_path.joinpath(f'{version2}/{commit["fixed_version"]}').mkdir(parents=True, exist_ok=True)
            url = f'{base_url}/patch/?id={commit["cmt_id"]}'
            patch = patch_sec_path.joinpath(f'{version2}/{commit["fixed_version"]}/{cve}-{commit["cmt_id"]}.patch')
            tasks.append(executor.submit(updateThread, url, patch))

    with tqdm(total=len(tasks)) as pbar:
        for _ in as_completed(tasks):
            pbar.update()


def format(args):
    """为仓库生成补丁"""
    # 生成补丁
    commit = args.commit or KERNEL_VERSION[args.version]
    target_path = patch_all_path.joinpath(repo_name)
    cmd = f'git format-patch -N {commit} -o {target_path}'
    output, ret_code = shell_cmd(cmd, env={'cwd': repo_path})
    number, _ = shell_cmd(f'ls {target_path} | wc -l')
    if ret_code != 0:
        print_failed(f'Generate patches Error: {output}')
        return
    print_focus(f'Generate {number.strip()} patchs: {target_path}')

    # 处理生成的补丁
    results = process_patches(patch_all_path)

    with open(kernel_patches, 'w+') as f:
        json.dump(results, f, indent=4)
        print_success(f'Patches saved in {kernel_patches}')


def compareThread(cve_path: Path):
    """将某个CVE补丁与所有内核补丁进行比较"""
    cve_name = '-'.join(cve_path.stem.split('-')[:3])
    result = {
        'url': f'{base_url}/commit/?h=linux-{cve_path.parents[1].name}.y&id={cve_path.stem.split("-")[-1]}',
        'poc': get_poc(cve_name),
    }

    diff_data = open(cve_path).read()
    patch_data = open(cve_path.with_suffix('.patch')).read()

    ret_code = 0
    if patches := filter_patches(patch_all_path, repo_name, cve_name, diff_data, patches_data):
        scan_result = scan_patches(repo_name, cve_name, patches, diff_data, patch_data, args.strict)
        result['scan'] = scan_result
        if not scan_result:
            print_failed(f'{cve_name} not found!')
            ret_code = 2
    else:
        print_failed(f'{cve_name} Files not exists!')
        ret_code = 1

    return ret_code, cve_name, result


def scan(args):
    """对比所有CVE补丁与所有内核补丁"""
    patches = []
    version = format_version(args.version)
    for folder in patch_sec_path.joinpath('.'.join(version[:2])).glob('*'):
        folder_name = format_version(folder.name)
        if int(folder_name[-1]) > int(version[-1]):
            patches += folder.glob('*.diff')

    executor = ProcessPoolExecutor(os.cpu_count()-1)
    tasks = [executor.submit(compareThread, cve) for cve in patches]
    executor.shutdown(True)

    results = defaultdict(dict)
    for task in tasks:
        ret_code, cve_name, item = task.result()
        item.update(cves_data[cve_name])
        if item.get('rejected', False) is True:
            continue

        # 优先使用cvss3
        cvss = cvssVector = severity = None
        if 'cvss3' in item:
            cvss = item['cvss3']['score']
            cvssVector = item['cvss3']['raw']
            severity = get_severity(cvss)
        elif 'cvss2' in item:
            cvss = item['cvss2']['score']
            cvssVector = item['cvss2']['raw']
            severity = get_severity(cvss, version=2)
        item['cvss'] = cvss
        item['cvssVector'] = cvssVector
        item['severity'] = severity

        for key in ['cvss3', 'cvss2', 'ref_urls']:
            item.pop(key, None)

        result = {cve_name: item}
        if ret_code == 1:
            results['no_files'].update(result)
            continue

        if item['scan']:
            results['patched'].update(result)
        else:
            results['unpatched'].update(result)

    with open(report_file, 'w+') as f:
        json.dump(results, f, indent=4)
        print_success(f'Results saved in {report_file}')


def argument():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_update = subparsers.add_parser('update', help='update CVE patch data')
    parser_update.add_argument('--cves', help='linux_kernel_cves git repository path', type=str, default=cves_path)
    parser_update.add_argument('--version', help='kernel version number', type=str, default=None)
    parser_update.set_defaults(func=update)

    parser_format = subparsers.add_parser('format', help='format local patch data')
    parser_format.add_argument('--repo', help='kernel git repository path', type=str, required=True)
    parser_format.add_argument('--version', help='kernel version number', type=str, required=True)
    parser_format.add_argument('--commit', help='kernel commit id', type=str, default=None)
    parser_format.set_defaults(func=format)

    parser_scan = subparsers.add_parser('scan', help='scan CVE patch data')
    parser_scan.add_argument('--cves', help='linux_kernel_cves git repository path', type=str, default=cves_path)
    parser_scan.add_argument('--version', help='kernel version number', type=str, required=True)
    parser_scan.add_argument('--strict', help='Strict mode', action='store_true', default=False)
    parser_scan.set_defaults(func=scan)

    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('cve_patch_linux'))
    cves_path = '~/github/linux_kernel_cves'
    base_url = 'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git'
    repo_name = 'linux'

    report_path = Path(__file__).absolute().parents[1].joinpath('data/SecScan')
    report_path.mkdir(parents=True, exist_ok=True)
    report_file = report_path.joinpath('cve_patch_linux.json')
    patch_all_path = report_path.joinpath('patch_all_linux')
    patch_sec_path = report_path.joinpath('patch_sec_linux')
    kernel_patches = patch_all_path.joinpath('kernel_patches.json')

    args = argument()

    # 第一步：更新CVE补丁库
    if args.func.__name__ == 'update':
        cves_path = Path(args.cves).expanduser().absolute()

    # 第二步：为仓库生成补丁
    elif args.func.__name__ == 'format':
        if not patch_sec_path.exists():
            print_failed('Please update first')
            sys.exit(1)

        repo_path = Path(args.repo).expanduser().absolute()

    # 第三步：对比所有CVE补丁与所有补丁
    elif args.func.__name__ == 'scan':
        if not kernel_patches.exists():
            print_failed('Please format first')
            sys.exit(1)

        patches_data = json.load(open(kernel_patches))
        cves_path = Path(args.cves).expanduser().absolute()
        cves_data = json.load(open(cves_path.joinpath('data/kernel_cves.json')))

    args.func(args)
