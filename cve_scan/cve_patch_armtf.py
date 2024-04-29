#!/usr/bin/python3

import sys
import requests
import pyfiglet
import argparse

from pathlib import Path
from bs4 import BeautifulSoup

from cve_utils import *
sys.path.append('..')
from utils import *


# 在扫描时排除的漏洞
CVE_EXCLUDE = {
    'TF-A': [],
    'TF-M': [],
}

# 手动指定commit
CVE_COMMIT = {
    
}


def extract_tfa():
    """获取TF-A的漏洞"""
    base_url = 'https://trustedfirmware-a.readthedocs.io/en/latest/security_advisories'

    # 获取目录
    r = requests.get(f'{base_url}/index.html')
    soup = BeautifulSoup(r.content, 'html.parser')
    items = soup.find('div', class_='toctree-wrapper').find_all('a')
    urls = [f'{base_url}/{item["href"]}' for item in items]
    print(f'CVE Advisories: {len(urls)}')

    # 获取CVE信息
    results = {}
    for url in urls:
        print(url)
        item = {'advisory': url}

        r = requests.get(url)
        soup = BeautifulSoup(r.content, 'html.parser')
        table = soup.find('table', class_='docutils')

        thead_p = table.find('thead').find_all('p')
        item[thead_p[0].text.lower()] = thead_p[1].text

        tbody_tr = table.find('tbody').find_all('tr')
        for tr in tbody_tr:
            td = tr.find_all('td')
            key = td[0].text.replace('\n', ' ').replace(' ', '_').lower()            
            if key == 'fix_version':
                key = 'fixes'
                value = [a['href'] for a in td[1].find_all('a')]
            else:
                value = td[1].text.replace('\n', ' ')
                if value == 'CVE-2017-5753 / CVE-2017-5715 / CVE-2017-5754':
                    value = 'CVE-2017-5715'
            item[key] = value

        cve_id = item['cve_id']
        item.update(get_cve_detail(cve_id))
        results[cve_id] = item
        print(item)

    return results


def extract_tfm():
    """获取TF-M的漏洞"""
    base_url = 'https://trustedfirmware-m.readthedocs.io/en/latest/security/security_advisories'

    # # 获取目录
    # r = requests.get(f'{base_url}/index.html')
    # soup = BeautifulSoup(r.content, 'html.parser')
    # items = soup.find('div', class_='toctree-wrapper').find_all('a')
    # urls = [f'{base_url}/{item["href"]}' for item in items]
    # print(f'CVE Advisories: {len(urls)}')

    # # 获取CVE补丁
    results = {}
    # for url in urls:
    #     print(url)
    #     item = {'advisory': url}

    #     r = requests.get(url)
    #     soup = BeautifulSoup(r.content, 'html.parser')

    return results


def update(args):
    """更新CVE补丁库"""
    if version == 'TF-A':
        items = extract_tfa()
    elif version == 'TF-M':
        items = extract_tfm()

    cves_data[version] = items
    for cve_data in items.values():
        patcher.download_and_write_patches(version, cve_data)

    patcher.write_sec_data(cves_data)


def format(args):
    """为仓库生成补丁"""
    # 生成补丁
    target_path = patch_all_path.joinpath(version)
    patcher.gen_patches_one_repo(repo_path, target_path, args.commit)

    # 处理生成的补丁
    patcher.process_patches()


def scan(args):
    """对比所有CVE补丁与所有补丁"""
    patches = patch_sec_path.joinpath(version).glob('*.diff')
    patcher.scan_patches(patches, patcher.scanThread)


def argument():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_update = subparsers.add_parser('update', help='update CVE patch data')
    parser_update.add_argument('--version', help='Trusted Firmware name (TF-A/TF-B)', type=str, required=True)
    parser_update.set_defaults(func=update)

    parser_format = subparsers.add_parser('format', help='format local patch data')
    parser_format.add_argument('--repo', help='Trusted Firmware git repository path', type=str, required=True)
    parser_format.add_argument('--version', help='Trusted Firmware name (TF-A/TF-B)', type=str, required=True)
    parser_format.add_argument('--commit', help='Trusted Firmware git commit id', type=str, default=None)
    parser_format.set_defaults(func=format)

    parser_scan = subparsers.add_parser('scan', help='scan CVE patch data')
    parser_scan.add_argument('--version', help='Trusted Firmware name (TF-A/TF-B)', type=str, default=True)
    parser_scan.add_argument('--strict', help='Strict mode', action='store_true', default=False)
    parser_scan.set_defaults(func=scan)

    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('cve_patch_armtf'))
    report_path = Path(__file__).absolute().parents[1].joinpath('data/SecScan')
    report_path.mkdir(parents=True, exist_ok=True)
    report_file = report_path.joinpath('cve_patch_armtf.json')
    report_html = report_file.with_suffix('.html')
    patch_all_path = report_path.joinpath('patch_all_armtf')
    patch_sec_path = report_path.joinpath('patch_sec_armtf')
    all_patches = patch_all_path.joinpath('all_patches.json')
    sec_cves = patch_sec_path.joinpath('sec_cves.json')

    args = argument()
    version = args.version
    repo_path = Path(getattr(args, 'repo', '')).expanduser().absolute()
    strict_mode = getattr(args, 'strict', False)

    # 第一步：更新CVE补丁库
    if args.func.__name__ == 'update':
        cves_data = {}

    # 第二步：为仓库生成补丁
    elif args.func.__name__ == 'format':
        if not patch_sec_path.exists():
            print_failed('Please update first')
            sys.exit(1)

    # 第三步：对比所有CVE补丁与所有补丁
    elif args.func.__name__ == 'scan':
        if not all_patches.exists():
            print_failed('Please format first')
            sys.exit(1)

    patcher = Patcher(
        patch_all_path, patch_sec_path, report_file,
        version, repo_path, strict_mode,
        CVE_EXCLUDE
    )
    args.func(args)
