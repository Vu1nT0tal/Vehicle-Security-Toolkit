#!/usr/bin/python3

import sys
import asyncio
import calendar
import pyfiglet
import argparse

from pathlib import Path
from datetime import datetime
from bs4 import BeautifulSoup
from collections import defaultdict
from playwright.async_api import async_playwright

from cve_utils import *
sys.path.append('..')
from utils import *

# 在扫描时排除的漏洞
CVE_EXCLUDE = {
    'SA8155P': [

    ],
    'SA8295P': [],
}

# 排除部分仓库，提高速度
REPO_EXCLUDE = [

]

# 移动过位置的仓库
REPO_MIGRATE = {
    'SA8155P': {},
    'SA8295P': {},
}

# 最早和最晚时间
BULLETIN_TIME = {
    'SA8295P': ('2022-10', ''),
    'SA8155P': ('2020-09', ''),
}


def download_patches(cve_data: dict):
    cve_id = cve_data['cve_id']
    chips = cve_data['affected_chipsets']

    if not chips or version not in chips:
        print_failed(f'{cve_id} not in {version}')
        return

    # 更新cves_data
    cves_data[version][cve_id] = cve_data

    # 下载并保存补丁文件
    patcher.download_and_write_patches(version, cve_data)


def extract_section(soup, date_str):
    """解析表格"""
    items = []
    found = soup.find_next_siblings('h3', {'class': 'sectiontitle'})
    if not found:
        return items

    for cve in found:
        cve_data = {'date': date_str, 'fixes': []}
        tbody = cve.find_next('tbody')
        for tr in tbody.find_all('tr'):
            tds = tr.find_all('td')
            key = tds[0].text.strip().strip('*').replace(' ', '_').lower()
            if key == 'cvss_score':
                value = float(tds[1].text.strip())
            elif key == 'affected_chipsets':
                raw_value = [i.strip() for i in tds[1].text.split(',')]
                value = [chip for chip in BULLETIN_TIME.keys() if chip in raw_value]
            elif key == 'patch':
                key = 'fixes'
                value = [
                    format_qcom_url(a.text.strip())
                    for a in tds[1].find_all('a')
                    if 'www.qualcomm.com/support' not in a.text]
            else:
                raw_value = tds[1].text.strip()
                value = ' '.join(raw_value.split()) # 去掉多余的空格和换行符
            cve_data[key] = value
        cve_data['poc'] = get_poc(cve_data['cve_id'])
        items.append(cve_data)
        print(cve_data)

    return items


async def updateThread(sem, browser, url):
    """更新线程"""
    async with sem:
        print(url)
        date_str = url.split('/')[-1].split('.')[0]
        page = None
        try:
            page = await browser.new_page(locale='zh-CN')
            await page.goto(url, wait_until='networkidle', timeout=60000*5)
            soup = BeautifulSoup(await page.content(), 'html.parser')
            # propref = soup.find('h2', id='Propref')
            openref = soup.find('h2', id='Openref')

            # items = extract_section(propref, date_str)
            # for item in items:
            #     download_patches(item, 'propref')
            items = extract_section(openref, date_str)
            for item in items:
                download_patches(item)
        except Exception as e:
            print(f'Error occurred: {url}\n{e}')
        finally:
            await page.close() if page else None


async def update(args):
    """更新CVE补丁库"""
    start_date, end_date = BULLETIN_TIME[version]
    end_date = datetime.strptime(end_date, '%Y-%m') if end_date else datetime.now()
    start_date = datetime.strptime(start_date, '%Y-%m')

    base_url = 'https://docs.qualcomm.com/product/publicresources/securitybulletin'
    urls = []
    while start_date <= end_date:
        url = f'{base_url}/{calendar.month_name[start_date.month].lower()}-{start_date.year}-bulletin.html'
        urls.append(url)
        if start_date.month == 12:
            start_date = start_date.replace(year=start_date.year+1, month=1)
        else:
            start_date = start_date.replace(month=start_date.month+1)

    sem = asyncio.Semaphore(5)#os.cpu_count()-1)
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        await asyncio.gather(*(updateThread(sem, browser, url) for url in urls))
        await browser.close()

    patcher.write_sec_data(cves_data)


def format(args):
    """为所有仓库生成补丁"""
    # 获取所有本地仓库
    all_hmi = patcher.get_local_repos()

    # 安全补丁涉及的AOSP仓库
    fix_repos = patcher.get_fix_repos()

    # 安全补丁对应的本地仓库
    sec_hmi = patcher.get_sec_repos(all_hmi, fix_repos)

    # 生成补丁
    patcher.gen_patches_date(sec_hmi, args.date)

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
    parser_update.add_argument('--version', help='Qcom chip name (SA8155P/SA8295P)', type=str, required=True)
    parser_update.set_defaults(func=update)

    parser_format = subparsers.add_parser('format', help='format local patch data')
    parser_format.add_argument('--repo', help='git repository path', type=str, required=True)
    parser_format.add_argument('--date', help='Date time "YYYY-MM-DD"', type=str, default=None)
    parser_format.add_argument('--version', help='Qcom chip name (SA8155P/SA8295P)', type=str, required=True)
    parser_format.set_defaults(func=format)

    parser_scan = subparsers.add_parser('scan', help='scan CVE patch data')
    parser_scan.add_argument('--version', help='Qcom chip name (SA8155P/SA8295P)', type=str, required=True)
    parser_scan.add_argument('--strict', help='Strict mode', action='store_true', default=False)
    parser_scan.set_defaults(func=scan)

    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('cve_patch_qcom'))
    report_path = Path(__file__).absolute().parents[1].joinpath('data/SecScan')
    report_path.mkdir(parents=True, exist_ok=True)
    report_file = report_path.joinpath('cve_patch_qcom.json')
    report_html = report_file.with_suffix('.html')
    patch_all_path = report_path.joinpath('patch_all_qcom')
    patch_sec_path = report_path.joinpath('patch_sec_qcom')
    all_patches = patch_all_path.joinpath('all_patches.json')
    sec_cves = patch_sec_path.joinpath('sec_cves.json')

    args = argument()
    version = args.version
    repo_path = Path(getattr(args, 'repo', '')).expanduser().absolute()
    strict_mode = getattr(args, 'strict', False)

    patcher = Patcher(
        patch_all_path, patch_sec_path, report_file,
        version, repo_path, strict_mode,
        CVE_EXCLUDE, REPO_EXCLUDE, REPO_MIGRATE
    )

    # 第一步：更新CVE补丁库
    if args.func.__name__ == 'update':
        cves_data = defaultdict(dict)
        asyncio.run(args.func(args))
        exit(0)

    # 第二步：为所有仓库生成补丁
    elif args.func.__name__ == 'format':
        if not sec_cves.exists():
            print('Please update first')
            sys.exit(1)

    # 第三步：对比所有CVE补丁与所有补丁
    elif args.func.__name__ == 'scan':
        if not all_patches.exists():
            print('Please format first')
            sys.exit(1)

    args.func(args)
