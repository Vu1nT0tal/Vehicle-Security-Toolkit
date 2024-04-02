#!/usr/bin/python3

import sys
import json
import asyncio
import calendar
import pyfiglet
import argparse

from pathlib import Path
from datetime import datetime
from bs4 import BeautifulSoup
from collections import defaultdict
from playwright.async_api import async_playwright
from concurrent.futures import ProcessPoolExecutor, as_completed

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

def all_chips():
    """针对单个芯片还是所有芯片"""
    return QCOM_CHIP == 'all'


def download_patches(cve_data: dict, tag: str):
    cve_id = cve_data['cve_id']
    chips = cve_data['affected_chipsets']

    if not chips:
        return
    if not all_chips() and QCOM_CHIP not in chips:
        print_failed(f'{tag} {cve_id} not in {QCOM_CHIP}')
        return

    # 更新cves_data
    chips = chips if all_chips() else [QCOM_CHIP]
    for chip in chips:
        cves_data[chip].setdefault(tag, {}).update({cve_id: cve_data})

    # 下载并保存补丁文件
    if tag == 'propref':
        return
    download_and_write_patches(patch_sec_path, tag, chips, cve_data)


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
            propref = soup.find('h2', id='Propref')
            openref = soup.find('h2', id='Openref')

            items = extract_section(propref, date_str)
            for item in items:
                download_patches(item, 'propref')
            items = extract_section(openref, date_str)
            for item in items:
                download_patches(item, 'openref')
        except Exception as e:
            print(f'Error occurred: {url}\n{e}')
        finally:
            await page.close() if page else None


async def update(args):
    """更新CVE补丁库"""
    if all_chips():
        start_date, _ = BULLETIN_TIME['SA8155P']
        end_date = datetime.now()
    else:
        start_date, end_date = BULLETIN_TIME[QCOM_CHIP]
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

    with open(qcom_cves, 'w+') as f:
        json.dump(cves_data, f, indent=4)
        print_success(f'Results saved in {qcom_cves}')


def get_repo(url: str, chip: str):
    """从fix url获取仓库名"""
    repo = '/'.join(url.split('/-/')[0].split('/')[5:])
    if repo in REPO_EXCLUDE:
        return ''
    if repo in REPO_MIGRATE.get(chip, {}):
        old_repo = repo
        repo = REPO_MIGRATE[chip][old_repo]
    return repo


def format(args):
    """为所有仓库生成补丁"""
    # 获取所有本地仓库
    all_hmi = get_local_repos(hmi_path, repo_tool)

    # 安全补丁涉及的AOSP仓库
    fix_repos = set()
    for cve_data in cves_data[QCOM_CHIP]['openref'].values():
        for url in cve_data['fixes']:
            repo = get_repo(url, QCOM_CHIP)
            fix_repos.add(repo)
    print_focus(f'Chip: {QCOM_CHIP}, Repos: {len(fix_repos)}')

    # 安全补丁对应的本地仓库
    sec_hmi = get_sec_repos(all_hmi, fix_repos)

    # 生成补丁
    generate_patches_date(patch_all_path, sec_hmi, args.date)
    print_success('Generate patches finished')

    # 处理生成的补丁
    results = process_patches(patch_all_path)

    with open(qcom_patches, 'w+') as f:
        json.dump(results, f, indent=4)
        print_success(f'Results saved in {qcom_patches}')


def compareThread(repo: str, cve_id: str, cve_path: Path):
    """对比某个CVE补丁与所有补丁"""
    cve_name = cve_path.stem
    diff_data = open(cve_path).read()
    patch_data = open(cve_path.with_suffix('.patch')).read()

    ret_code = 0
    result = []
    if patches := filter_patches(patch_all_path, repo, cve_name, diff_data, patches_data):
        result = scan_patches(repo, cve_name, patches, diff_data, patch_data, args.strict)
        if not result:
            print_failed(f'[{repo}] {cve_name} not found!')
            ret_code = 2
    else:
        print_failed(f'[{repo}] {cve_name} Files not exists!')
        ret_code = 1

    return ret_code, repo, cve_id, {cve_name: result}


def scan(args):
    """对比所有CVE补丁与所有补丁"""
    def make_data(key, data):
        """按仓库名组织数据，减少计算量"""
        for cve, cve_data in data.items():
            if fixes := cve_data['fixes']:
                for fix in fixes:
                    if repo := get_repo(fix, QCOM_CHIP):
                        cve_fixes[key][repo][cve] = cve_data
            else:
                # 没有修复链接
                results[key]['no_fixes'][cve] = cve_data

    def get_diff_path(patches, key, repo, cve_id):
        def in_repo(repo1, patch):
            temp = patch.stem.split('-')
            idx = int(temp[-1]) if len(temp) == 4 else 0
            if idx != 0:
                fix = cve_fixes[key][repo][cve_id]['fixes'][idx-1]
                repo2 = get_repo(fix, QCOM_CHIP)
                return repo1 == repo2
            return True

        result = []
        for patch in patches:
            if cve_id in patch.stem and in_repo(repo, patch):
                result.append(patch)
        return result

    key = 'openref'
    results = defaultdict(dict)
    results[key] = defaultdict(dict)
    data = cves_data[QCOM_CHIP][key]

    cve_fixes = {key: defaultdict(dict)}
    make_data(key, data)
    print_focus(f'QCOM CVE: {len(data)}, CVE fixes: {len(cve_fixes[key])}')
    with open(patch_sec_path.joinpath('cve_fixes.json'), 'w+') as f:
        json.dump(cve_fixes, f, indent=4)

    patches = list(patch_sec_path.joinpath(QCOM_CHIP, key).glob('*.diff'))
    with ProcessPoolExecutor(os.cpu_count()-1) as executor:
        tasks = []
        for repo, cve_dict in cve_fixes[key].items():
            print(repo, len(cve_dict))

            # 排除没有的本地仓库
            if repo not in patches_data:
                print_failed(f'[{repo}] Repo not exists!')
                results[key]['no_repo'][repo] = cve_dict
                continue

            for cve_id, cve_data in cve_dict.items():
                # 排除部分漏洞
                if cve_id in CVE_EXCLUDE.get(QCOM_CHIP, []):
                    results[key]['exclude'][cve_id] = cve_data
                    continue

                for cve_path in get_diff_path(patches, key, repo, cve_id):
                    thread = executor.submit(compareThread, repo, cve_id, cve_path)
                    tasks.append(thread)

        for f in as_completed(tasks):
            # 先全部放到patched里面
            ret_code, repo, cve_id, result = f.result()
            cve_data = cve_fixes[key][repo][cve_id]

            if ret_code == 1:
                results[key]['no_files'][cve_id] = cve_data
                continue

            if cve_id in results[key]['patched']:
                cve_data['scan'].update(result)
            else:
                cve_data['scan'] = result
                results[key]['patched'][cve_id] = cve_data

        # 将未修复的移到unpatched里面
        pop_list = []
        for cve_id, cve_data in results[key]['patched'].items():
            # strict模式下，只要有一个补丁未修复，就认为该漏洞未修复
            if args.strict:
                if any(i == [] for i in cve_data['scan'].values()):
                    results[key]['unpatched'][cve_id] = cve_data
                    pop_list.append(cve_id)
            # 非strict模式下，只要有一个补丁修复，就认为该漏洞修复
            else:
                if all(i == [] for i in cve_data['scan'].values()):
                    results[key]['unpatched'][cve_id] = cve_data
                    pop_list.append(cve_id)
        for i in pop_list:
            results[key]['patched'].pop(i)

    with open(report_file, 'w+') as f:
        json.dump(results, f, indent=4)
        print_success(f'Results saved in {report_file}')


def argument():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_update = subparsers.add_parser('update', help='update CVE patch data')
    parser_update.add_argument('--chip', help='Qualcomm chip name', type=str, default=None)
    parser_update.set_defaults(func=update)

    parser_format = subparsers.add_parser('format', help='format local patch data')
    parser_format.add_argument('--repo', help='git repository path', type=str, required=True)
    parser_format.add_argument('--date', help='Date time "YYYY-MM-DD"', type=str, default=None)
    parser_format.add_argument('--chip', help='Qualcomm chip name', type=str, required=True)
    parser_format.set_defaults(func=format)

    parser_scan = subparsers.add_parser('scan', help='scan CVE patch data')
    parser_scan.add_argument('--chip', help='Qualcomm chip name', type=str, required=True)
    parser_scan.add_argument('--strict', help='Strict mode', action='store_true', default=False)
    parser_scan.set_defaults(func=scan)

    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('cve_patch_qcom'))
    report_path = Path(__file__).absolute().parents[1].joinpath('data/SecScan')
    report_path.mkdir(parents=True, exist_ok=True)
    report_file = report_path.joinpath('cve_patch_qcom.json')
    patch_all_path = report_path.joinpath('patch_all_qcom')
    patch_sec_path = report_path.joinpath('patch_sec_qcom')
    qcom_patches = patch_all_path.joinpath('qcom_patches.json')
    qcom_cves = patch_sec_path.joinpath('qcom_cves.json')

    args = argument()
    QCOM_CHIP = args.chip or 'all'

    # 第一步：更新CVE补丁库
    if args.func.__name__ == 'update':
        cves_data = defaultdict(dict)
        asyncio.run(args.func(args))
        exit(0)

    # 第二步：为所有仓库生成补丁
    elif args.func.__name__ == 'format':
        if not qcom_cves.exists():
            print('Please update first')
            sys.exit(1)

        cves_data = json.load(open(qcom_cves))
        hmi_path = Path(args.repo).expanduser().absolute()
        repo_tool = hmi_path.joinpath('.repo/repo/repo')

    # 第三步：对比所有CVE补丁与所有补丁
    elif args.func.__name__ == 'scan':
        if not qcom_patches.exists():
            print('Please format first')
            sys.exit(1)

        cves_data = json.load(open(qcom_cves))
        patches_data = json.load(open(qcom_patches))

    args.func(args)
