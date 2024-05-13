#!/usr/bin/python3

import re
import sys
import json
import pyfiglet
import argparse
import requests

from lxml import etree
from pathlib import Path
from thefuzz import fuzz
from bs4 import BeautifulSoup
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from cve_utils import *
sys.path.append('..')
from utils import *

# 在扫描时排除的漏洞
CVE_EXCLUDE = {
    '11': [

    ],
    '12': [

    ]
}

# 排除部分仓库，提高速度
REPO_EXCLUDE = [
    'platform/cts',
]

# 移动过位置的仓库
REPO_MIGRATE = {
    '12': {
        'platform/packages/modules/Bluetooth': 'platform/system/bt',
    },
    '11': {
        'platform/packages/modules/Bluetooth': 'platform/system/bt',
        'platform/packages/modules/NeuralNetworks': 'platform/frameworks/ml',
        'platform/packages/modules/StatsD': 'platform/frameworks/base',
        'platform/packages/modules/Connectivity': 'platform/frameworks/base',
        'platform/packages/modules/Wifi': 'platform/frameworks/opt/net/wifi',
    },
}

# 最早和最晚时间
BULLETIN_TIME = {
    '14': ('2023-11-01', ''),
    '13': ('2022-09-01', ''),
    '12L': ('2022-04-01', ''),
    '12': ('2021-11-01', ''),
    '11': ('2020-10-01', '2024-02-01'),
    '10': ('2019-09-01', '2023-02-01'),
    '9': ('2018-09-01', '2022-01-01'),
    '8.1': ('2018-01-01', '2021-10-01'),
    '8.0': ('2017-09-01', '2021-01-01'),
}

# HTML元素ID
BULLETIN_IDS = {
    'aosp': [
        'android-runtime',
        '01android-runtime',
        'android-runtime-01',
        'framework',
        '01framework',
        'framework-01',
        'media-framework',
        '01media-framework',
        'media-framework-01',
        'system',
        '01system',
        'system-01',
        'library',
        'Android-runtime-05',
        'framework-05',
        '05-framework',
        'system-05',
        '05-system'
    ],
    # 'kernel': [
    #     'kernel components',
    #     'kernel-compoents',
    #     'kernel-components',
    #     'kernel-components-05',
    #     '05-kernel-components',
    #     'kernel-components_1',
    #     'kernel',
    #     '01kernel',
    #     '05kernel',
    #     '05-kernel',
    # ],
    # 'qualcomm': [
    #     'qualcomm',
    #     'qualcom-components',
    #     'ualcomm components',
    #     'qualcomm-components',
    #     '05qualcomm',
    #     'qualcomm-components-05',
    #     '05-qualcomm-components',
    #     # 'qualcomm-closed-source',
    #     # 'qualcomm-closed-source-05'
    # ],
    # 'mediatek': [
    #     'mediatek-components-05'
    # ]
    'aaos': [
        'media-framework',
        'platform-apps',
        'platform-apps_1',
        'platform-service',
        'system',
        'system-ui',
        'aaos',
        'car-settings',
    ],
}


def get_patch_meta(url: str):
    """获取补丁的元数据"""
    url = f'{url}&&format=JSON' if '/?s=' in url else f'{url}?format=JSON'
    return requests.get(url).text[5:]


def extract_section(soup, tag2: str, date_str: str):
    """解析表格"""
    def parse_table(row):
        flag = False
        type_text = ''
        vers_text = ''
        component_text = ''
        idx = 0
        for col in row.find_all('td'):
            if idx == cve_idx:
                temp = col.text.strip()
                if temp.startswith('CVE-'):
                    cve_id = temp.split(',')[0].strip() if ',' in temp else temp
                elif not temp:
                    # 一个CVE有多行的情况
                    flag = True
                else:
                    flag = True
                    idx += 2    # 列标校准
            if idx == ref_idx and not flag:
                bug_id = col.text.split('\n')[0].strip()
                urls = []
                for url in col.find_all('a'):
                    href = url.get('href')
                    if href and href != '#asterisk':
                        urls.append(href.strip())
            if idx == type_idx:
                type_text = col.text.strip()
            if idx == severity_idx:
                severity_text = col.text.strip()
            if idx == ver_idx:
                vers_text = col.text.strip()
            if idx == component_idx:
                component_text = col.text.strip()
            idx += 1

        item = {
            'cve_id': cve_id,
            'date': date_str,
            'bug_id': bug_id,
            'fixes': urls,
            'affected_versions': vers_text,
            'affected_component': component_text,
            'type': type_text,
            'severity': severity_text
        }
        item.update(get_cve_detail(cve_id))
        return item

    items = []
    found = soup.find('h3', id=tag2)
    if not found:
        return items

    # 解析表头
    title = found.find_next('table').find('tr')
    ver_idx = -1
    component_idx = -1
    type_idx = -1
    for idx, col in enumerate(title.find_all('th')):
        if col.text == 'CVE':
            cve_idx = idx
        elif col.text in {'Component', 'Subcomponent'}:
            component_idx = idx
        elif col.text == 'References':
            ref_idx = idx
        elif col.text == 'Severity':
            severity_idx = idx
        elif col.text == 'Type':
            type_idx = idx
        elif col.text == 'Updated AOSP versions':
            ver_idx = idx

    # 解析表内容
    for row in title.find_next_siblings('tr'):
        item = parse_table(row)
        items.append(item)
        print_success(f'{tag2}\t{item}')

    return items


def download_patches(cve_data: dict):
    """下载补丁和元数据"""
    cve_id = cve_data['cve_id']
    vers = cve_data['affected_versions'].replace(" ", "").split(',')

    if not vers or version not in vers:
        print_failed(f'{cve_id} not in Android {version}')
        return

    # 更新cves_data
    cves_data[version][cve_id] = cve_data

    # 下载并保存补丁文件
    patcher.download_and_write_patches(version, cve_data)


def updateThread(url: str, tag: str):
    """更新线程"""
    print_focus(url)

    date_str = url.split('/')[-1]
    r = requests.get(url)
    soup = BeautifulSoup(r.content, 'html.parser')

    for tag2 in BULLETIN_IDS[tag]:
        items = extract_section(soup, tag2, date_str)
        for item in items:
            download_patches(item)


def updatePatch(ver, repos):
    """更新各版本的补丁"""
    ver_meta = {}

    for repo in repos:
        base_url = f'https://android.googlesource.com/{repo}/+log/refs/heads/android{ver}-security-release'
        print_focus(base_url)

        # 获取多页数据
        repo_meta = []
        next_commit = ''
        for _ in range(5):
            try:
                url = f'{base_url}/?s={next_commit}' if next_commit else base_url
                meta = json.loads(get_patch_meta(url))
                repo_meta.extend(meta['log'])
                next_commit = meta.get('next')
                if not next_commit:
                    break
            except Exception as e:
                print_failed(f'{base_url} no security branch')
                print(e)
                break
        ver_meta[repo] = repo_meta

    with open(android_meta, 'w+') as f:
        json.dump(ver_meta, f, indent=4)
        print_success(f'Meta saved in {android_meta}')


def scanThread(repo: str, cve_path: Path):
    """对比某个CVE补丁与所有补丁"""
    def get_meta_str(meta):
        pattern = r'[0-9a-f]{40}'   # 删掉commit id，提高准确性
        message = re.sub(pattern, '', meta.get('message', ''))
        author = meta.get('author', {})
        return json.dumps({
            'author': {
                'name': author.get('name', ''),
                'email': author.get('email', '')},
            'message': message},
            sort_keys=True)

    # 比较通用补丁
    cve_name = cve_path.stem
    cve_id = '-'.join(cve_name.split('-')[:3])
    diff_data = open(cve_path).read()

    ret_code = 0
    result = []
    if patches := patcher.filter_patches(repo, diff_data):
        result = patcher.scan_one_patch(repo, cve_name, patches, diff_data)

        # 如果没有找到，则比较特定补丁
        if not result:
            specific = []
            cve_meta = json.load(open(cve_path.with_suffix('.meta')))
            f1_meta = get_meta_str(cve_meta)

            for meta_item in meta_data[repo]:
                f3_meta = get_meta_str(meta_item)
                ratio = fuzz.ratio(f1_meta, f3_meta)
                if ratio >= 80:
                    url = f'https://android.googlesource.com/{repo}/+/{meta_item["commit"]}'
                    specific.append((f'{ratio}%', url))
                    try:
                        patch, meta, diff_data = get_patch(url)
                    except Exception as e:
                        continue
                    temp = patcher.scan_one_patch(repo, cve_name, patches, diff_data)
                    result.extend(temp)
                    # 非strict模式下找到一个就返回
                    if result and not strict_mode:
                        break
            print_focus(f'[{repo}] {cve_name} specific patch: {len(specific)}')
            print(specific)

        if not result:
            print_failed(f'[{repo}] {cve_name} not found!')
            ret_code = 2
    else:
        print_failed(f'[{repo}] {cve_name} Files not exists!')
        ret_code = 1

    return ret_code, cve_id, {cve_name: result}


def update(args):
    """更新CVE补丁库"""
    start_date, end_date = BULLETIN_TIME[version]
    end_date = datetime.strptime(end_date, '%Y-%m-%d') if end_date else datetime.now()
    start_date = datetime.strptime(start_date, '%Y-%m-%d')
    print_focus(f'Update from {start_date} to {end_date}')

    def get_urls(overview_url: str, bulletin_url: str):
        urls = []
        r = requests.get(overview_url)
        root = etree.HTML(r.content)
        table = root.xpath('//*[@id="gc-wrapper"]/main/devsite-content/article/div[3]/table/tr')
        for i in table:
            href = i.xpath('td/a/@href')
            if href and 'android' not in href[0]:
                date_str = href[0].split('/')[-1]
                url_date = datetime.strptime(date_str, '%Y-%m-%d')
                if url_date >= start_date and url_date <= end_date:
                    urls.append(f'{bulletin_url}/{date_str}')
        return urls

    # 更新AOSP公告
    aosp_url = 'https://source.android.com/docs/security/bulletin'
    urls = get_urls(f'{aosp_url}/asb-overview', aosp_url)

    executor = ThreadPoolExecutor(5)#os.cpu_count()-1)
    tasks = [executor.submit(updateThread, url, 'aosp') for url in urls]
    executor.shutdown(wait=True)

    # 更新AAOS公告
    # aoos_url = 'https://source.android.com/docs/security/bulletin/aaos'
    # urls = get_urls(aoos_url, aoos_url)

    # executor = ThreadPoolExecutor(5)#os.cpu_count()-1)
    # tasks = [executor.submit(updateThread, url, 'aaos') for url in urls]
    # executor.shutdown(wait=True)

    patcher.cves_data = cves_data[version]
    fix_repos = patcher.get_fix_repos()
    updatePatch(version, fix_repos)

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
    patches = patcher.patch_sec_path.joinpath(version).glob('*.diff')
    patcher.scan_patches(patches, scanThread)


def argument():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_update = subparsers.add_parser('update', help='update CVE patch data')
    parser_update.add_argument('--version', help='Android version number', type=str, required=True)
    parser_update.set_defaults(func=update)

    parser_format = subparsers.add_parser('format', help='format local patch data')
    parser_format.add_argument('--repo', help='Android git repository path', type=str, required=True)
    parser_format.add_argument('--date', help='Date time "YYYY-MM-DD"', type=str, required=True)
    parser_format.add_argument('--version', help='Android version number', type=str, required=True)
    parser_format.set_defaults(func=format)

    parser_scan = subparsers.add_parser('scan', help='scan CVE patch data')
    parser_scan.add_argument('--version', help='Android version number', type=str, required=True)
    parser_scan.add_argument('--strict', help='Strict mode', action='store_true', default=False)
    parser_scan.set_defaults(func=scan)

    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('cve_patch_android'))
    report_path = Path(__file__).absolute().parents[1].joinpath('data/SecScan')
    report_path.mkdir(parents=True, exist_ok=True)

    args = argument()
    version = args.version
    strict_mode = getattr(args, 'strict', False)
    repo_path = Path(getattr(args, 'repo', '')).expanduser().absolute()

    patcher = Patcher(
        'android', report_path,
        version, repo_path, strict_mode,
        CVE_EXCLUDE, REPO_EXCLUDE, REPO_MIGRATE
    )
    android_meta = patcher.patch_sec_path.joinpath(version, 'meta.json')

    # 第一步：更新CVE补丁库
    if args.func.__name__ == 'update':
        cves_data = defaultdict(dict)

    # 第二步：为所有仓库生成补丁
    elif args.func.__name__ == 'format':
        if not patcher.sec_cves.exists():
            print_failed('Please update first')
            sys.exit(1)

    # 第三步：对比所有CVE补丁与所有补丁
    elif args.func.__name__ == 'scan':
        if not patcher.all_patches.exists():
            print_failed('Please format first')
            sys.exit(1)

        meta_data = json.load(open(android_meta))

    args.func(args)
