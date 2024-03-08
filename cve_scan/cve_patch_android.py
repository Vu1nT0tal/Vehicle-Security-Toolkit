#!/usr/bin/python3

import sys
import json
import base64
import nvdlib
import pyfiglet
import argparse
import requests
import contextlib

from tqdm import tqdm
from lxml import etree
from pathlib import Path
from thefuzz import fuzz
from bs4 import BeautifulSoup
from datetime import datetime
from selenium import webdriver
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

sys.path.append('..')
from utils import *

options = webdriver.ChromeOptions()
options.add_argument('--headless')

NVD_KEY = ''

# 在扫描时排除的漏洞
CVE_EXCLUDE = []

# 转移了位置和需要排除的仓库
REPOSITORY = {
    'migrate': {
        'platform/packages/modules/Bluetooth': 'platform/system/bt',
        'platform/packages/modules/NeuralNetworks': 'platform/frameworks/ml',
        'platform/packages/modules/StatsD': 'platform/frameworks/base',
        'platform/packages/modules/Connectivity': 'platform/frameworks/base',
        'platform/packages/modules/Wifi': 'platform/frameworks/opt/net/wifi',
    },
    'exclude': [
        'platform/cts',
    ]
}

# 最早和最晚时间
ANDROID_VERSION = {
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
IDS = {
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
    'kernel': [
        'kernel components',
        'kernel-compoents',
        'kernel-components',
        'kernel-components-05',
        '05-kernel-components',
        'kernel-components_1',
        'kernel',
        '01kernel',
        '05kernel',
        '05-kernel',
    ],
    'qualcomm': [
        'qualcomm',
        'qualcom-components',
        'ualcomm components',
        'qualcomm-components',
        '05qualcomm',
        'qualcomm-components-05',
        '05-qualcomm-components',
        # 'qualcomm-closed-source',
        # 'qualcomm-closed-source-05'
    ],
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


def get_repo(url: str, flag: bool):
    """从fix url获取仓库名"""
    repo = url.split("googlesource.com/")[1].split('/+/')[0]
    if flag:
        if repo in REPOSITORY['exclude']:
            return ''
        if repo in REPOSITORY['migrate']:
            repo = REPOSITORY['migrate'][repo]
    return repo


def get_patch(url: str):
    """获取patch"""

    class shadow:
        def __init__(self, browser):
            self.browser = browser

        def get_shadow(self, shadow, by: str, value: str):
            element = shadow.find_element(by, value)
            shadow = self.browser.execute_script('return arguments[0].shadowRoot', element)
            return shadow

    url = url.strip('/')
    if 'source.codeaurora.org' in url:
        # 已迁移到codelinaro
        url = url.replace('commit/?id', 'commit?id')
        data = url.split('/')
        path = '/'.join(data[4:-1])
        id = data[-1].split('=')[1].split('_')[0]
        url = f'https://git.codelinaro.org/clo/{path}/-/commit/{id}'
        patch = requests.get(f'{url}.diff').text
    elif 'git.codelinaro.org' in url:
        patch = requests.get(f'{url}.diff').text
    elif 'git.kernel.org' in url:
        patch = requests.get(url.replace('commit', 'patch')).text
    elif 'android.googlesource.com' in url:
        r = requests.get(f'{url}^!/?format=TEXT')
        patch = base64.b64decode(r.text).decode()
    elif 'android-review.googlesource.com' in url:
        browser = webdriver.Chrome(options=options)
        browser.get(url)
        sd = shadow(browser)
        shadow = sd.get_shadow(browser, 'id', 'pg-app')
        shadow = sd.get_shadow(shadow, 'id', 'app-element')
        shadow = sd.get_shadow(shadow, 'tag name', 'gr-change-view')
        shadow = sd.get_shadow(shadow, 'tag name', 'gr-file-list-header')
        shadow = sd.get_shadow(shadow, 'tag name', 'gr-commit-info')
        url = shadow.find_element('tag name', 'a').get_attribute('href')
        r = requests.get(f'{url}^!/?format=TEXT')
        patch = base64.b64decode(r.text).decode()
    elif 'lore.kernel.org' in url:
        if 'patchwork' in url:
            r = requests.get(url)
            url = r.history[-1].headers['Location']
        patch, _ = shell_cmd(f'b4 -q am -o- {url.split("/")[-1]}')
    elif 'github.com/torvalds' in url:
        patch = requests.get(f'{url}.patch')
    else:
        print_failed(f'{url} not support')
        patch = ''
    return patch


def get_poc(cve_id: str):
    """检查是否有POC/EXP"""
    pocs = []

    poc_url = 'https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master'
    with contextlib.suppress(Exception):
        r = requests.get(f'{poc_url}/{cve_id.split("-")[1]}/{cve_id.upper()}.json', timeout=15)
        if r.status_code == 200:
            pocs.extend([i['html_url'] for i in r.json()])

    edb_url = 'https://www.exploit-db.com/search?cve='
    with contextlib.suppress(Exception):
        headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36'
        }
        r = requests.get(f'{edb_url}{cve_id.upper()}', headers=headers, timeout=15)
        if r.status_code == 200:
            pocs.extend([f'https://www.exploit-db.com/exploits/{i["id"]}' for i in r.json()['data']])

    return pocs


def get_cve_detail(cve_id: str):
    """获取CVE详情"""
    result = {
        'references': [f'https://nvd.nist.gov/vuln/detail/{cve_id}']
    }

    try:
        r = nvdlib.searchCVE(cveId=cve_id, key=NVD_KEY)[0]
        result['cvss'] = r.score[1]
        result['cvssVector'] = getattr(r, 'v31vector', getattr(r, 'v30vector', getattr(r, 'v2vector', '')))
        result['references'].extend([i.url for i in r.references])
        result['summary'] = r.descriptions[0].value
        result['poc'] = get_poc(cve_id)
    except Exception as e:
        print_failed(f'{cve_id} detail failed: {e}')

    # try:
    #     r = requests.get(f'https://cve.circl.lu/api/cve/{cve_id}').json()
    #     result['cvss'] = r.get('cvss') or ''
    #     result['cvssVector'] = r.get('cvss-vector') or ''
    #     result['summary'] = r.get('summary') or ''
    #     result['references'].extend(r.get('references') or [])
    # except Exception as e:
    #     print_failed(f'{cve_id} detail failed: {e}')

    return result


def extract_section(soup, tag1: str, tag2: str, date_str: str):
    """解析表格"""

    found = soup.find('h3', id=tag2)
    if not found:
        return

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
        flag = False
        type_text = ''
        vers_text = ''
        component_text = ''
        idx = 0
        for col in row.find_all('td'):
            if idx == cve_idx:
                temp = col.text.strip()
                if temp.startswith('CVE-'):
                    cve_id = temp
                elif ',' in temp:
                    # 一行有多个CVE的情况
                    cve_id = temp
                elif not temp:
                    # 一个CVE有多行的情况
                    flag = True
                else:
                    flag = True
                    idx += 2    # 列标校准
            if idx == ref_idx and not flag:
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

        item = {cve_id: {
            'date': date_str,
            'fixes': urls,
            'affected_versions': vers_text,
            'affected_component': component_text,
            'type': type_text,
            'severity': severity_text
        }}
        print_success(f'{tag2}\t{item}')
        item[cve_id].update(get_cve_detail(cve_id))

        # 下载patch
        tag_path = patch_sec_path.joinpath(tag1)
        tag_path.mkdir(parents=True, exist_ok=True)
        if tag1 in {'aosp', 'aaos'}:
            vers = vers_text.replace(" ", "").split(',')
            for ver in vers:
                cves_data[tag1][ver].update(item)

            if not urls:
                print_failed(f'{tag1} {cve_id} no fixes')
                continue

            for idx, url in enumerate(urls):
                try:
                    patch = get_patch(url)
                except Exception as e:
                    print_failed(f'{url} download failed')
                    print(e, item)
                    continue

                for ver in vers:
                    ver_path = tag_path.joinpath(ver)
                    ver_path.mkdir(parents=True, exist_ok=True)
                    if len(urls) == 1:
                        patch_path = ver_path.joinpath(f'{cve_id}.patch')
                    else:
                        patch_path = ver_path.joinpath(f'{cve_id}-{idx+1}.patch')
                    with open(patch_path, 'w+') as f:
                        f.write(patch)
        else:
            cves_data[tag1].update(item)

            if not urls:
                print_failed(f'{tag1} {cve_id} no fixes')
                continue

            for idx, url in enumerate(urls):
                try:
                    patch = get_patch(url)
                except Exception as e:
                    print_failed(f'{url} download failed')
                    print(e, item)
                    continue

                if len(urls) == 1:
                    patch_path = tag_path.joinpath(f'{cve_id}.patch')
                else:
                    patch_path = tag_path.joinpath(f'{cve_id}-{idx+1}.patch')
                with open(patch_path, 'w+') as f:
                    f.write(patch)


def updateAospThread(url: str):
    """更新线程"""
    print_focus(url)

    date_str = url.split('/')[-1]
    r = requests.get(url)
    soup = BeautifulSoup(r.content, 'html.parser')

    for tag1, v in IDS.items():
        for tag2 in v:
            extract_section(soup, tag1, tag2, date_str)


def updateAaosThread(url: str):
    """更新线程"""
    print_focus(url)

    date_str = url.split('/')[-1]
    r = requests.get(url)
    soup = BeautifulSoup(r.content, 'html.parser')

    tag1 = 'aaos'
    for tag2 in IDS[tag1]:
        extract_section(soup, tag1, tag2, date_str)


def update(args):
    """更新CVE补丁库"""
    start_date, end_date = ANDROID_VERSION[args.version]
    start_date = datetime.strptime(start_date, '%Y-%m-%d')
    end_date = datetime.strptime(end_date, '%Y-%m-%d') if end_date else datetime.now().strftime('%Y-%m-%d')

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
    tasks = [executor.submit(updateAospThread, url) for url in urls]
    executor.shutdown(wait=True)

    # 更新AAOS公告
    aoos_url = 'https://source.android.com/docs/security/bulletin/aaos'
    urls = get_urls(aoos_url, aoos_url)

    executor = ThreadPoolExecutor(5)#os.cpu_count()-1)
    tasks = [executor.submit(updateAaosThread, url) for url in urls]
    executor.shutdown(wait=True)

    with open(android_cves, 'w+') as f:
        json.dump(cves_data, f, indent=4)
        print_success(f'Results saved in {android_cves}')


def compareThread(key: str, repo: str, cve_id: str, cve_path: Path):
    """对比某个CVE补丁与所有补丁"""

    result = []
    f1 = cve_path.read_text(errors='ignore')
    f1_files = get_modified_files(f1)

    patches = [
        patch_all_path.joinpath(repo).joinpath(f2)
        for f2, f2_files in patches_data[repo].items()
        if any(i in f2_files for i in f1_files)
    ]

    for patch in patches:
        f2 = open(patch).read()
        ratio = fuzz.ratio(f1, f2)
        if ratio > 80:
            result.append(f'{ratio}%{patch.stem}')
            print_focus(f'[{repo}] {cve_path.stem} found ({ratio}%): {patch.stem}')

    if not result:
        print_failed(f'[{repo}] {cve_path.stem} not found!')

    return key, repo, cve_id, {cve_path.stem: result}


def formatThread(repo_name, repo_path):
    target_path = patch_all_path.joinpath(repo_name)
    if target_path.exists():
        number = len(list(target_path.glob('*.patch')))
        print_success(f'Generate {number} patches: {repo_name}')
        return repo_name, number
    target_path.mkdir(parents=True, exist_ok=True)

    # 获取从某天开始第一次提交的哈希
    cmd = f'git --no-pager log --since="{args.date}" --pretty=format:"%H" | tail -n 1'
    first_commit, ret_code = shell_cmd(cmd, env={'cwd': repo_path})
    cmd1 = f'git rev-parse {first_commit}^' # 获取前一个哈希
    prev_commit, ret_code1 = shell_cmd(cmd1, env={'cwd': repo_path})
    if ret_code != 0 or ret_code1 != 0 or not first_commit or not prev_commit:
        print_failed(f'No first commit: {repo_name}')
        return repo_name, -1

    # 生成所有补丁
    cmd = f'git format-patch -N {prev_commit} -o {target_path}'
    output, ret_code = shell_cmd(cmd, env={'cwd': repo_path})
    number, _ = shell_cmd(f'ls {target_path} | wc -l')
    if ret_code != 0:
        print_failed(f'Generate patches Error: {repo_name}\n{output}')
        return repo_name, -1

    print_success(f'Generate {number} patches: {repo_name}')
    return repo_name, int(number)


def get_modified_files(patch: str):
    """获取补丁中修改的文件"""
    modified_files = []
    for line in patch.splitlines():
        if line.startswith('diff --git'):
            start = line.find(' a/') + len(' a/')
            end = line.find(' b/')
            modified_files.append(line[start:end])
    return modified_files


def patchThread(repo: Path, patch: Path):
    try:
        # 提取diff部分
        lines = patch.read_text(errors='ignore').splitlines()
        diff_index = next((i for i, line in enumerate(lines) if line.startswith('diff --git')), -1)
        diff_part = lines[diff_index:-3]

        new_patch = '\n'.join(diff_part)
        with open(patch, 'w+') as f:
            f.write(new_patch)

        # 找出修改的文件
        modified_files = get_modified_files(new_patch)
        return str(repo), patch.name, modified_files
    except Exception as e:
        print_failed(f'patchThread failed: {patch.name}\n{e}')
        return str(repo), patch.name, []


def format_manifest(hmi):
    # TODO
    manifest_path = hmi_path.joinpath('.repo/manifests')
    default_manifest = manifest_path.joinpath('default.xml')
    date = args.manifest

    scan_manifest = next(
        (
            xml_file
            for xml_file in manifest_path.glob('*.xml')
            if date.replace('-', '') in xml_file.name
        ),
        '',
    )
    if not scan_manifest:
        print_failed(f'Manifest not found: {date}')
        return False


def format_date(hmi):
    executor = ProcessPoolExecutor(os.cpu_count()-1)
    tasks = [executor.submit(formatThread, name, path) for name, path in hmi.items()]
    executor.shutdown(True)

    success = []
    error = []
    for task in tasks:
        name, number = task.result()
        success.append(name) if number != -1 else error.append(name)
    print_focus(f'Success: {len(success)}, Error: {len(error)}')
    print(error)


def format(args):
    """为所有仓库生成补丁"""
    # 获取所有AOSP仓库
    # aosp = requests.get('https://android.googlesource.com/?format=TEXT').text.splitlines()
    # repos = set(aosp).intersection(set(hmi.keys())) # aosp和hmi都有
    # new_hmi = {key: value for key, value in hmi.items() if key in repos}

    # 获取所有本地仓库
    all_hmi = {}
    output, ret_code = shell_cmd(f'cd {hmi_path} && {repo_tool} list')
    for line in output.splitlines():
        path = line.split(':')[0].strip()
        repo = line.split(':')[1].strip()
        all_hmi[repo] = hmi_path.joinpath(path)

    # 安全补丁涉及的AOSP仓库
    fixes = set()
    for ver_data in {**cves_data['aaos'], **cves_data['aosp']}.values():
        for cve_data in ver_data.values():
            for url in cve_data['fixes']:
                fixes.add(get_repo(url, flag=False))

    # 安全补丁对应的本地仓库
    sec_hmi = {key: all_hmi[key] for key in fixes if key in all_hmi}
    not_hmi = fixes - sec_hmi.keys()
    print_focus(f'Repo found: {len(sec_hmi)}, Repo not found: {len(not_hmi)}')
    print(not_hmi)
    # 排除无效仓库
    for key in REPOSITORY['exclude']:
        sec_hmi.pop(key, None)
    # 处理迁移仓库
    for key, value in REPOSITORY['migrate'].items():
        if key not in sec_hmi and value in all_hmi:
            print_focus(f'Migrated: {key} -> {value}')
            if value not in sec_hmi:
                sec_hmi[value] = all_hmi[value]

    # 生成补丁
    if args.manifest:
        format_manifest(sec_hmi)
    elif args.date:
        format_date(sec_hmi)
    else:
        print_failed('Please input manifest or date')
        return
    print_success('Generate patches finished')

    # 处理生成的补丁
    results = defaultdict(dict)
    patch_paths = list(patch_all_path.glob('**/*.patch'))
    with ProcessPoolExecutor(os.cpu_count()-1) as executor:
        tasks = []
        for patch in patch_paths:
            # 安全补丁通常小于50KB
            if patch.stat().st_size < 50 * 1024:
                thread = executor.submit(patchThread, patch.relative_to(patch_all_path).parent, patch)
                tasks.append(thread)
            else:
                patch.unlink(missing_ok=True)

        with tqdm(total=len(tasks)) as pbar:
            for f in as_completed(tasks):
                try:
                    repo, patch, modified_files = f.result(timeout=300)
                    results[repo][patch] = modified_files
                except Exception as e:
                    print_failed('patchThread timeout')
                pbar.update()

    with open(android_patches, 'w+') as f:
        json.dump(results, f, indent=4)
        print_success(f'Results saved in {android_patches}')


def scan(args):
    """对比所有CVE补丁与所有补丁"""
    def make_data(key, data):
        """按仓库名组织数据，减少计算量"""
        for cve, cve_data in data.items():
            if fixes := cve_data['fixes']:
                for fix in fixes:
                    if repo := get_repo(fix, flag=True):
                        cve_fixes[key][repo][cve] = cve_data
            else:
                # 没有修复链接
                results[key]['no_fixes'][cve] = cve_data

    def get_patch_path(patches, key, repo, cve_id):
        def in_repo(repo1, patch):
            temp = patch.stem.split('-')
            idx = int(temp[-1]) if len(temp) == 4 else 0
            if idx != 0:
                fix = cve_fixes[key][repo][cve_id]['fixes'][idx-1]
                repo2 = get_repo(fix, flag=True)
                return repo1 == repo2
            return True

        result = []
        for patch in patches:
            if cve_id in patch.stem and in_repo(repo, patch):
                result.append(patch)
        return result

    results = defaultdict(dict)
    results['aosp'] = defaultdict(dict)
    results['aaos'] = defaultdict(dict)

    aosp = cves_data['aosp'][args.version]
    aaos = cves_data['aaos'][args.version]
    aaos = {key: aaos[key] for key in aaos.keys() - aosp.keys()}
    print_focus(f'AOSP CVE: {len(aosp)}, AAOS CVE: {len(aaos)}')

    cve_fixes = {'aosp': defaultdict(dict), 'aaos': defaultdict(dict)}
    make_data('aosp', aosp)
    make_data('aaos', aaos)
    print_focus(f'CVE fixes: AOSP {len(cve_fixes["aosp"])}, AAOS {len(cve_fixes["aaos"])}')
    with open('cve_fixes.json', 'w+') as f:
        json.dump(cve_fixes, f, indent=4)

    with ProcessPoolExecutor(os.cpu_count()-1) as executor:
        tasks = []
        for key, value in cve_fixes.items():
            patches_path = patch_sec_path.joinpath(key).joinpath(args.version)
            patches = list(patches_path.glob('*.patch'))

            for repo, cve_dict in value.items():
                print(repo, len(cve_dict))

                # 排除没有的本地仓库
                if repo not in patches_data:
                    print_failed(f'[{repo}] not exists!')
                    results[key]['no_repo'][repo] = cve_dict
                    continue

                for cve_id, cve_data in cve_dict.items():
                    # 排除部分漏洞
                    if cve_id in CVE_EXCLUDE:
                        results[key]['exclude'][cve_id] = cve_data
                        continue

                    for cve_path in get_patch_path(patches, key, repo, cve_id):
                        thread = executor.submit(compareThread, key, repo, cve_id, cve_path)
                        tasks.append(thread)

        for f in as_completed(tasks):
            # 先全部放到patched里面
            key, repo, cve_id, result = f.result()
            cve_data = cve_fixes[key][repo][cve_id]
            if cve_id in results[key]['patched']:
                cve_data['scan'].update(result)
            else:
                cve_data['scan'] = result
                results[key]['patched'][cve_id] = cve_data

        # 将未修复的移到unpatched里面
        for key, value in results.items():
            pop_list = []
            for cve_id, cve_data in value['patched'].items():
                if any(i == [] for i in cve_data['scan'].values()):
                    results[key]['unpatched'][cve_id] = cve_data
                    pop_list.append(cve_id)
            for i in pop_list:
                value['patched'].pop(i)

    with open(report_file, 'w+') as f:
        json.dump(results, f, indent=4)
        print_success(f'Results saved in {report_file}')


def argument():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_update = subparsers.add_parser('update', help='update CVE patch data')
    parser_update.add_argument('--version', help='Android version number', type=str, required=True)
    parser_update.set_defaults(func=update)

    parser_format = subparsers.add_parser('format', help='format CVE patch data for Android repository')
    parser_format.add_argument('--repo', help='Android git repository path', type=str, required=True)
    parser_format.add_argument('--manifest', help='Manifest time "YYYY-MM-DD"', type=str, required=False)
    parser_format.add_argument('--date', help='Date time "YYYY-MM-DD"', type=str, required=False)
    parser_format.set_defaults(func=format)

    parser_scan = subparsers.add_parser('scan', help='scan CVE patch in Android repository')
    parser_scan.add_argument('--repo', help='Android git repository path', type=str, required=True)
    parser_scan.add_argument('--version', help='Android version number', type=str, required=True)
    parser_scan.set_defaults(func=scan)

    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('cve_patch_android'))
    report_path = Path(__file__).absolute().parents[1].joinpath('data/SecScan')
    report_path.mkdir(parents=True, exist_ok=True)
    report_file = report_path.joinpath('cve_patch_android.json')
    patch_all_path = report_path.joinpath('patch_all_android')
    patch_sec_path = report_path.joinpath('patch_sec_android')
    android_patches = patch_all_path.joinpath('android_patches.json')
    android_cves = patch_sec_path.joinpath('android_cves.json')

    args = argument()

    # 第一步：更新CVE补丁库
    if args.func.__name__ == 'update':
        cves_data = defaultdict(dict)
        cves_data['aosp'] = defaultdict(dict)
        cves_data['aaos'] = defaultdict(dict)

    # 第二步：为所有仓库生成补丁
    elif args.func.__name__ == 'format':
        if not android_cves.exists():
            print_failed('Please update first')
            sys.exit(1)

        cves_data = json.load(open(android_cves))
        hmi_path = Path(args.repo).expanduser().absolute()
        repo_tool = hmi_path.joinpath('.repo/repo/repo')

    # 第三步：对比所有CVE补丁与所有补丁
    if args.func.__name__ == 'scan':
        if not android_patches.exists():
            print_failed('Please format first')
            sys.exit(1)

        cves_data = json.load(open(android_cves))
        patches_data = json.load(open(android_patches))

    args.func(args)
