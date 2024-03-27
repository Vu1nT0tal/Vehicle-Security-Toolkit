#!/usr/bin/python3

import re
import sys
import json
import base64
import nvdlib
import pyfiglet
import argparse
import requests

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


def all_version():
    """针对单个版本还是所有版本"""
    return ANDROID_VERSION == 'all'


def in_version(date_str: str):
    """找到符合时间的版本"""
    vers = []
    url_date = datetime.strptime(date_str, '%Y-%m-%d')
    for ver, (start_date, end_date) in BULLETIN_TIME.items():
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        end_date = datetime.strptime(end_date, '%Y-%m-%d') if end_date else datetime.now()
        if url_date >= start_date and url_date <= end_date:
            vers.append(ver)
    return vers


def get_repo(url: str, ver: str):
    """从fix url获取仓库名"""
    repo = url.split("googlesource.com/")[1].split('/+/')[0]
    if repo in REPO_EXCLUDE:
        return ''
    if repo in REPO_MIGRATE.get(ver, {}):
        old_repo = repo
        repo = REPO_MIGRATE[ver][old_repo]
    return repo


def get_fix_repos(ver):
    """获取某个版本所有补丁涉及的所有仓库"""
    repos = set()
    for cve_data in {**cves_data[ver].get('aaos', {}), **cves_data[ver]['aosp']}.values():
        for url in cve_data['fixes']:
            if repo := get_repo(url, ver):
                repos.add(repo)
    print_focus(f'Version: {ver}, Repos: {len(repos)}')
    print(repos)
    return repos


def get_patch_meta(url: str, text: bool=False):
    """获取补丁的元数据"""
    url = f'{url}&&format=JSON' if '/?s=' in url else f'{url}?format=JSON'
    data = requests.get(url).text[5:]
    return data if text else json.loads(data)


def get_patch(url: str):
    """获取补丁"""
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
                bug_id = col.text.strip()
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
            'bug_id': bug_id,
            'fixes': urls,
            'affected_versions': vers_text,
            'affected_component': component_text,
            'type': type_text,
            'severity': severity_text
        }}
        item[cve_id].update(get_cve_detail(cve_id))
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


def download_patches(item: dict, tag1: str, date_str: str):
    """下载补丁和元数据"""
    def update_cves_data(vers):
        if all_version():
            for ver in vers:
                cves_data[ver].setdefault(tag1, {}).update(item)
        elif ANDROID_VERSION in vers:
            cves_data[ANDROID_VERSION].setdefault(tag1, {}).update(item)
        else:
            print_failed(f'{tag1} {cve_id} not in Android {ANDROID_VERSION}')
            return False
        return True

    def write_aosp_files(ver):
        tag_path = patch_sec_path.joinpath(ver, tag1)
        tag_path.mkdir(parents=True, exist_ok=True)
        if len(urls) == 1:
            patch_path = tag_path.joinpath(f'{cve_id}.patch')
            patch_meta_path = tag_path.joinpath(f'{cve_id}.json')
        else:
            patch_path = tag_path.joinpath(f'{cve_id}-{idx+1}.patch')
            patch_meta_path = tag_path.joinpath(f'{cve_id}-{idx+1}.json')
        with open(patch_path, 'w+') as f1, open(patch_meta_path, 'w+') as f2:
            f1.write(patch)
            f2.write(patch_meta)

    def write_other_files(ver):
        tag_path = patch_sec_path.joinpath(ver, tag1)
        tag_path.mkdir(parents=True, exist_ok=True)
        if len(urls) == 1:
            patch_path = tag_path.joinpath(f'{cve_id}.patch')
        else:
            patch_path = tag_path.joinpath(f'{cve_id}-{idx+1}.patch')
        with open(patch_path, 'w+') as f:
            f.write(patch)

    tag_aosp = tag1 in {'aosp', 'aaos'}
    cve_id = list(item.keys())[0]
    cve_data = item[cve_id]
    urls = cve_data['fixes']
    vers = cve_data['affected_versions'].replace(" ", "").split(',') if tag_aosp else in_version(date_str)

    # 更新cves_data
    if not update_cves_data(vers):
        return

    # 下载补丁
    if not urls:
        print_failed(f'{tag1} {cve_id} no fixes')
        return

    for idx, url in enumerate(urls):
        try:
            patch = get_patch(url)
            if tag_aosp:
                patch_meta = get_patch_meta(url, text=True)
        except Exception as e:
            print_failed(f'{url} download failed')
            print(e, item)
            continue

        if all_version():
            for ver in vers:
                write_aosp_files(ver) if tag_aosp else write_other_files(ver)
        else:
            write_aosp_files(ANDROID_VERSION) if tag_aosp else write_other_files(ANDROID_VERSION)


def updateAospThread(url: str):
    """更新线程"""
    print_focus(url)

    date_str = url.split('/')[-1]
    r = requests.get(url)
    soup = BeautifulSoup(r.content, 'html.parser')

    for tag1, v in BULLETIN_IDS.items():
        if tag1 == 'aaos':
            continue
        for tag2 in v:
            items = extract_section(soup, tag2, date_str)
            for item in items:
                download_patches(item, tag1, date_str)


def updateAaosThread(url: str):
    """更新线程"""
    print_focus(url)

    date_str = url.split('/')[-1]
    r = requests.get(url)
    soup = BeautifulSoup(r.content, 'html.parser')

    tag1 = 'aaos'
    for tag2 in BULLETIN_IDS[tag1]:
       items = extract_section(soup, tag2, date_str)
       for item in items:
           download_patches(item, tag1, date_str)


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
                meta = get_patch_meta(url)
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


def update(args):
    """更新CVE补丁库"""
    if all_version():
        start_date, _ = BULLETIN_TIME['11']#['8.0']
        end_date = datetime.now()
    else:
        start_date, end_date = BULLETIN_TIME[ANDROID_VERSION]
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

    if all_version():
        for ver in BULLETIN_TIME.keys():
            fix_repos = get_fix_repos(ver)
            updatePatch(ver, fix_repos)
    else:
        fix_repos = get_fix_repos(ANDROID_VERSION)
        updatePatch(ANDROID_VERSION, fix_repos)


def compareThread(key: str, repo: str, cve_id: str, cve_path: Path):
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

    def filter_patches(f1):
        # 有相同路径或文件名的补丁
        f1_filenames = get_modified_files(f1, mode='name')
        fi_paths = get_modified_files(f1, mode='path')

        patches1 = [
            patch_all_path.joinpath(repo, f2)
            for f2, f2_files in patches_data[repo].items()
            if any(i.split('/')[-1] in f1_filenames for i in f2_files)
        ]
        patches2 = [
            patch_all_path.joinpath(repo, f2)
            for f2, f2_files in patches_data[repo].items()
            if any('/'.join(i.split('/')[:-1]) in fi_paths for i in f2_files)
        ]
        patches = set(patches1 + patches2)
        if not patches:
            print_failed(f'[{repo}] {cve_name} not found patches!')
        return patches

    def find_patch(patches, f1):
        result = []
        for patch in patches:
            f2 = open(patch).read()
            ratio = fuzz.ratio(f1, f2)
            if ratio >= 60:
                print_focus(f'[{repo}] {cve_name} found ({ratio}%): {patch.stem}')
                if ratio >= 80:
                    result.append(f'{ratio}% {patch.stem}')
                    # 非strict模式下找到一个就返回
                    if not args.strict:
                        break
        return result

    # 比较通用补丁
    cve_name = cve_path.stem
    f1 = cve_path.read_text(errors='ignore')
    patches = filter_patches(f1)
    result = find_patch(patches, f1)

    # 如果没有找到，则比较特定补丁
    if not result:
        specific = []
        cve_meta = json.load(open(cve_path.with_suffix('.json')))
        f1_meta = get_meta_str(cve_meta)

        for meta in meta_data[repo]:
            f3_meta = get_meta_str(meta)
            ratio = fuzz.ratio(f1_meta, f3_meta)
            if ratio >= 80:
                url = f'https://android.googlesource.com/{repo}/+/{meta["commit"]}'
                specific.append((f'{ratio}%', url))
                try:
                    f1 = get_patch(url)
                except Exception as e:
                    continue
                patches = filter_patches(f1)
                result.extend(find_patch(patches, f1))
                # 非strict模式下找到一个就返回
                if result and not args.strict:
                    break
        print_focus(f'[{repo}] {cve_name} specific patch: {len(specific)}')
        print(specific)

    if not result:
        print_failed(f'[{repo}] {cve_name} not found!')

    return key, repo, cve_id, {cve_name: result}


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
    cmd = f'git format-patch --histogram -N {prev_commit} -o {target_path}'
    output, ret_code = shell_cmd(cmd, env={'cwd': repo_path})
    number, _ = shell_cmd(f'ls {target_path} | wc -l')
    if ret_code != 0:
        print_failed(f'Generate patches Error: {repo_name}\n{output}')
        return repo_name, -1

    print_success(f'Generate {number} patches: {repo_name}')
    return repo_name, int(number)


def get_modified_files(patch: str, mode: str='all'):
    """获取补丁中修改的文件"""
    modified_files = []
    for line in patch.splitlines():
        if line.startswith('diff --git'):
            start = line.find(' a/') + len(' a/')
            end = line.find(' b/')
            file = line[start:end]
            if mode == 'name':
                modified_files.append(file.split('/')[-1])
            elif mode == 'path':
                modified_files.append('/'.join(file.split('/')[:-1]))
            else:
                modified_files.append(file)
    return modified_files


def parse_patch(patch: Path, data: str):
    lines = data.splitlines()
    diff_index = next((i for i, line in enumerate(lines) if line.startswith('diff --git')), -1)
    meta_part = lines[:diff_index]
    diff_part = lines[diff_index:-3]

    with open(patch, 'w+') as f1, open(patch.with_suffix('.txt'), 'w+') as f2:
        f1.write('\n'.join(diff_part))
        f2.write('\n'.join(meta_part))


def patchThread(repo: Path, patch: Path):
    try:
        # 提取diff部分
        patch_data = patch.read_text(errors='ignore')
        parse_patch(patch, patch_data)

        # 找出修改的文件
        modified_files = get_modified_files(patch_data)
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
    fix_repos = get_fix_repos(ANDROID_VERSION)

    # 安全补丁对应的本地仓库
    sec_hmi = {key: all_hmi[key] for key in fix_repos if key in all_hmi}
    not_hmi = fix_repos - sec_hmi.keys()
    print_focus(f'Repo found: {len(sec_hmi)}, Repo not found: {len(not_hmi)}')
    print(not_hmi) if not_hmi else None

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
                    if repo := get_repo(fix, ANDROID_VERSION):
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
                repo2 = get_repo(fix, ANDROID_VERSION)
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

    aosp = cves_data[ANDROID_VERSION]['aosp']
    aaos = cves_data[ANDROID_VERSION]['aaos']
    aaos = {key: aaos[key] for key in aaos.keys() - aosp.keys()}
    print_focus(f'AOSP CVE: {len(aosp)}, AAOS CVE: {len(aaos)}')

    cve_fixes = {'aosp': defaultdict(dict), 'aaos': defaultdict(dict)}
    make_data('aosp', aosp)
    make_data('aaos', aaos)
    print_focus(f'CVE fixes: AOSP {len(cve_fixes["aosp"])}, AAOS {len(cve_fixes["aaos"])}')
    with open(patch_sec_path.joinpath('cve_fixes.json'), 'w+') as f:
        json.dump(cve_fixes, f, indent=4)

    with ProcessPoolExecutor(os.cpu_count()-1) as executor:
        tasks = []
        for key, value in cve_fixes.items():
            patches_path = patch_sec_path.joinpath(ANDROID_VERSION, key)
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
                    if cve_id in CVE_EXCLUDE[ANDROID_VERSION]:
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
                value['patched'].pop(i)

    with open(report_file, 'w+') as f:
        json.dump(results, f, indent=4)
        print_success(f'Results saved in {report_file}')


def argument():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_update = subparsers.add_parser('update', help='update CVE patch data')
    parser_update.add_argument('--version', help='Android version number', type=str, default=None)
    parser_update.set_defaults(func=update)

    parser_format = subparsers.add_parser('format', help='format CVE patch data for Android repository')
    parser_format.add_argument('--repo', help='Android git repository path', type=str, required=True)
    parser_format.add_argument('--manifest', help='Manifest time "YYYY-MM-DD"', type=str, default=None)
    parser_format.add_argument('--date', help='Date time "YYYY-MM-DD"', type=str, default=None)
    parser_format.add_argument('--version', help='Android version number', type=str, required=True)
    parser_format.set_defaults(func=format)

    parser_scan = subparsers.add_parser('scan', help='scan CVE patch in Android repository')
    parser_scan.add_argument('--repo', help='Android git repository path', type=str, required=True)
    parser_scan.add_argument('--version', help='Android version number', type=str, required=True)
    parser_scan.add_argument('--strict', help='Strict mode', action='store_true', default=False)
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
    ANDROID_VERSION = args.version or 'all'
    android_meta = patch_sec_path.joinpath(ANDROID_VERSION, 'meta.json')

    # 第一步：更新CVE补丁库
    if args.func.__name__ == 'update':
        cves_data = defaultdict(dict)

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
        meta_data = json.load(open(android_meta))

    args.func(args)
