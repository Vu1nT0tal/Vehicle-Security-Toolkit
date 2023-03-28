#!/usr/bin/python3

import sys
import json
import base64
import pyfiglet
import argparse
import requests
import cve_searchsploit
from lxml import etree
from pathlib import Path
from bs4 import BeautifulSoup
from datetime import datetime
from selenium import webdriver
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

sys.path.append('..')
from utils import shell_cmd, Color

options = webdriver.ChromeOptions()
options.add_argument('--headless')

# 最早出现时间
ANDROID_VERSION = {
    '12': '2021-11-01',
    '11': '2020-10-01',
    '10': '2019-09-01',
    '9': '2018-09-01',
    '8.1': '2018-01-01',
    '8.0': '2017-09-01'
}


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
        patch = requests.get(url.replace('commit', 'patch')).text
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
        Color.print_failed(f'[-] {url} not support')
    return patch


def get_cve(cve_name: str):
    """获取CVE详情"""

    r = requests.get(f'https://cve.circl.lu/api/cve/{cve_name}').json()
    result = {
        'poc': [f'https://www.exploit-db.com/exploits/{edbid}' for edbid in cve_searchsploit.edbid_from_cve(cve_name)],
        'cvss': {
            'vector': r['cvss-vector'] if r else '',
            'score': r['cvss'] if r else ''
        },
        'cwe': r['cwe'] if r else '',
        'nvd_text': r['summary'] if r else '',
        'ref_urls': r['references'] if r else [],
    }
    result['ref_urls'].append(f'https://nvd.nist.gov/vuln/detail/{cve_name}')
    poc_url = f'https://github.com/nomi-sec/PoC-in-GitHub/blob/master/{cve_name.split("-")[1]}/{cve_name}.json'
    if requests.get(poc_url):
        result['poc'].append(poc_url)
    if result['cwe']:
        cwe_url = f'https://cwe.mitre.org/data/definitions/{result["cwe"].split("-")[1]}.html'
        r = requests.get(cwe_url)
        root = etree.HTML(r.content)
        cwe = root.xpath('//*[@id="Contentpane"]/div[2]/h2/text()')[0]
        result['cwe'] = cwe
    return result


def extract_section(soup, tag1: str, tag2: str):
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
        elif col.text == 'Component':
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
                    cve_name = temp
                elif ',' in temp:
                    # 一行有多个CVE的情况
                    cve_name = temp
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

        item = {cve_name: {
            'fixes': urls,
            'affected_versions': vers_text,
            'affected_component': component_text,
            'type': type_text,
            'severity': severity_text
        }}
        Color.print_success(f'{tag2}\t{item}')
        item[cve_name].update(get_cve(cve_name))

        # 下载patch
        tag_path = patch_sec_path.joinpath(tag1)
        tag_path.mkdir(parents=True, exist_ok=True)
        if tag1 == 'aosp':
            for ver in vers_text.replace(" ", "").split(','):
                if not urls:
                    Color.print_failed(f'[-] {tag1} {cve_name} not found')
                else:
                    tag_path.joinpath(ver).mkdir(parents=True, exist_ok=True)
                    for idx, url in enumerate(urls):
                        try:
                            patch = get_patch(url)
                        except Exception as e:
                            Color.print_failed(f'[-] {url} download faild')
                            print(e, item)
                            continue

                        if len(urls) == 1:
                            patch_path = tag_path.joinpath(f'{ver}/{cve_name}.patch')
                        else:
                            patch_path = tag_path.joinpath(f'{ver}/{cve_name}-{idx+1}.patch')
                        with open(patch_path, 'w+') as f:
                            f.write(patch)
                results[tag1][ver].update(item)
        else:
            if not urls:
                Color.print_failed(f'[-] {tag1} {cve_name} not found')
            else:
                for idx, url in enumerate(urls):
                    try:
                        patch = get_patch(url)
                    except Exception as e:
                        Color.print_failed(f'[-] {url} download faild')
                        print(e, item)
                        continue

                    if len(urls) == 1:
                        patch_path = tag_path.joinpath(f'{cve_name}.patch')
                    else:
                        patch_path = tag_path.joinpath(f'{cve_name}-{idx+1}.patch')
                    with open(patch_path, 'w+') as f:
                        f.write(patch)
            results[tag1].update(item)


def updateThread(url: str):
    """更新线程"""
    Color.print_focus(url)
    ids = {
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
    }
    r = requests.get(url)
    soup = BeautifulSoup(r.content, 'html.parser')
    for k, v in ids.items():
        for i in v:
            extract_section(soup, k, i)


def update(args):
    """更新CVE补丁库"""
    ver_date = datetime.strptime(ANDROID_VERSION[args.version], '%Y-%m-%d')

    bulletin_url = 'https://source.android.com/security/bulletin'
    r = requests.get(bulletin_url)
    root = etree.HTML(r.content)
    table = root.xpath('//*[@id="gc-wrapper"]/main/devsite-content/article/div[2]/table/tr')
    urls = []
    for i in table:
        href = i.xpath('td/a/@href')
        if href and 'android' not in href[0]:
            date_str = href[0].split('/')[-1]
            url_date = datetime.strptime(date_str, '%Y-%m-%d')
            if url_date >= ver_date:
                urls.append(f'{bulletin_url}/{date_str}')

    executor = ThreadPoolExecutor(5)
    tasks = [executor.submit(updateThread, url) for url in urls]
    executor.shutdown(True)


def compareThread(cve: Path, patch_path: Path):
    """对比某个CVE补丁与所有补丁"""
    cve_name = '-'.join(cve.stem.split('-')[:3])
    result = {cve_name: {
        'scan': {}
    }}

    try:
        f1 = open(cve).read()
    except Exception as e:
        print(e, cve_name, patch_path.stem)
    return cve_name, result


def scan(args):
    """对比所有CVE补丁与所有补丁"""

    repo_path = Path(args.repo).expanduser().absolute()
    repo_tool = repo_path.joinpath('.repo/repo/repo')

    aosp = requests.get('https://android.googlesource.com/?format=TEXT').text.splitlines()
    output, ret_code = shell_cmd(f'cd {repo_path} && {repo_tool} list')
    hmi = [line.split(':')[1].strip() for line in output.splitlines()]

    # diff1 = set(aosp).difference(set(hmi))  # aosp有，hmi沒有
    # diff2 = set(hmi).difference(set(aosp))  # aosp沒有，hmi有
    diff = set(aosp).intersection(set(hmi))     # aosp和hmi都有
    print(len(diff))
    for i in diff:
        print(repo_path.joinpath(f'android/{i}'))


def argument():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_update = subparsers.add_parser('update', help='update CVE patch data')
    parser_update.add_argument('--version', help='Android version number', type=str, required=True)
    parser_update.set_defaults(func=update)

    parser_scan = subparsers.add_parser('scan', help='scan CVE patch in Android repository')
    parser_scan.add_argument('--repo', help='Android git repository path', type=str, required=True)
    parser_scan.add_argument('--version', help='Android version number', type=str, required=True)
    parser_scan.set_defaults(func=scan)

    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('poc_patch_android'))
    report_path = Path(__file__).absolute().parents[1].joinpath('data/SecScan')
    patch_sec_path = report_path.joinpath('patch_sec_android')
    patch_sec_path.mkdir(parents=True, exist_ok=True)

    results = defaultdict(dict)
    results['aosp'] = defaultdict(dict)
    args = argument()
    args.func(args)
    with open(patch_sec_path.joinpath('android_cves.json'), 'w+') as f:
        json.dump(results, f, indent=4)
