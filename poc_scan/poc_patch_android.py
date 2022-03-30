#!/usr/bin/python3

import sys
import json
import base64
import argparse
import requests
import cve_searchsploit
from lxml import etree
from pathlib import Path
from bs4 import BeautifulSoup
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

sys.path.append('..')
from utils import shell_cmd, Color


def get_cve(cve_name: str):
    """获取CVE详情"""
    # print(cve_name)
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
    poc_url = f'https://github.com/nomi-sec/PoC-in-GitHub/blob/master/{cve_name.split("-")[1]}/{cve_name}.json'
    if requests.get(poc_url):
        result['poc'].append(poc_url)
    return result


def extract_section(soup, _id):
    """解析表格"""

    found = soup.find('h3', id=_id)
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
        if col.text == 'References':
            ref_idx = idx
        if col.text == 'Type':
            type_idx = idx
        if col.text == 'Severity':
            severity_idx = idx
        if col.text == 'Updated AOSP versions':
            ver_idx = idx
        if col.text == 'Component':
            component_idx = idx

    # 解析表内容
    for row in title.find_next_siblings('tr'):
        flag = False
        type_text = 'N/A'
        for idx, col in enumerate(row.find_all('td')):
            if idx == cve_idx:
                temp = col.text.strip()
                if not temp:
                    # 一个CVE有多行的情况
                    flag = True
                elif ',' in temp:
                    # 一行有多个CVE的情况
                    cve_name = temp
                else:
                    cve_name = temp
            if idx == ref_idx and not flag:
                urls = []
                for url in col.find_all('a'):
                    href = url.get('href')
                    if href:
                        urls.append(href.strip())
            if idx == type_idx:
                type_text = col.text.strip()
            if idx == severity_idx:
                severity_text = col.text.strip()
            if idx == ver_idx:
                vers_text = col.text.strip()
                item = {cve_name: {
                    'fixes': urls,
                    'affected_versions': vers_text,
                    'type': type_text,
                    'severity': severity_text
                }}
                item[cve_name].update(get_cve(cve_name))

                # 下载patch
                for ver in vers_text.replace(" ", "").split(','):
                    patch_sec_path.joinpath(ver).mkdir(parents=True, exist_ok=True)
                    if len(urls) == 1:
                        r = requests.get(f'{url}^!/?format=TEXT')
                        patch = base64.b64decode(r.text).decode()
                        with open(patch_sec_path.joinpath(f'{ver}/{cve_name}.patch'), 'w+') as f:
                            f.write(patch)
                    elif len(urls) > 1:
                        for idx, url in enumerate(urls):
                            r = requests.get(f'{url}^!/?format=TEXT')
                            patch = base64.b64decode(r.text).decode()
                            with open(patch_sec_path.joinpath(f'{ver}/{cve_name}-{idx+1}.patch'), 'w+') as f:
                                f.write(patch)
                    else:
                        print(f'[-] {cve_name} found no patch!')
                    results[ver].update(item)
            if idx == component_idx:
                component_text = col.text.strip()
                item = {cve_name: {
                    'fixes': urls,
                    'affected_component': component_text,
                    'type': type_text,
                    'severity': severity_text
                }}
                item[cve_name].update(get_cve(cve_name))

                patch_sec_path.joinpath(f'others/{_id}').mkdir(parents=True, exist_ok=True)
                with open(patch_sec_path.joinpath(f'others/{_id}/{cve_name}'), 'w+') as f:
                    f.write(json.dumps(item, indent=4))
                results['others'][_id].update(item)


def updateThread(url: str):
    """更新线程"""

    r = requests.get(url)
    soup = BeautifulSoup(r.content, 'html.parser')
    ids = [
        'android-runtime',
        'framework',
        'media-framework',
        'system',
        '01android-runtime',
        '01framework',
        '01media-framework',
        '01system',
        'kernel-compoents', # 2021-01-01,
        'kernel-components',
        'kernel',
        '01kernel',
        '05kernel',
        'qualcomm-components',
        'qualcomm-closed-source'
    ]
    for i in ids:
        extract_section(soup, i)
    return thread_result


def update(args=None):
    """更新CVE补丁库"""

    r = requests.get('https://source.android.com/security/bulletin')
    root = etree.HTML(r.content)
    table = root.xpath('/html/body/section/section/main/devsite-content/article/div[2]/table/tr')
    urls = []
    for i in table:
        href = i.xpath('td/a/@href')
        if href and 'android' not in href[0]:
            url = f'https://source.android.com/{href[0]}'
            urls.append(url)

    tasks = []
    executor = ThreadPoolExecutor(20)
    for url in urls:
        tasks.append(executor.submit(updateThread, url))
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
        print(e, cve_name, patch.stem)
    finally:
        return cve_name, result


def scan(args):
    """对比所有CVE补丁与所有补丁"""

    repo_path = Path(args.repo).expanduser().absolute()
    repo_tool = repo_path.joinpath('.repo/repo/repo')

    aosp = requests.get('https://android.googlesource.com/?format=TEXT').text.splitlines()
    hmi = []
    output, ret_code = shell_cmd(f'cd {repo_path} && {repo_tool} list')
    for line in output.splitlines():
        hmi.append(line.split(':')[1].strip())

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
    parser_update.set_defaults(func=update)

    parser_scan = subparsers.add_parser('scan', help='scan CVE patch in Android repository')
    parser_scan.add_argument('--repo', help='Android git repository path', type=str, required=True)
    parser_scan.add_argument('--version', help='Android version number', type=str, required=True)
    parser_scan.set_defaults(func=scan)

    return parser.parse_args()


if __name__ == '__main__':
    print('***************** poc_patch_android.py ****************')
    report_path = Path(__file__).absolute().parents[1].joinpath('data/SecScan')
    report_path.mkdir(parents=True, exist_ok=True)
    patch_sec_path = report_path.joinpath('patch_sec_android')

    results = defaultdict(dict)
    results['others'] = defaultdict(dict)
    args = argument()
    args.func(args)
    with open(patch_sec_path.joinpath('android_cves.json'), 'w+') as f:
        f.write(json.dumps(results, indent=4))
