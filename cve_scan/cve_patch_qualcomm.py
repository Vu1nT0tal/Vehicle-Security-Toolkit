#!/usr/bin/python3

import sys
import json
import asyncio
import calendar
import pyfiglet
import requests
import argparse
from lxml import etree
from pathlib import Path
from playwright.async_api import async_playwright

sys.path.append('..')
from utils import *


def get_patch(url: str):
    """获取patch"""
    url = url.strip('/')
    if 'source.codeaurora.org' in url:
        # 已迁移到codelinaro
        url = url.replace('commit/?id', 'commit?id')
        data = url.split('/')
        path = '/'.join(data[4:-1])
        id = data[-1].split('=')[1].split('_')[0]
        url = f'https://git.codelinaro.org/clo/{path}/-/commit/{id}'

    try:
        r = requests.get(f'{url}.diff').text
        if not r.startswith('diff'):
            print(f'Error url: {url}')
            return ''
        return r
    except Exception as e:
        print(f'Error url: {url}\n{e}')
        return ''


async def updateThread(browser, url):
    """更新线程"""
    async with sem:
        print(url)
        page = None
        try:
            page = await browser.new_page(locale='zh-CN')
            await page.goto(url, wait_until='networkidle', timeout=60000)

            html = etree.HTML(await page.content())
            if cves := html.xpath('//h3[@class="sectiontitle"]/text()'):
                for cve in cves:
                    data = html.xpath(f'//h3[@id="_{cve.lower()}"]/following-sibling::*[1]/tbody/tr/td/text()')

                    info = dict(zip(data[::2], data[1::2]))
                    if chips := info.get('Affected Chipsets*') or info.get('Affected Chipsets'):
                        info['Affected Chipsets'] = [i.strip() for i in chips.split(',')]
                        info.pop('Affected Chipsets*', None)

                    temp = html.xpath(f'//h3[@id="_{cve.lower()}"]/following-sibling::*[1]/tbody/tr/td/ul/li/a/text()')
                    urls = [i.strip() for i in temp if 'www.qualcomm.com/support' not in i]
                    info['Patch'] = urls
                    info.pop('Patch**', None)

                    # 下载补丁
                    for idx, url in enumerate(urls):
                        if patch := get_patch(url):
                            if len(urls) == 1:
                                file_path = patch_path.joinpath(f'{cve}.patch')
                            else:
                                file_path = patch_path.joinpath(f'{cve}-{idx+1}.patch')

                            with open(file_path, 'w+') as f:
                                f.write(patch)
                        else:
                            print(f'download faild: {url}')

                    results[cve] = info
            else:
                print(f'No CVEs found: {url}')
        except Exception as e:
            print(f'Error occurred: {url}\n{e}')
        finally:
            await page.close() if page else None


async def update(args=None):
    """更新漏洞库"""
    start_year = 2018
    end_year = 2023
    years = range(start_year, end_year + 1)
    months = [calendar.month_name[i].lower() for i in range(1, 13)]
    base_url = 'https://docs.qualcomm.com/product/publicresources/securitybulletin'

    urls = []
    for year in years:
        for mouth in months:
            url = f'{base_url}/{mouth.lower()}-{year}-bulletin.html'
            urls.append(url)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        await asyncio.gather(*(updateThread(browser, url) for url in urls))
        await browser.close()


async def scan(args=None):
    pass


def argument():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_update = subparsers.add_parser('update', help='update CVE patch data')
    parser_update.set_defaults(func=update)

    parser_scan = subparsers.add_parser('scan', help='scan CVE in source repository')
    parser_scan.add_argument('--repo', help='git repository path', type=str, required=True)
    parser_scan.set_defaults(func=scan)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('cve_patch_qualcomm'))
    report_path = Path(__file__).absolute().parents[1].joinpath('data/SecScan')
    patch_sec_path = report_path.joinpath('patch_sec_qualcomm')
    patch_path = patch_sec_path.joinpath('patch')
    patch_path.mkdir(parents=True, exist_ok=True)

    results = {}
    args = argument()
    sem = asyncio.Semaphore(os.cpu_count()-1)
    asyncio.run(args.func(args))

    with open(patch_sec_path.joinpath('qualcomm_cves.json'), 'w+') as f:
        json.dump(results, f, indent=4)
