#!/usr/bin/python3

import os
import sys
import json
import argparse
import asyncio
from aiohttp import ClientSession
from concurrent.futures import ProcessPoolExecutor
from thefuzz import fuzz
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color

# https://kernel.org/category/releases.html
KERNEL_VERSION = {
    # LTS
    '4.9': '69973b830859bc6529a7a0468ba0d80ee5117826',
    '4.14': 'bebc6082da0a9f5d47a1ea2edc099bf671058bd4',
    '4.19': '84df9525b0c27f3ebc2ebb1864fa62a97fdedb7d',
    '5.4': '219d54332a09e8d8741c1e1982f5eae56099de85',
    '5.10': '2c85ebc57b3e1817b6ce1a6b703928e113a90442',
    '5.15': '8bb7eca972ad531c9b149c0a51ab43a417385813',

    # others
    '4.4': 'afd2ff9b7e1b367172f18ba7f693dfb62bdcb2dc',
    '5.11': 'f40ddce88593482919761f74910f42f4b84c004b',
    '5.12': '9f4ad9e425a1d3b6a34617b8ea226d56a119a717',
    '5.13': '62fb9874f5da54fdb243003b386128037319b219',
    '5.14': '7d2a07b769330c34b4deabeed939325c77a7ec2f',
    '5.16': 'df0cc57e057f18e44dac8e6c18aba47ab53202f9',
}


def update(args=None):
    async def download(sem, url: str, patch: Path):
        async with sem:
            async with ClientSession() as session:
                async with session.get(url) as r:
                    data = await r.text()
                    with open(patch, 'w+') as f:
                        f.write(data)

    cves_path = Path('~/github/linux_kernel_cves').expanduser()
    patch_path = cves_path.joinpath('patch')

    if cves_path.exists():
        output, ret_code = shell_cmd('git pull', env={'cwd': '~/github/linux_kernel_cves'})
    else:
        output, ret_code = shell_cmd('git clone --depth=1 https://github.com/nluedtke/linux_kernel_cves.git ~/github/linux_kernel_cves')
    if ret_code != 0:
        print(output)
        return False

    with open(cves_path.joinpath('data/stream_fixes.json'), 'r') as f:
        stream_fixes = json.load(f)

    tasks = []
    sem = asyncio.Semaphore(100)
    loop = asyncio.get_event_loop()
    for cve, value in stream_fixes.items():
        for version, commit in value.items():
            patch_path.joinpath(version).mkdir(parents=True, exist_ok=True)
            url = f'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={commit["cmt_id"]}'
            patch = patch_path.joinpath(f'{version}/{cve}-{commit["cmt_id"]}.patch')
            task = asyncio.ensure_future(download(sem, url, patch))
            tasks.append(task)
    try:
        loop.run_until_complete(asyncio.wait(tasks))
        print(f'[+] Download {len(tasks)} patchs: {patch_path}')
    finally:
        loop.close()


def compareThread(cve: Path, patch_path: Path):
    cve_name = '-'.join(cve.stem.split('-')[:3])
    result = {cve_name: {
        'url': f'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=linux-{cve.parent.name}.y&id={cve.stem.split("-")[-1]}',
        'scan': {},
    }}
    try:
        f1 = open(cve).read()
        for patch in patch_path.glob('*'):
            f2 = open(patch).read()
            ratio = fuzz.ratio(f1, f2)
            if ratio > 70:
                result[cve_name]['scan'].update({ratio: patch.stem})
                print(f'[+] {cve_name} found ({ratio}%): {patch.stem}')
        if not result[cve_name]['scan']:
            print(f'[-] {cve_name} not found!')
    except Exception as e:
        print(e, cve_name, patch.stem)
    finally:
        return cve_name, result


def scan(args):
    cves_path = Path('~/github/linux_kernel_cves').expanduser()
    repo_path = Path(args.repo).expanduser().absolute()
    report_path = Path(__file__).absolute().parents[1].joinpath('data/SecScan')
    patch_path = report_path.joinpath('patch_all')

    cmd = f'git format-patch -N {KERNEL_VERSION[args.version]} -o {patch_path}'
    output, ret_code = shell_cmd(cmd, env={'cwd': repo_path})
    number, _ = shell_cmd(f'ls {patch_path} | wc -l')
    if ret_code != 0:
        print(output)
        return False
    else:
        print(f'[+] Generate {number.strip()} patchs: {patch_path}')

    tasks = []
    executor = ProcessPoolExecutor(os.cpu_count()-1)
    for cve in cves_path.joinpath(f'patch/{args.version}').glob('*'):
        tasks.append(executor.submit(compareThread, cve, patch_path))
    executor.shutdown(True)

    results = {}
    report_file = report_path.joinpath('poc_patch.json')
    with open(report_file, 'w+') as f1, open(cves_path.joinpath('data/kernel_cves.json')) as f2:
        cves_info = json.load(f2)
        for task in tasks:
            cve_name, result = task.result()
            result[cve_name].update(cves_info[cve_name])
            results.update(result)
        f1.write(json.dumps(results, indent=4))
        print(f'[+] Results saved in {report_file}')


def argument():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_update = subparsers.add_parser('update', help='update CVE patch data')
    parser_update.set_defaults(func=update)

    parser_scan = subparsers.add_parser('scan', help='scan CVE patch in kernel repository')
    parser_scan.add_argument('--repo', help='kernel git repository path', type=str, required=True)
    parser_scan.add_argument('--version', help='kernel version number', type=str, required=True)
    parser_scan.set_defaults(func=scan)

    return parser.parse_args()


if __name__ == '__main__':
    print('********************* poc_patch.py ********************')
    args = argument()
    args.func(args)
