#!/usr/bin/python3

import os
import json
import argparse
import requests
from tqdm import tqdm
from pathlib import Path
from collections import defaultdict


class CVEScan:
    def __init__(self, args):
        self.file = Path(args.file)
        self.output = self.file.parent.joinpath(f'{self.file.stem}-output.json') if not args.output else Path(args.output)
        self.console = self.output.parent.joinpath(f'{self.output.stem}-console.txt')
        self.result = self.output.parent.joinpath(f'{self.output.stem}-result.txt')

        if self.output.exists() or self.console.exists() or self.result.exists():
            self.output.unlink(missing_ok=True)
            self.console.unlink(missing_ok=True)
            self.result.unlink(missing_ok=True)

    def scan(self):
        print(f'[+] CVE漏洞扫描...{self.file}')
        cmd = f'cve-bin-tool {self.file} --report -f json -o {self.output} > {self.console}'
        os.system(cmd)

        print(f'扫描结果输出: {self.output}')
        print(f'控制台输出: {self.console}')

    def parse_result(self):
        print(f'[+] CVE数据解析...')

        result = defaultdict(list)
        try:
            with open(self.output, 'r') as f:
                data = json.load(f)

                cache = {}
                for item in tqdm(data):
                    cve_number = item['cve_number']
                    if cve_number == 'UNKNOWN':
                        continue

                    cve_info = {'cwe': '', 'summary': '', 'references': []}
                    if cve_number in cache:
                        cve_info = cache[cve_number]
                    else:
                        req = requests.get(f"https://cve.circl.lu/api/cve/{cve_number}")
                        if req.status_code == 200:
                            req_json = req.json()
                            cve_info = {
                                'cwe': req_json['cwe'],
                                'summary': req_json['summary'],
                                'references': req_json['references']
                            }
                            cache[cve_number] = cve_info

                    if item['cvss_version'] == '3':
                        cvss = {'cvss3': item['score']}
                    else:
                        cvss = {'cvss2': item['score']}
                    result[f"{item['vendor']}.{item['product']}.{item['version']}"] += [
                        dict({'paths': item['paths'], 'cve': cve_number}, **cvss, **cve_info), ]

            with open(self.result, 'w+') as f:
                f.write(json.dumps(result, indent=4))
            print(f'解析结果输出: {self.result}')
        except Exception as e:
            print(f'[!] 解析错误: {e}')


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="File or directory to scanning", type=str, required=True)
    parser.add_argument("-o", "--output", help="Write to file results", type=str, required=False)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************* bin-cvescan.py *******************')

    args = argument()
    init = CVEScan(args)
    init.scan()
    init.parse_result()
