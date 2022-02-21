#!/usr/bin/python3

import sys
import argparse
import requests
from pathlib import Path
from requests_toolbelt.multipart.encoder import MultipartEncoder

sys.path.append('..')
from utils import get_host_ip

DEFAULT_SERVER = f'http://{get_host_ip()}:8000'


class MobSF:
    def __init__(self, apikey: str, server: str=''):
        self.server = server.rstrip('/') if server else DEFAULT_SERVER
        self.apikey = apikey

    def upload(self, file_path: Path):
        """上传一个文件 apk, zip, ipa, appx"""
        multipart_data = MultipartEncoder(
            fields={'file': (str(file_path), open(file_path, 'rb'), 'application/octet-stream')})
        headers = {'Content-Type': multipart_data.content_type, 'Authorization': self.apikey}

        r = requests.post(f'{self.server}/api/v1/upload', data=multipart_data, headers=headers)
        return r.status_code, r.json()

    def scan(self, scan_type: str, filename: str, scan_hash: str, rescan: bool=False):
        """扫描一个已经上传的文件 xapk, apk, zip, ipa, appx"""
        post_dict = {'scan_type': scan_type,
                     'file_name': filename,
                     'hash': scan_hash,
                     're_scan': rescan}
        headers = {'Authorization': self.apikey}

        r = requests.post(f'{self.server}/api/v1/scan', data=post_dict, headers=headers)
        return r.status_code, r.json()

    def scans(self, page: int=1, page_size: int=100):
        """查看最近的扫描"""
        payload = {'page': page,
                   'page_size': page_size}
        headers = {'Authorization': self.apikey}

        r = requests.get(f'{self.server}/api/v1/scans', params=payload, headers=headers)
        return r.status_code, r.json()

    def report_pdf(self, scan_hash: str, pdf_path: Path):
        """生成PDF报告并保存"""
        headers = {'Authorization': self.apikey}
        data = {'hash': scan_hash}

        r = requests.post(f'{self.server}/api/v1/download_pdf', data=data, headers=headers, stream=True)

        with open(pdf_path, 'wb+') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)

        return r.status_code

    def report_json(self, scan_hash: str, json_path: Path):
        """生成JSON报告"""
        headers = {'Authorization': self.apikey}
        data = {'hash': scan_hash}

        r = requests.post(f'{self.server}/api/v1/report_json', data=data, headers=headers)

        with open(json_path, 'w+') as f:
            f.write(r.json())

        return r.status_code

    def delete_scan(self, scan_hash: str):
        """删除一次扫描"""
        print(f'Requesting {self.server} to delete scan {scan_hash}')

        headers = {'Authorization': self.apikey}
        data = {'hash': scan_hash}

        r = requests.post(f'{self.server}/api/v1/delete_scan', data=data, headers=headers)
        return r.status_code, r.json()


def analysis(apikey: str, apk_path: Path):
    init = MobSF(apikey)

    ret_code, data = init.upload(apk_path)
    if ret_code != 200:
        return 1

    md5 = data['hash']
    ret_code, data = init.scan(data['scan_type'], data['file_name'], md5)
    if ret_code != 200:
        return 2

    pdf_path = apk_path.parent.joinpath('SecScan/mobsf.pdf')
    ret_code = init.report_pdf(md5, pdf_path)
    if ret_code != 200:
        return 3

    return 0


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    parser.add_argument("--key", help="Mobsf REST API key", type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************* apk_mobsf.py *********************')

    failed = []
    success_num = 0
    args = argument()
    apk_dirs = open(args.config, 'r').read().splitlines()

    for apk in apk_dirs:
        print(f'[+] [mobsf] {apk}')
        apk_path = Path(apk)

        report_path = apk_path.parent.joinpath('SecScan')
        if not report_path.exists():
            report_path.mkdir()

        ret = analysis(args.key, apk_path)
        if ret:
            failed.append(apk)
        else:
            success_num += 1

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
