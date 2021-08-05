#!/usr/bin/python3

import json
import hashlib
import argparse
import requests
from pathlib import Path
from requests_toolbelt.multipart.encoder import MultipartEncoder


DEFAULT_SERVER = 'http://127.0.0.1:8000'


def get_md5(file_path: str):
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            md5.update(chunk)
    return md5.hexdigest()


class MobSF:
    """MobSF API"""

    def __init__(self, apikey, server=None):
        self.__server = server.rstrip('/') if server else DEFAULT_SERVER
        self.__apikey = apikey

    @property
    def server(self):
        return self.__server

    @property
    def apikey(self):
        return self.__apikey

    def upload(self, file_path: str):
        """上传一个文件

        :param file_path: 文件路径，支持apk, zip, ipa, appx
        :return:
        """
        print(f"Uploading {file_path} to {self.__server}")

        multipart_data = MultipartEncoder(
            fields={'file': (file_path, open(file_path, 'rb'), 'application/octet-stream')})
        headers = {'Content-Type': multipart_data.content_type, 'Authorization': self.__apikey}

        r = requests.post(f'{self.__server}/api/v1/upload', data=multipart_data, headers=headers)
        return r.status_code, r.json()

    def scan(self, scan_type, filename, scan_hash, rescan=False):
        """扫描一个已经上传的文件

        :param scan_type: xapk, apk, zip, ipa, appx
        :param filename: 文件名
        :param scan_hash: 扫描哈希
        :param rescan: True or False
        :return:
        """
        print(f"Requesting {self.__server} to scan {scan_hash} ({filename}, {scan_type})")

        post_dict = {'scan_type': scan_type,
                     'file_name': filename,
                     'hash': scan_hash,
                     're_scan': rescan}
        headers = {'Authorization': self.__apikey}

        r = requests.post(f'{self.__server}/api/v1/scan', data=post_dict, headers=headers)
        return r.status_code, r.json()

    def scans(self, page=1, page_size=100):
        """查看最近的扫描

        :param page:
        :param page_size:
        :return:
        """
        print(f'Requesting recent scans from {self.__server}')

        payload = {'page': page,
                   'page_size': page_size}
        headers = {'Authorization': self.__apikey}

        r = requests.get(f'{self.__server}/api/v1/scans', params=payload, headers=headers)
        return r.status_code, r.json()

    def report_pdf(self, scan_hash, pdf_path=None):
        """生成PDF报告并保存

        :param scan_hash: 扫描哈希
        :param pdf_path: PDF路径
        :return:
        """
        pdf_path = pdf_path if pdf_path else 'report.pdf'

        print(f'Requesting PDF report for scan {scan_hash}')

        headers = {'Authorization': self.__apikey}
        data = {'hash': scan_hash}

        r = requests.post(f'{self.__server}/api/v1/download_pdf', data=data, headers=headers, stream=True)

        print(f'Writing PDF report to {pdf_path}')
        with open(pdf_path, 'wb') as pdf:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    pdf.write(chunk)

        return r.status_code, pdf_path

    def report_json(self, scan_hash):
        """生成JSON报告

        :param scan_hash: 扫描哈希
        :return:
        """
        print(f'Requesting JSON report for scan {scan_hash}')

        headers = {'Authorization': self.__apikey}
        data = {'hash': scan_hash}

        r = requests.post(f'{self.__server}/api/v1/report_json', data=data, headers=headers)
        return r.status_code, r.json()

    def view_source(self, scan_type, file_path, scan_hash):
        """获取源文件

        :param scan_type: apk/ipa/studio/eclipse/ios
        :param file_path: 文件相对路径
        :param scan_hash: 扫描哈希
        :return:
        """
        print(f'Requesting source files for {scan_hash} ({file_path}, {scan_type})')

        headers = {'Authorization': self.__apikey}
        data = {'type': scan_type,
                'hash': scan_hash,
                'file': file_path}

        r = requests.post(f'{self.__server}/api/v1/view_source', data=data, headers=headers)
        return r.json()

    def delete_scan(self, scan_hash):
        """删除一次扫描

        :param scan_hash: 扫描哈希
        :return:
        """
        print(f'Requesting {self.__server} to delete scan {scan_hash}')

        headers = {'Authorization': self.__apikey}
        data = {'hash': scan_hash}

        r = requests.post(f'{self.__server}/api/v1/delete_scan', data=data, headers=headers)
        return r.status_code, r.json()


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", help="Mobsf REST API key", type=str, required=True)
    parser.add_argument("-f", "--file", help="APK file to scanning", type=str, required=False)
    parser.add_argument("-d", "--dir", help="Target directory", type=str, required=False)
    arg = parser.parse_args()
    return arg


def analysis(apk_path: str):
    """一次完整的分析过程
    
    :param apk_path: APK路径
    :return: True or False
    """
    # md5 = get_md5(apk_path)
    ret_code, data = init.upload(apk_path)
    if ret_code != 200:
        print(f"[!] 上传失败: {apk_path}")
        return False
    else:
        md5 = data['hash']
        ret_code, data = init.scan(data['scan_type'], data['file_name'], md5)
        if ret_code != 200:
            print(f"[!] 扫描失败: {apk_path}")
            return False
        else:
            file_path = Path(apk_path)
            json_path = file_path.parent.joinpath(f'{file_path.stem}-mobsf.json')
            with open(json_path, 'w+') as f:
                f.write(json.dumps(data, indent=4))
            
            pdf_path = file_path.parent.joinpath(f'{file_path.stem}-mobsf.pdf')
            ret_code, data = init.report_pdf(md5, str(pdf_path))
            if ret_code != 200:
                print(f"[!] 下载报告失败: {apk_path}")
                return False
            else:
                print()
                return True


if __name__ == '__main__':
    print('******************* apk-mobsf.py *********************')

    failed = []
    args = argument()
    init = MobSF(args.key)
    if args.file and not args.dir:
        analysis(args.file)
    elif args.dir and not args.file:
        success_num = 0
        for apk in Path(args.dir).rglob('*.apk'):
            ret = analysis(str(apk))
            if ret:
                success_num += 1
            else:
                failed.append(str(apk))
        print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
        print({'\n'.join(failed)})
    else:
        print('[!] 参数错误（-f和-d只能有一个）: python3 apk-mobsf.py --help')
