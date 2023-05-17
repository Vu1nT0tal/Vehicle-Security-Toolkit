#!/usr/bin/python3

import sys
import time
import pyfiglet
import argparse
import requests
from lxml import etree
from pathlib import Path

sys.path.append('..')
from utils import *


DEFAULT_SERVER = f'http://{get_host_ip()}:8888'

class Audit:
    def __init__(self, token: str, server: str='') -> None:
        self.server = server.rstrip('/') if server else DEFAULT_SERVER
        self.token = token

    def app_list(self):
        """列出app"""

        headers = {'Authorization': f'Token {self.token}'}
        r = requests.get(url=f'{self.server}/api/v1/app/', headers=headers)
        return r.json()

    def app_create(self) -> int:
        """创建app"""

        headers = {'Authorization': f'Token {self.token}'}
        data = {'name': 'test', 'description': 'test'}
        r = requests.post(url=f'{self.server}/api/v1/app/', headers=headers, data=data)
        return r.json()['id']

    def app_delete(self, app_id: int):
        """删除app"""

        headers = {'Authorization': f'Token {self.token}'}
        data = {'id': app_id}
        r = requests.delete(url=f'{self.server}/api/v1/app/{app_id}', headers=headers, data=data)
        return r.text

    def scan_list(self) -> tuple:
        """列出扫描"""
        success = []
        failed = []
        headers = {'Authorization': f'Token {self.token}'}
        for i in range(1, 50):
            r = requests.get(url=f'{self.server}/api/v1/scan/?page={i}', headers=headers)
            if r.status_code == 404:
                break
            success += [i['description'] for i in r.json()['results'] if i ['status'] == 'Finished']
            failed += [i['description'] for i in r.json()['results'] if i ['status'] == 'Error']
        return success, failed

    def scan_create(self, apk: Path, app: int):
        """创建扫描"""
        headers = {'Authorization': f'Token {self.token}'}
        data = {
            'description': apk,
            'app': app
        }
        files = {
            'apk': (
                apk.name,
                open(apk, 'rb')
            )
        }
        r = requests.post(url=f'{self.server}/api/v1/scan/', headers=headers, data=data, files=files)
        return r.json()

    def scan_read(self, scan_id: int) -> int:
        """获取扫描进度"""

        headers = {'Authorization': f'Token {self.token}'}
        data = {'id': scan_id}
        r = requests.get(url=f'{self.server}/api/v1/scan/{scan_id}', headers=headers, data=data)
        return r.json()

    @staticmethod
    def get_token(username: str, password: str) -> str:
        """获取API token"""

        data = {
            'username': username,
            'password': password
        }
        r = requests.post(url=f'{DEFAULT_SERVER}/api/v1/auth-token/', data=data)
        return r.json()['token']

    @staticmethod
    def register(username: str, password: str) -> int:
        """注册用户"""

        r = requests.get(url=f'{DEFAULT_SERVER}/accounts/register/')
        csrf_token = r.cookies.get('csrftoken')
        csrfmiddlewaretoken = etree.HTML(r.text).xpath('/html/body/div[1]/form/input/@value')[0]

        cookies = {'csrftoken': csrf_token}
        data = {
            'csrfmiddlewaretoken': csrfmiddlewaretoken,
            'username': username,
            'first_name': '123', 'last_name': '123', 'email': '123@123.com',
            'password1': password, "password2": password
        }
        requests.post(url=f'{DEFAULT_SERVER}/accounts/register/', cookies=cookies, data=data)


def init_audit():
    # 注册用户并获取token
    username = 'auditor'
    password = 'audit123'
    Audit.register(username, password)
    token = Audit.get_token(username, password)
    audit = Audit(token)

    # 确保只有一个app
    r = audit.app_list()
    if r['count'] != 1:
        for i in r['results']:
            audit.app_delete(i['id'])
        app_id = audit.app_create()
    else:
        app_id = r['results'][0]['id']

    print_focus(f'[audit] token: {token}, app_id: {app_id}')
    return audit, app_id


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('apk_audit'))
    apk_dirs = open(argument().config, 'r').read().splitlines()

    # 初始化 Audit
    audit, app_id = init_audit()

    success_list, error_list = audit.scan_list()
    for apk in apk_dirs:
        print_focus(f'[audit] {apk}')

        # 避免重复
        if apk not in success_list+error_list:
            scan_id = audit.scan_create(Path(apk), app_id)['id']
            while True:
                r = audit.scan_read(scan_id)
                if r['status'] == 'Finished':
                    print_success('[audit] success')
                    break
                elif r['status'] == 'Error':
                    print_failed('[audit] failed')
                    break
                else:
                    time.sleep(5)
