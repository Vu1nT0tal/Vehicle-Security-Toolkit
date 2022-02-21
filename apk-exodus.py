#!/usr/bin/python3

import re
import json
import requests
import argparse
from pathlib import Path
from collections import namedtuple
from exodus_core.analysis.static_analysis import StaticAnalysis


def get_trackers():
    """将trackers缓存下来，避免每个扫描都下载一遍"""
    signatures = []
    exodus_url = "https://reports.exodus-privacy.eu.org/api/trackers"
    r = requests.get(exodus_url)
    data = r.json()
    for e in data['trackers']:
        signatures.append(namedtuple('tracker', data['trackers'][e].keys())(*data['trackers'][e].values()))

    compiled_tracker_signature = [re.compile(track.code_signature) for track in signatures]

    return signatures, compiled_tracker_signature


class AnalysisHelper(StaticAnalysis):
    def create_json_report(self):
        return {
            'application': {
                'handle': self.get_package(),
                'version_name': self.get_version(),
                'version_code': self.get_version_code(),
                'uaid': self.get_application_universal_id(),
                'name': self.get_app_name(),
                'permissions': self.get_permissions(),
                'libraries': [library for library in self.get_libraries()],
            },
            'apk': {
                'path': self.apk_path,
                'checksum': self.get_sha256(),
            },
            'trackers': [
                {'name': t.name, 'id': t.id} for t in self.detect_trackers()
            ],
        }


def analysis(apk_path: Path):
    print(f'[+] {apk_path}')
    report_file = apk_path.parent.joinpath(f'{apk_path.stem}-exodus.json')

    analysis = AnalysisHelper(str(apk_path))
    analysis.signatures = signature
    analysis.compiled_tracker_signature = compiled_signature
    # analysis.load_trackers_signatures()
    report = json.dumps(analysis.create_json_report(), indent=4)
    with open(report_file, 'w+') as f:
        f.write(report)


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="A config file containing APK path", type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************* apk-exodus.py ********************')

    success_num = 0
    apk_dirs = open(argument().config, 'r').read().splitlines()

    signature, compiled_signature = get_trackers()
    for apk in apk_dirs:
        analysis(Path(apk))
        success_num += 1

    print(f'扫描完成: {success_num}')
