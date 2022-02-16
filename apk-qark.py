#!/usr/bin/python3

import shutil
import argparse
from pathlib import Path
from utils import shell_cmd


def analysis(apk_path: Path, mode: str, report: str = None):
    print(f'[+] {apk_path}')

    report_type = 'html' if report is None else report
    report_file = apk_path.parent.joinpath(f'report.{report_type}')
    new_report_file = apk_path.parent.joinpath(f'{apk_path.stem}-qark.{report_type}')

    cmd = f'qark --{mode} {apk_path} --report-type {report_type} --report-path {apk_path.parent}'
    output, ret_code = shell_cmd(cmd)

    if report_file.exists():
        report_file.rename(new_report_file)
    else:
        with open(f'{new_report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", help="A directory containing APK to decompile and run static analysis", type=str, required=False)
    parser.add_argument("--java", help="A directory containing Java code to run static analysis.", type=str, required=False)
    parser.add_argument("--report", help="Type of report to generate [html|xml|json|csv]", type=str, required=False)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************** apk-qark.py *********************')

    failed = []
    success_num = 0
    args = argument()
    if args.apk and not args.java:
        for apk in Path(args.apk).rglob('*.apk'):
            ret = analysis(apk, 'apk', args.report)
            if ret == 0:
                success_num += 1
            else:
                failed.append(str(apk))
    elif args.java and not args.apk:
        for java in Path(args.java).rglob('jadx_java'):
            ret = analysis(java, 'java', args.report)
            if ret == 0:
                success_num += 1
            else:
                failed.append(str(java))
    else:
        print('[!] 参数错误（--apk和--java只能有一个）: python3 apk-qark.py --help')

    shutil.rmtree(Path(__file__).parent.joinpath('build'), ignore_errors=True)
    Path(__file__).parent.joinpath('classes-error.zip').unlink(missing_ok=True)
    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
