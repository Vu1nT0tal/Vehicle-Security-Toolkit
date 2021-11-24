#!/usr/bin/python3

import shutil
import argparse
from pathlib import Path
from utils import shell_cmd_ret_code


def analysis(path: Path, mode: str, report: str = None):
    print(f'[+] {path}')

    report_type = 'html' if report is None else report
    report_file = path.parent.joinpath(f'report.{report_type}')
    new_report_file = path.parent.joinpath(f'{path.stem}-qark.{report_type}')

    cmd = f'qark --{mode} {str(path)} --report-type {report_type} --report-path {str(path.parent)}'
    output, ret_code = shell_cmd_ret_code(cmd)

    if report_file.exists():
        report_file.rename(new_report_file)
    else:
        with open(str(new_report_file)+'.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", help="A directory containing APK to decompile and run static analysis", type=str, required=False)
    parser.add_argument("--java", help="A directory containing Java code to run static analysis.", type=str, required=False)
    parser.add_argument("--report", help="Type of report to generate [html|xml|json|csv]", type=str, required=False)
    arg = parser.parse_args()
    return arg


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
            ret = 0
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
