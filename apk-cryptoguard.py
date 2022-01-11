#!/usr/bin/python3

import argparse
from pathlib import Path
from utils import shell_cmd_ret_code


def analysis(apk_path: Path):
    print(f'[+] {apk_path}')
    report_name = f'{apk_path.stem}-cryptoguard.json'
    report_file = apk_path.parent.joinpath(report_name)

    cmd = f'export sdkman="/home/runner/.sdkman/candidates" && \
        docker run --rm -v {str(apk_path.parent)}:/apk frantzme/cryptoguard $sdkman/java/current/bin/java -jar /Notebook/cryptoguard.jar \
            -android $sdkman/android/current -java $sdkman/java/7.0.322-zulu/ -in apk -s /apk/{apk_path.name} -o /apk/{report_name} -n'
    output, ret_code = shell_cmd_ret_code(cmd)

    if not report_file.exists():
        with open(str(report_file)+'.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", help="A directory containing APK to run static analysis", type=str, required=True)
    arg = parser.parse_args()
    return arg


if __name__ == '__main__':
    print('***************** apk-cryptoguard.py *****************')

    failed = []
    success_num = 0
    apk_dir = argument().apk
    if apk_dir:
        for apk in Path(apk_dir).rglob('*.apk'):
            ret = analysis(apk.absolute())
            if ret == 0:
                success_num += 1
            else:
                failed.append(str(apk))
    else:
        print('[!] 参数错误: python3 apk-cryptoguard.py --help')

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
