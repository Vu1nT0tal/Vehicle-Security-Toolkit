#!/usr/bin/python3

import shutil
import argparse
from pathlib import Path
from utils import shell_cmd_ret_code


report_path = Path(__file__).parent.joinpath('data/scan/depcheck')
report_path.mkdir(parents=True, exist_ok=True)


def analysis(src_path: Path, mode: str):
    print(f'[+] {src_path}')
    report_file = report_path.joinpath(f'{src_path.stem}-depcheck.html')

    if mode == 'cli':
        scanner = Path(__file__).parent.joinpath('tools/dependency-check/bin/dependency-check.sh')
        cmd = f'{scanner} -s {src_path} -o {report_file}'
        output, ret_code = shell_cmd_ret_code(cmd)

    elif mode == 'gradle':
        build1 = str(src_path.joinpath('build.gradle'))
        build2 = list(src_path.rglob('build.gradle'))[-1]

        # 备份
        shutil.copy(build1, build1+'.bak')
        shutil.copy(str(build2), str(build2)+'.bak')

        # 修改
        sed1 = 'sed -i \"/dependencies {/a\classpath \'org.owasp:dependency-check-gradle:6.5.3\'\" '+build1
        sed2 = 'sed -i \"/repositories {/a\mavenCentral()\" '+build1
        sed3 = 'echo \"\napply plugin: \'org.owasp.dependencycheck\'\" >> '+str(build2)

        shell_cmd_ret_code(f'{sed1} && {sed2} && {sed3}')

        # 运行
        env = {
            'ANDROID_HOME': Path('~').expanduser().joinpath('Android/Sdk'),
            'ANDROID_SDK_ROOT': Path('~').expanduser().joinpath('Android/Sdk'),
            'DOTNET_CLI_HOME': '/tmp/dotnethome',
            'LC_ALL': 'C.UTF-8'
        }
        cmd = f'cd {src_path} && chmod +x gradlew && ./gradlew dependencyCheckAnalyze'
        output, ret_code = shell_cmd_ret_code(cmd, env=env)
        if 'Could not determine java version' in output:
            cmd2 = f'source {Path("~").expanduser().joinpath(".sdkman/bin/sdkman-init.sh")} && sdk use java 8.0.312-tem && {cmd}'
            output, ret_code = shell_cmd_ret_code(cmd2, env=env, exe='/bin/zsh')

        org_file = build2.parent.joinpath('build/reports/dependency-check-report.html')
        if org_file.exists():
            org_file.replace(report_file)
            shutil.rmtree(build2.parent.joinpath('build'), ignore_errors=True)

        # 恢复
        shutil.move(build1+'.bak', build1)
        shutil.move(str(build2)+'.bak', str(build2))
    else:
        return False

    if not report_file.exists():
        with open(f'{report_file}.error', 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="A config file containing source code paths to run analysis", type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('****************** src-depcheck.py *******************')

    failed = []
    success_num = 0
    config_file = argument().config
    if config_file:
        src_dirs = open(config_file, 'r').read().splitlines()

        for src in src_dirs:
            src_path = Path(src)
            if src_path.joinpath('gradlew').exists():
                ret = analysis(src_path, 'gradle')
            else:
                ret = analysis(src_path, 'cli')

            if ret == 0:
                success_num += 1
            else:
                failed.append(src)
    else:
        print('[!] 参数错误: python3 src-depcheck.py --help')

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
