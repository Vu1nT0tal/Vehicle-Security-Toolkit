#!/usr/bin/python3

import sys
import shutil
import argparse
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd


env = {
    'ANDROID_HOME': Path('~').expanduser().joinpath('Android/Sdk'),
    'ANDROID_SDK_ROOT': Path('~').expanduser().joinpath('Android/Sdk'),
    'DOTNET_CLI_HOME': '/tmp/dotnethome',
    'LC_ALL': 'C.UTF-8'
}


def analysis_cli(src_path: Path, tools_path: Path):
    print(f'[+] {src_path} - cli')

    scanner = tools_path.joinpath('dependency-check/bin/dependency-check.sh')
    report = src_path.joinpath('dependency-check-report.html')
    cmd = f'{scanner} -s {src_path} -o {report}'
    return shell_cmd(cmd)


def analysis_gradle(src_path: Path, tools_path: Path):
    print(f'[+] {src_path} - gradle')
    local_env = env.copy()
    local_env.update({'cwd': src_path})
    build1 = str(src_path.joinpath('build.gradle'))

    # 备份
    shutil.copy(build1, build1+'.bak')

    # 修改
    sed1 = 'sed -i \"/dependencies {/a\classpath \'org.owasp:dependency-check-gradle:6.5.3\'\" '+build1
    sed2 = 'sed -i \"/repositories {/a\mavenCentral()\" '+build1
    sed3 = 'sed -i \"/allprojects {/a\\apply plugin: \'org.owasp.dependencycheck\'\\ndependencyCheck {scanConfigurations += \'releaseRuntimeClasspath\'}\" '+build1

    shell_cmd(f'{sed1} && {sed2} && {sed3}')

    # 运行

    cmd = f'chmod +x gradlew && ./gradlew dependencyCheckAnalyze'
    output, ret_code = shell_cmd(cmd, local_env)

    if 'Could not determine java version' in output:
        # 切换java版本
        local_env.update({'java': 8})
        output, ret_code = shell_cmd(cmd, local_env)

    if ret_code == 0:
        # 生成依赖关系图
        cmd = f'chmod +x gradlew && ./gradlew -q projects 2>&1 | grep Project | cut -d "\'" -f 2'
        output, _ = shell_cmd(cmd, local_env)
        # 遍历根模块和所有子模块
        for subproject in output.splitlines()+['']:
            cmd = f'chmod +x gradlew && ./gradlew {subproject}:dependencies'
            output, _ = shell_cmd(cmd, local_env)

            subdir = subproject.replace(':', '/')[1:] if subproject else '.'
            with open(src_path.joinpath(f'{subdir}/build/reports/dependency-check-graph.txt'), 'w+') as f:
                f.write(output)
    else:
        print(f'[-] {src_path} gradlew 运行失败，尝试 cli')
        output, ret_code = analysis_cli(src_path, tools_path)

    # 恢复
    shutil.move(build1+'.bak', build1)

    # 清理
    shell_cmd('./gradlew clean', local_env)
    shutil.rmtree(src_path.joinpath('.gradle'), ignore_errors=True)
    #for i in list(Path(build1).parent.rglob('dependency-check-report.html')):
    #    shutil.rmtree(i.parent, ignore_errors=True)
    return output, ret_code


def analysis(src_path: Path, tools_path: Path, mode: str):
    if mode == 'cli':
        output, ret_code = analysis_cli(src_path, tools_path)
    elif mode == 'gradle':
        output, ret_code = analysis_gradle(src_path, tools_path)
    else:
        return False

    if ret_code != 0:
        with open(src_path.joinpath(f'dependency-check-report.html.error'), 'w+') as f:
            f.write(output)

    return ret_code


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing source code path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('****************** src_depcheck.py *******************')
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')

    failed = []
    success_num = 0
    src_dirs = open(argument().config, 'r').read().splitlines()

    for src in src_dirs:
        src_path = Path(src)

        if src_path.joinpath('gradlew').exists():
            ret = analysis(src_path, tools_path, 'gradle')
        else:
            ret = analysis(src_path, tools_path, 'cli')

        if ret:
            failed.append(src)
        else:
            success_num += 1

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
