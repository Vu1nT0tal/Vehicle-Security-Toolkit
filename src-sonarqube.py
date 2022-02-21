#!/usr/bin/python3

import re
import shutil
import argparse
from pathlib import Path
from sonarqube import SonarQubeClient
from utils import shell_cmd, get_host_ip


DEFAULT_SERVER = f'http://{get_host_ip()}:9000'
env = {
    'ANDROID_HOME': Path('~').expanduser().joinpath('Android/Sdk'),
    'ANDROID_SDK_ROOT': Path('~').expanduser().joinpath('Android/Sdk')
}


def cleanup(src_path: Path):
    """清理"""
    local_env = env.copy()
    local_env.update({'cwd': src_path})
    shell_cmd('./gradlew clean', local_env)
    shutil.rmtree(src_path.joinpath('.gradle'), ignore_errors=True)
    shutil.rmtree(src_path.joinpath('.scannerwork'), ignore_errors=True)


def gradle_build(src_path: Path):
    print(f'[+] {src_path} - build')

    local_env = env.copy()
    local_env.update({'cwd': src_path})
    if src_path.joinpath('gradlew').exists():
        build_cmd = f'chmod +x gradlew && ./gradlew build'
    else:
        build_cmd = f'gradle build'
    output, ret_code = shell_cmd(build_cmd, local_env)

    if 'Minimum supported Gradle version is 6' in output:
        local_env.update({'gradle': 6})
        output, ret_code = shell_cmd(build_cmd, local_env)

    if 'No version of NDK matched' in output:
        # 下载对应ndk重试
        for line in output.splitlines():
            if 'No version of NDK matched' in line:
                ndk_version = re.search(r'\d+\.(?:\d+\.)*\d+', line).group()
        sdkmanager = Path('~').expanduser().joinpath('Android/Sdk/cmdline-tools/latest/bin/sdkmanager')
        cmd = f'{sdkmanager} --install "ndk;{ndk_version} && {build_cmd}'
        output, ret_code = shell_cmd(cmd, local_env)

    if ret_code != 0:
        local_env.update({'java': 8})
        output, ret_code = shell_cmd(build_cmd, local_env)
    return output, ret_code


def analysis_cli(src_path: Path):
    print(f'[+] {src_path} - cli')

    cmd = f'docker run --rm -e SONAR_HOST_URL={DEFAULT_SERVER} -e SONAR_LOGIN={token} -v {src_path}:/usr/src sonarsource/sonar-scanner-cli -Dsonar.projectKey={src_path.name} -Dsonar.java.binaries=/usr/src'
    output, ret_code = shell_cmd(cmd)
    if ret_code != 0:
        print(f'[-] {src_path} cli 失败')
    cleanup(src_path)
    return output, ret_code


def analysis_gradle(src_path: Path, java: int = 11):
    print(f'[+] {src_path} - gradle')
    local_env = env.copy()
    local_env.update({'java': java, 'cwd': src_path})

    build1 = str(src_path.joinpath('build.gradle'))

    # 备份
    shutil.copy(build1, build1+'.bak')

    # 修改
    sed1 = 'sed -i \"/dependencies {/a\classpath \'org.sonarsource.scanner.gradle:sonarqube-gradle-plugin:3.3\'\" '+build1
    sed2 = 'sed -i \"/repositories {/a\mavenCentral()\" '+build1
    sed3 = 'sed -i \"/allprojects {/a\\apply plugin: \'org.sonarqube\'\" '+build1

    shell_cmd(f'{sed1} && {sed2} && {sed3}')

    # 运行
    cmd = f'chmod +x gradlew && ./gradlew sonarqube -Dsonar.projectKey={src_path.name} -Dsonar.host.url={DEFAULT_SERVER} -Dsonar.login={token}'
    output, ret_code = shell_cmd(cmd, local_env)

    # 恢复
    shutil.move(build1+'.bak', build1)

    if ret_code != 0:
        print(f'[-] {src_path} gradlew 失败')
    cleanup(src_path)
    return output, ret_code


def analysis(src_path: Path, mode: str):
    output, ret_code = gradle_build(src_path)
    if ret_code == 0:
        if mode == 'cli':
            output, ret_code = analysis_cli(src_path)
        elif mode == 'gradle':
            output, ret_code = analysis_gradle(src_path)
            if ret_code != 0:
                output2, ret_code = analysis_cli(src_path)
                output += output2 if ret_code != 0 else ''
    else:
        print(f'[-] {src_path} gradle build 失败')

    if ret_code != 0:
        with open(report_path.joinpath('sonarqube.error'), 'w+') as f:
            f.write(output)

    return ret_code


def delete_projects():
    """删除所有project"""
    projects = list(sonar.projects.search_projects())
    for i in projects:
        sonar.projects.delete_project(i['key'])


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing source code path', type=str, required=True)
    parser.add_argument("--key", help="authentication token", type=str, required=False)
    return parser.parse_args()


if __name__ == '__main__':
    print('****************** src-sonarqube.py *******************')

    failed = []
    success_num = 0
    args = argument()

    sonar = SonarQubeClient(DEFAULT_SERVER, username='admin', password='admin123')

    # 设置token
    if not args.key:
        try:
            token = sonar.user_tokens.generate_user_token("apptest")['token']
            with open('./data/sonarqube.token', 'w+') as f:
                f.write(token)
            print(f'[+] "apptest" token "{token}" saved to ./data/sonarqube.token')
        except Exception as e:
            try:
                with open('./data/sonarqube.token', 'r') as f:
                    token = f.read()
            except Exception as e:
                token = input('请输入token：')
            print(f'[+] token: {token}')

    src_dirs = open(args.config, 'r').read().splitlines()
    for src in src_dirs:
        src_path = Path(src)
        report_path = src_path.joinpath('SecScan')
        if not report_path.exists():
            report_path.mkdir()

        try:
            sonar.projects.create_project(project=src_path.name, name=src_path.name)
        except Exception as e:
            if 'key already exists' in str(e) and input('项目已存在，是否重建 [y/n]：') == 'n':
                continue

        # if src_path.joinpath('gradlew').exists():
        #     ret = analysis(src_path, 'gradle')
        # else:
        ret = analysis(src_path, 'cli')

        if ret:
            failed.append(src)
        else:
            success_num += 1

    print(f'扫描完成: {success_num}, 扫描失败: {len(failed)}')
    print('\n'.join(failed))
