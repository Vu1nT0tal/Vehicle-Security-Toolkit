#!/usr/bin/python3

import sys
import shutil
import pyfiglet
import argparse
from pathlib import Path
from sonarqube import SonarQubeClient

sys.path.append('..')
from utils import *


DEFAULT_SERVER = f'http://{get_host_ip()}:9000'

env = {
    'ANDROID_HOME': Path('~').expanduser().joinpath('Android/Sdk'),
    'ANDROID_SDK_ROOT': Path('~').expanduser().joinpath('Android/Sdk')
}


def analysis_cli(src_path: Path, token: str):
    print_focus('[sonarqube] - cli')

    cmd = f'docker run --rm -e SONAR_HOST_URL={DEFAULT_SERVER} -e SONAR_LOGIN={token} -v {src_path}:/usr/src sonarsource/sonar-scanner-cli -Dsonar.projectKey={src_path.name} -Dsonar.java.binaries=/usr/src'
    output, ret_code = shell_cmd(cmd)
    if ret_code != 0:
        print_failed('[sonarqube] cli 失败')
    return output, ret_code


def analysis_gradle(src_path: Path, java: int = 11):
    print_focus('[sonarqube] - gradle')
    local_env = env.copy()
    local_env.update({'java': java, 'cwd': src_path})

    build1 = str(src_path.joinpath('build.gradle'))

    # 备份
    shutil.copy(build1, f'{build1}.bak')

    # 修改
    sed1 = 'sed -i \"/dependencies {/a\classpath \'org.sonarsource.scanner.gradle:sonarqube-gradle-plugin:3.3\'\" '+build1
    sed2 = 'sed -i \"/repositories {/a\mavenCentral()\" '+build1
    sed3 = 'sed -i \"/allprojects {/a\\apply plugin: \'org.sonarqube\'\" '+build1

    shell_cmd(f'{sed1} && {sed2} && {sed3}')

    # 运行
    cmd = f'chmod +x gradlew && ./gradlew sonarqube -Dsonar.projectKey={src_path.name} -Dsonar.host.url={DEFAULT_SERVER} -Dsonar.login={token}'
    output, ret_code = shell_cmd(cmd, local_env)

    # 恢复
    shutil.move(f'{build1}.bak', build1)

    if ret_code != 0:
        print_failed('[sonarqube] gradlew 失败')
    return output, ret_code


def analysis(src_path: Path, mode: str, token: str):
    if mode == 'cli':
        output, ret_code = analysis_cli(src_path, token)
    elif mode == 'gradle':
        output, ret_code = analysis_gradle(src_path)
        if ret_code != 0:
            output2, ret_code = analysis_cli(src_path, token)
            output += output2 if ret_code != 0 else ''

    if ret_code != 0:
        with open(report_path.joinpath('sonarqube.error'), 'w+') as f:
            f.write(output)

    return ret_code


def create_project(sonar: SonarQubeClient):
    """创建项目"""
    try:
        sonar.projects.create_project(project=src_path.name, name=src_path.name)
    except Exception as e:
        if 'key already exists' in str(e) and input('项目已存在，是否重建 [y/n]：') == 'n':
            return False
    return True


def delete_projects(sonar: SonarQubeClient):
    """删除所有project"""
    projects = list(sonar.projects.search_projects())
    for i in projects:
        sonar.projects.delete_project(i['key'])


def init_sonarqube(key: str=''):
    # 设置token
    sonar = SonarQubeClient(DEFAULT_SERVER, username='admin', password='admin123')

    if not key:
        try:
            token = sonar.user_tokens.generate_user_token("apptest")['token']
            print_focus(f'"apptest" token: {token}')
        except Exception as e:
            token = input('请输入token：')

    return sonar, token


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing source code path', type=str, required=True)
    parser.add_argument("--key", help="authentication token", type=str, required=False)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('src_sonarqube'))
    args = argument()

    src_dirs = open(args.config, 'r').read().splitlines()
    for src in src_dirs:
        print_focus(f'[sonarqube] {src}')

        src_path = Path(src)
        report_path = src_path.joinpath('SecScan')
        report_path.mkdir(parents=True, exist_ok=True)

        key = args.key or ''
        sonar, token = init_sonarqube(key)

        if create_project(sonar):
            # if src_path.joinpath('gradlew').exists():
            #     ret = analysis(src_path, 'gradle')
            # else:

            if ret := analysis(src_path, 'cli', token):
                print_failed('[sonarqube] failed')
            else:
                print_success('[sonarqube] success')
        else:
            print_focus('[sonarqube] pass')
