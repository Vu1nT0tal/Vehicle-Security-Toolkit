import os
import socket
import hashlib
from colorama import Fore
from pathlib import Path
from subprocess import Popen, PIPE, STDOUT, TimeoutExpired


def shell_cmd(cmd: str, env: dict = None, timeout: int = None):
    """执行shell命令，返回元组 (output, ret_code)，其中output包括STDOUT和STDERR。"""
    sdkman = f'source {Path("~").expanduser().joinpath(".sdkman/bin/sdkman-init.sh")}'
    change_java = {
        8: f'{sdkman} && sdk use java 8.0.312-tem',
        11: f'{sdkman} && sdk use java 11.0.13-tem'
    }
    change_gradle = {
        4: f'{sdkman} && sdk use gradle 4.10.3',
        5: f'{sdkman} && sdk use gradle 5.6.4',
        6: f'{sdkman} && sdk use gradle 6.9.2'
    }

    os.environ['PATH'] += ':'+str(Path('~/.local/bin').expanduser())
    local_env = env.copy() if env else os.environ
    cwd = local_env.pop('cwd', None)
    exe = local_env.pop('exe', 'sh')
    gradle = local_env.pop('gradle', None)
    if gradle:
        cmd = f'{change_gradle[gradle]} && {cmd}'
        exe = 'zsh'
    java = local_env.pop('java', None)
    if java:
        cmd = f'{change_java[java]} && {cmd}'
        exe = 'zsh'

    pl = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT, cwd=cwd, env=local_env, executable=f'/bin/{exe}')
    try:
        output = pl.communicate(timeout=timeout)[0].decode('utf-8', errors='replace')
        ret_code = pl.returncode
    except TimeoutExpired:
        print('Execution timeout!')
        pl.kill()
        output = pl.communicate()[0].decode('utf-8', errors='replace')
        output += '\n\nERROR: execution timed out!'
        ret_code = 1
    return output, ret_code


def get_host_ip() -> str:
    """获取本机ip"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close() 
    return ip


def get_md5(file_path: str) -> str:
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            md5.update(chunk)
    return md5.hexdigest()


class Color:
    @staticmethod
    def print_focus(data: str):
        print(Fore.YELLOW+data+Fore.RESET)

    @staticmethod
    def print_success(data: str):
        print(Fore.LIGHTGREEN_EX+data+Fore.RESET)

    @staticmethod
    def print_failed(data: str):
        print(Fore.LIGHTRED_EX+data+Fore.RESET)
