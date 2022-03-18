import os
import socket
import hashlib
from lxml import etree
from colorama import Fore
from pathlib import Path
from subprocess import Popen, PIPE, STDOUT, TimeoutExpired


def shell_cmd(cmd: str, env: dict = None, timeout: int = None):
    """执行shell命令，返回元组 (output, ret_code)，其中output包括STDOUT和STDERR。"""
    change_java = {
        8: 'sdk use java 8.0.322-tem',
        11: 'sdk use java 11.0.14-tem'
    }
    change_gradle = {
        4: 'sdk use gradle 4.10.3',
        5: 'sdk use gradle 5.6.4',
        6: 'sdk use gradle 6.9.2',
        7: 'sdk use gradle 7.4'
    }

    os.environ['PATH'] += ':'+str(Path('~/.local/bin').expanduser())
    local_env = env.copy() if env else os.environ
    cwd = local_env.pop('cwd', None)
    cwd = Path(cwd).expanduser() if cwd else cwd
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


class ManifestUtil:
    def __init__(self, file_path: Path):
        self.path = file_path
        self.tree = etree.parse(self.path)
        self.root = self.tree.getroot()

    def get_permissions(self):
        permissions = []
        permissions_xml = self.root.findall("uses-permission")
        for perm in permissions_xml:
            for att in perm.attrib:
                permissions.append(perm.attrib[att])

        return permissions

    def is_debuggable(self):
        application_tag = self.root.findall('application')
        application_tag = application_tag[0]
        if '{http://schemas.android.com/apk/res/android}debuggable' in application_tag.attrib \
                and application_tag.attrib['{http://schemas.android.com/apk/res/android}debuggable'] == 'true':
            return True
        else:
            return False

    def is_allowBackup(self):
        application_tag = self.root.findall('application')
        application_tag = application_tag[0]
        if '{http://schemas.android.com/apk/res/android}allowBackup' in application_tag.attrib \
                and application_tag.attrib['{http://schemas.android.com/apk/res/android}allowBackup'] == 'true':
            return True
        else:
            return False

    def check_all(self):
        Color.print_focus('Debuggable:')
        if self.is_debuggable():
            Color.print_failed('True')
        else:
            Color.print_success('False')

        Color.print_focus('AllowBackup:')
        if self.is_allowBackup():
            Color.print_failed('True')
        else:
            Color.print_success('False')

    def set_debuggable(self):
        application_tag = self.root.findall('application')
        application_tag = application_tag[0]
        application_tag.set('{http://schemas.android.com/apk/res/android}debuggable', 'true')
        self.tree.write(self.path)

    def set_networkSecurityConfig(self):
        application_tag = self.root.findall('application')
        application_tag = application_tag[0]
        application_tag.set('{http://schemas.android.com/apk/res/android}networkSecurityConfig', '@xml/network_security_config')
        self.tree.write(self.path)


def make_network_security_config(target_path: Path):
    xml_path = target_path.joinpath('res/xml')
    xml_path.mkdir(parents=True, exist_ok=True)

    with open(target_path.joinpath('res/xml/network_security_config.xml'), 'w+') as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n' +
            '<network-security-config>\n' +
            '    <base-config>\n' +
            '        <trust-anchors>\n' +
            '            <certificates src="system" />\n' +
            '            <certificates src="user" />\n' +
            '        </trust-anchors>\n' +
            '    </base-config>\n' +
            '</network-security-config>')
