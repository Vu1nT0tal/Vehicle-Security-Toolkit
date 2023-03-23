import os
import pprint
import socket
import hashlib
from lxml import etree
from colorama import Fore
from pathlib import Path
from subprocess import Popen, PIPE, STDOUT, TimeoutExpired


def shell_cmd(cmd: str, env: dict = None, timeout: int = None):
    """执行shell命令，返回元组 (output, ret_code)，其中output包括STDOUT和STDERR。"""
    os.environ['PATH'] += ':'+str(Path('~/.local/bin').expanduser())
    local_env = env.copy() if env else os.environ
    cwd = local_env.pop('cwd', None)
    cwd = Path(cwd).expanduser() if cwd else cwd
    exe = local_env.pop('exe', 'sh')
    if gradle := local_env.pop('gradle', None):
        change_gradle = {
            4: 'sdk use gradle 4.10.3',
            5: 'sdk use gradle 5.6.4',
            6: 'sdk use gradle 6.9.3',
            7: 'sdk use gradle 7.6'
        }
        cmd = f'{change_gradle[gradle]} && {cmd}'
        exe = 'zsh'
    if java := local_env.pop('java', None):
        change_java = {
            8: 'sdk use java 8.0.362-tem',
            11: 'sdk use java 11.0.18-tem'
        }
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

    @staticmethod
    def print(data):
        pprint.pprint(data)


class ManifestUtil:
    def __init__(self, file_path: Path):
        self.path = file_path
        self.tree = etree.parse(self.path)
        self.root = self.tree.getroot()

    def get_permissions(self):
        permissions = []
        permissions_xml = self.root.findall("uses-permission")
        for perm in permissions_xml:
            permissions.extend(perm.attrib[att] for att in perm.attrib)
        return permissions

    def is_debuggable(self):
        return self._extracted('{http://schemas.android.com/apk/res/android}debuggable')

    def is_allowBackup(self):
        return self._extracted('{http://schemas.android.com/apk/res/android}allowBackup')

    def _extracted(self, arg0):
        application_tag = self.root.findall('application')[0]
        return arg0 in application_tag.attrib and application_tag.attrib[arg0] == 'true'

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
        self._extracted2('{http://schemas.android.com/apk/res/android}debuggable', 'true')

    def set_networkSecurityConfig(self):
        self._extracted2('{http://schemas.android.com/apk/res/android}networkSecurityConfig', '@xml/network_security_config')

    def _extracted2(self, arg0, arg1):
        application_tag = self.root.findall('application')[0]
        application_tag.set(arg0, arg1)
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
