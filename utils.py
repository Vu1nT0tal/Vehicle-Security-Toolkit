import socket
import hashlib
from subprocess import Popen, PIPE, STDOUT, TimeoutExpired


def shell_cmd_ret_code(cmd: str, timeout: int = None, env: dict = None, exe: str = '/bin/sh'):
    """执行shell命令，返回元组 (output, ret_code)，其中output包括STDOUT和STDERR。"""
    pl = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT, env=env, executable=exe)
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
