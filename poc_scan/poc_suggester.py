#!/usr/bin/python3

import sys
import pyfiglet
import argparse
import paramiko
import getpass
from pathlib import Path

sys.path.append('..')
from utils import shell_cmd, Color


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--connect', help='adb | ssh', type=str, required=True)
    parser.add_argument('--device', help='ip:port', type=str, required=True)
    return parser, parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('poc_suggester'))
    tools_path = Path(__file__).absolute().parents[1].joinpath('tools')
    parser, args = argument()
    if ':' in args.device:
        ip, port = args.device.split(':')
    else:
        ip, port = args.device, 22

    if args.connect == 'adb':
        shell_cmd(f'adb connect {ip}:{port}')
        output, ret_code = shell_cmd(f'adb shell "uname -a"')
    elif args.connect == 'ssh':
        username = input('请输入用户名：')
        password = getpass.getpass('请输入密码：')

        tp = paramiko.Transport((ip, port))
        tp.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(tp)
        ssh = paramiko.SSHClient()
        ssh._transport = tp

        stdin, stdout, stderr = ssh.exec_command('uname -a')
        output = stdout.read().decode('utf-8').strip()
    else:
        parser.print_help()

    scanner = tools_path.joinpath('linux-exploit-suggester.sh')
    output, ret_code = shell_cmd(f'{scanner} -f -d -u "{output}"')
    print(output)
