#!/usr/bin/python3

import pyfiglet
import argparse
from pathlib import Path

from utils import *


def weggli(src_path: Path):
    print_focus('weggli ...')
    rules = """
    -R 'func=^str.*cpy$' '{char $b[_]; $func($b, _);}'
    --unique -R 'func=.*cpy$' '{$func($_, _($a), _($a));}'
    -R 'func=.*cpy$' '{$func($_, $a._, $a._);}'
    --unique -R 'func=.*ncpy$' '{$func($_, _($a), $n - $m);}'
    -R '$fn=lloc' '{$size; $size=_+_; $fn($size);}'
    -R '$fn=lloc' '{$user_num=atoi(_);$fn($user_num);}'
    '{ _* $p;NOT: $p = _;$func(&$p);}'
    -R '$fn=printf$' '{$ret = $fn$($b,_,_);$b[$ret] = _;}'
    '{$len=strlen($buf);$dest=malloc($len);strcpy($dest,$buf);}'
    -R '$fn=printf$' -R '$arg=[^"]*' '{$fn($arg);}'
    -R '$fn=^[^n]*printf$' -R '$arg=[^"]*' '{$fn($arg);}'
    -R '$fn=nprintf$' -R '$arg=[^"]*' '{$fn($_,$_,$arg);}'
    '{$user_num=atoi(_);$user_num+_;}'
    ' {_ $buf[_]; $t = $buf;while (_) { $t; }}'
    -R '$f1=(fopen|chmod|access|stat)' -R '$f2=(fopen|chmod|access|stat)' '{$f1($name);$f2($name);}'
    -R '$fn=free' '{$fn($a);not: $a=_;not: return _;$fn($a);}'
    -R '$fn=free' '{$fn($a);not: $a=_;not: return _;_($a);}'
    '_ $fn(_ $buf) {free($buf);}'
    '{_ $buf[_];memcpy($buf,_,_);}'
    '{$ret = snprintf($b,_,_);$b[$ret] = _;}'
    '{ _* $p;NOT: $p = _;$func(&$p);}'
    --cpp '{$x = _.GetWeakPtr();DCHECK($x);$x->_;}'
    -X 'DCHECK(_!=_.end());'
    '_ $fn(_ $limit) {_ $buf[_];for (_; $i<$limit; _) {$buf[$i]=_;}}'
    -R func=decode '_ $func(_) {_;}'
    '_ $func($t *$input, $t2 *$output) {for (_($i);_;_) {$input[$i]=_($output);}}'
    '{NOT: $a = memdup_user(_);NOT: memset($a);NOT: memset($a->$b);copy_to_user(_, $a, sizeof(*$a));}'
    """
    report_file = report_path.joinpath('weggli.txt')

    full_output = ''
    for rule in rules.splitlines()[1:]:
        cmd = f'weggli {rule} {src_path}'
        output, ret_code = shell_cmd(cmd)
        full_output += f'Rule: {rule}\n{output}\n\n'

    with open(report_file, 'w') as f:
        f.write(full_output)


def cq(src_path: Path):
    print_focus('cq ...')
    report_path = report_path.joinpath('cq')

    scanner = tools_path.joinpath('cq-main/cq.py')
    cmd = f'{scanner} {src_path} {report_path}'
    shell_cmd(cmd)


def semgrep(src_path: Path):
    print_focus('semgrep ...')
    report_file = report_path.joinpath('semgrep.txt')

    config1 = tools_path.joinpath("semgrep/default/c")
    config2 = tools_path.joinpath("semgrep/c_cpp/c")
    cmd = f'semgrep scan --lang c --config {config1} --config {config2} {src_path} -o {report_file}'
    shell_cmd(cmd)


def flawfinder(src_path: Path):
    print_focus('flawfinder ...')
    report_file = report_path.joinpath('flawfinder.html')

    scanner = tools_path.joinpath('flawfinder-env/bin/flawfinder')
    cmd = f'{scanner} --context --quiet --html {src_path} > {report_file}'
    shell_cmd(cmd)


def tscancode(src_path: Path):
    print_focus('tscancode ...')
    report_file = report_path.joinpath('tscancode.xml')

    scanner = tools_path.joinpath('TscanCode/TscanCode/tscancode')
    cmd = f'{scanner} --enable=all --xml {src_path} 2>{report_file} >/dev/null'
    shell_cmd(cmd)


def cppcheck(src_path: Path):
    print_focus('cppcheck ...')
    report_file1 = report_path.joinpath('cppcheck.txt')
    report_file2 = report_path.joinpath('cppcheck-bug.txt')

    scanner = tools_path.joinpath('cppcheck/bin/cppcheck')
    cmd1 = f'{scanner} {src_path} 2>&1 | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" > {report_file1}'
    shell_cmd(cmd1)

    cmd2 = f'{scanner} --bug-hunting {src_path} 2>&1 | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" > {report_file2}'
    shell_cmd(cmd2)


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--src', help='Source code path', type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('src-allinone_c'))
    src_path = Path(argument().src).absolute()
    tools_path = Path(__file__).absolute().parent.joinpath('tools')

    report_path = src_path.joinpath('SecScan')
    report_path.mkdir(parents=True, exist_ok=True)

    plugin = {
        'semgrep': 1,
        'flawfinder': 1,
        'tscancode': 1,
        'cppcheck': 1,
        'weggli': 1,
        'cq': 1,
    }

    if 'semgrep' in plugin:
        semgrep(src_path)

    if 'flawfinder' in plugin:
        flawfinder(src_path)

    if 'tscancode' in plugin:
        tscancode(src_path)

    if 'cppcheck' in plugin:
        cppcheck(src_path)

    if 'weggli' in plugin:
        weggli(src_path)

    if 'cq' in plugin:
        cq(src_path)

    print(f'报告地址：{report_path}')
