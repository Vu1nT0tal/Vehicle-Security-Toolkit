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
