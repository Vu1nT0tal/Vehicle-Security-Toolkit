import re
import sys
import copy
import mmap
import nvdlib
import base64
import requests
import contextlib
from tqdm import tqdm
from thefuzz import fuzz
from selenium import webdriver
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed

sys.path.append('..')
from utils import *

NVD_KEY = 'b2f07e13-3a3b-45c4-89b0-0e7140e5d436'

requests_headers = {
    'X-Requested-With': 'XMLHttpRequest',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36'
}

def get_poc(cve_id: str):
    """检查是否有POC/EXP"""
    pocs = []

    poc_url = 'https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master'
    with contextlib.suppress(Exception):
        r = requests.get(f'{poc_url}/{cve_id.split("-")[1]}/{cve_id.upper()}.json', timeout=15)
        if r.status_code == 200:
            pocs.extend([i['html_url'] for i in r.json()])

    edb_url = 'https://www.exploit-db.com/search?cve='
    with contextlib.suppress(Exception):
        r = requests.get(f'{edb_url}{cve_id.upper()}', headers=requests_headers, timeout=15)
        if r.status_code == 200:
            pocs.extend([f'https://www.exploit-db.com/exploits/{i["id"]}' for i in r.json()['data']])

    return pocs


def get_severity(score: float, version: int=3):
    """通过分数计算严重性"""
    severity_dict = {
        (0, 3.9): "Low",
        (4.0, 6.9): "Medium",
        (7.0, 8.9): "High",
        (9.0, 10): "Critical" if version == 3 else "High"
    }
    return next(
        (
            sev
            for (low, high), sev in severity_dict.items()
            if low <= score <= high
        ),
        None,
    )


def get_cve_detail(cve_id: str):
    """获取CVE详情"""
    result = {
        'references': [f'https://nvd.nist.gov/vuln/detail/{cve_id}']
    }

    try:
        r = nvdlib.searchCVE(cveId=cve_id, key=NVD_KEY)[0]
        result['cvss'] = r.score[1]
        result['cvssVector'] = getattr(r, 'v31vector', getattr(r, 'v30vector', getattr(r, 'v2vector', '')))
        result['references'].extend([i.url for i in r.references])
        result['summary'] = r.descriptions[0].value
        result['poc'] = get_poc(cve_id)
    except Exception as e:
        print_failed(f'{cve_id} detail failed: {e}')

    # try:
    #     r = requests.get(f'https://cve.circl.lu/api/cve/{cve_id}').json()
    #     result['cvss'] = r.get('cvss') or ''
    #     result['cvssVector'] = r.get('cvss-vector') or ''
    #     result['summary'] = r.get('summary') or ''
    #     result['references'].extend(r.get('references') or [])
    # except Exception as e:
    #     print_failed(f'{cve_id} detail failed: {e}')

    return result


def format_qcom_url(url: str):
    """将高通补丁链接规范化处理"""
    if 'codeaurora' in url:
        # 已迁移到codelinaro
        url = url.replace('commit/?h', 'commit?id').replace('commit/?id', 'commit?id')
        path = '/'.join(url.split('/')[4:-1])
        cmt_id = url.split('=')[-1]
        url = f'https://git.codelinaro.org/clo/{path}/-/commit/{cmt_id}'
        replace = [
            'qca-wifi-host-cmn',
            'audio-kernel',
            'display-drivers',
            'edk2']
        if any(repo in url for repo in replace):
            url = url.replace('/qsdk/', '/la/').replace('/le/', '/la/')

    data = url.split('/')
    cmt_id = data[-1].split('_')[0]
    url = f'{"/".join(data[:-1])}/{cmt_id}'
    return url


def get_patch(url: str):
    """获取补丁"""
    class shadow:
        def __init__(self, browser):
            self.browser = browser

        def get_shadow(self, shadow, by: str, value: str):
            element = shadow.find_element(by, value)
            shadow = self.browser.execute_script('return arguments[0].shadowRoot', element)
            return shadow

    # patch = meta + diff
    patch = ''
    meta = ''
    diff = ''
    url = url.strip('/')

    # 高通
    if 'source.codeaurora.org' in url or 'git.codelinaro.org' in url:
        url = format_qcom_url(url)
        patch = requests.get(f'{url}.patch').text
        if not patch.startswith('From'):
            print(f'Format error: {url}')
            patch = ''
        else:
            meta, diff = parse_patch(patch)

    # AOSP
    elif 'android.googlesource.com' in url:
        meta = requests.get(f'{url}?format=JSON').text[5:]
        r = requests.get(f'{url}^!/?format=TEXT')
        diff = base64.b64decode(r.text).decode()
    elif 'chromium.googlesource.com' in url:
        meta = requests.get(f'{url}?format=JSON').text[5:]
        r = requests.get(f'{url}^!/?format=TEXT')
        diff = base64.b64decode(r.text).decode()
    elif 'android-review.googlesource.com' in url:
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        browser = webdriver.Chrome(options=options)
        browser.get(url)
        sd = shadow(browser)
        shadow = sd.get_shadow(browser, 'id', 'pg-app')
        shadow = sd.get_shadow(shadow, 'id', 'app-element')
        shadow = sd.get_shadow(shadow, 'tag name', 'gr-change-view')
        shadow = sd.get_shadow(shadow, 'tag name', 'gr-file-list-header')
        shadow = sd.get_shadow(shadow, 'tag name', 'gr-commit-info')
        url = shadow.find_element('tag name', 'a').get_attribute('href')
        meta = requests.get(f'{url}?format=JSON').text[5:]
        r = requests.get(f'{url}^!/?format=TEXT')
        diff = base64.b64decode(r.text).decode()

    # 内核
    elif 'git.kernel.org' in url:
        patch = requests.get(url.replace('commit', 'patch')).text
        if not patch.startswith('From'):
            print(f'Format error: {url}')
            patch = ''
        else:
            meta, diff = parse_patch(patch)
    elif 'lore.kernel.org' in url:
        if 'patchwork' in url:
            r = requests.get(url)
            url = r.history[-1].headers['Location']
        patch, _ = shell_cmd(f'b4 -q am -o- {url.split("/")[-1]}')
        if not patch.startswith('From'):
            print(f'Format error: {url}')
            patch = ''
        else:
            meta, diff = parse_patch(patch)
    elif 'github.com/torvalds' in url:
        patch = requests.get(f'{url}.patch').text
        if not patch.startswith('From'):
            print(f'Format error: {url}')
            patch = ''
        else:
            meta, diff = parse_patch(patch)

    else:
        print_failed(f'Format error: {url}')
    return patch, meta, diff


def get_local_repos(hmi_path: Path, repo_tool: Path):
    """获取本地仓库"""
    all_hmi = {}
    output, ret_code = shell_cmd(f'cd {hmi_path} && {repo_tool} list')
    for line in output.splitlines():
        path = line.split(':')[0].strip()
        repo = line.split(':')[1].strip()
        all_hmi[repo] = hmi_path.joinpath(path)
    return all_hmi


def get_sec_repos(all_hmi: dict, fix_repos: set):
    """根据本地仓库中涉及CVE的仓库"""
    sec_hmi = {key: all_hmi[key] for key in fix_repos if key in all_hmi}
    not_hmi = fix_repos - sec_hmi.keys()
    print_focus(f'Repo found: {len(sec_hmi)}, Repo not found: {len(not_hmi)}')
    print(not_hmi) if not_hmi else None
    return sec_hmi


def get_modified_files(patch: str, mode: str='all'):
    """获取补丁中修改的文件"""
    modified_files = []
    for line in patch.splitlines():
        if line.startswith('diff --git'):
            start = line.find(' a/') + len(' a/')
            end = line.find(' b/')
            file = line[start:end]
            if mode == 'name':
                modified_files.append(file.split('/')[-1])
            elif mode == 'path':
                modified_files.append('/'.join(file.split('/')[:-1]))
            else:
                modified_files.append(file)
    return modified_files


def parse_patch(data: str):
    """将补丁分成meta和diff"""
    lines = data.splitlines()
    diff_index = next((i for i, line in enumerate(lines) if line.startswith('diff --git')), -1)
    if diff_index == -1:
        print_failed(f'No diff --git: {data}')
        return '', ''

    meta_part = '\n'.join(lines[:diff_index])
    diff_part = '\n'.join(lines[diff_index:-3])
    return meta_part, diff_part


def download_and_write_patches(patch_sec_path, tag, vers, cve_data):
    """下载并保存补丁文件"""
    cve_id = cve_data['cve_id']
    urls = cve_data['fixes']
    if not urls:
        print_failed(f'{tag} {cve_id} no fixes')
        return

    for idx, url in enumerate(urls):
        try:
            patch, meta, diff = get_patch(url)
            if not patch and not meta and not diff:
                print_failed(f'Download failed: {url}')
                continue
        except Exception as e:
            print_failed(f'Download failed: {url}')
            print(e, cve_data)
            continue

        for ver in vers:
            write_path = patch_sec_path.joinpath(ver, tag)
            write_files(write_path, cve_id, patch, meta, diff, idx, len(urls))


def write_files(write_path, cve_id, patch, meta, diff, idx, total):
    """保存补丁文件"""
    write_path.mkdir(parents=True, exist_ok=True)
    file_suffix = f'-{idx+1}' if total > 1 else ''
    patch_path = write_path.joinpath(f'{cve_id}{file_suffix}.patch')
    diff_path = write_path.joinpath(f'{cve_id}{file_suffix}.diff')
    meta_path = write_path.joinpath(f'{cve_id}{file_suffix}.meta')
    for path, data in zip((patch_path, diff_path, meta_path), (patch, diff, meta)):
        with open(path, 'w+') as f:
            f.write(data)


def processThread(repo: Path, patch: Path):
    try:
        # 提取diff部分
        patch_data = patch.read_text(errors='ignore')
        meta, diff = parse_patch(patch_data)
        if not meta or not diff:
            print_failed(f'Parse failed: {patch}')
            return str(repo), patch.name, []
        with open(patch.with_suffix('.meta'), 'w+') as f:
            f.write(meta)
        with open(patch.with_suffix('.diff'), 'w+') as f:
            f.write(diff)

        # 找出修改的文件
        modified_files = get_modified_files(diff)
        return str(repo), patch.name, modified_files
    except Exception as e:
        print_failed(f'processThread failed: {patch}\n{e}')
        return str(repo), patch.stem, []


def generate_patches_manifest(patch_all_path, hmi):
    """根据manifest生成所有补丁"""
    # TODO
    manifest_path = hmi_path.joinpath('.repo/manifests')
    default_manifest = manifest_path.joinpath('default.xml')
    date = args.manifest

    scan_manifest = next(
        (
            xml_file
            for xml_file in manifest_path.glob('*.xml')
            if date.replace('-', '') in xml_file.name
        ),
        '',
    )
    if not scan_manifest:
        print_failed(f'Manifest not found: {date}')
        return False


def generateThread(patch_all_path: Path, repo_name: str, repo_path: str, date: str):
    target_path = patch_all_path.joinpath(repo_name)
    if target_path.exists():
        number = len(list(target_path.glob('*.diff')))
        print_success(f'Generate {number} patches: {repo_name}')
        return repo_name, number
    target_path.mkdir(parents=True, exist_ok=True)

    # 获取从某天开始第一次提交的哈希
    cmd = f'git --no-pager log --since="{date}" --pretty=format:"%H" | tail -n 1'
    first_commit, ret_code = shell_cmd(cmd, env={'cwd': repo_path})
    cmd1 = f'git rev-parse {first_commit}^' # 获取前一个哈希
    prev_commit, ret_code1 = shell_cmd(cmd1, env={'cwd': repo_path})

    if ret_code != 0 or not first_commit:
        print_failed(f'No first commit: {repo_name}')
        return repo_name, -1
    if ret_code1 == 128 and 'unknown revision' in prev_commit:
        prev_commit = first_commit

    # 生成所有补丁
    cmd = f'git format-patch --histogram -N {prev_commit} -o {target_path}'
    output, ret_code = shell_cmd(cmd, env={'cwd': repo_path})
    number, _ = shell_cmd(f'ls {target_path} | wc -l')
    if ret_code != 0:
        print_failed(f'Generate patches Error: {repo_name}\n{output}')
        return repo_name, -1

    print_success(f'Generate {number} patches: {repo_name}')
    return repo_name, int(number)


def generate_patches_date(patch_all_path, hmi, date):
    """根据日期生成所有补丁"""
    executor = ProcessPoolExecutor(os.cpu_count()-1)
    tasks = [executor.submit(generateThread, patch_all_path, name, path, date) for name, path in hmi.items()]
    executor.shutdown(True)

    success = []
    error = []
    for task in tasks:
        name, number = task.result()
        success.append(name) if number != -1 else error.append(name)
    print_focus(f'Success: {len(success)}, Error: {len(error)}')
    print(error)


def process_patches(patch_all_path: Path):
    """处理生成的补丁"""
    results = defaultdict(dict)
    patch_paths = list(patch_all_path.glob('**/*.patch'))
    with ProcessPoolExecutor(os.cpu_count()-1) as executor:
        tasks = []
        for patch in patch_paths:
            # 安全补丁通常小于50KB
            if patch.stat().st_size < 50 * 1024:
                thread = executor.submit(processThread, patch.relative_to(patch_all_path).parent, patch)
                tasks.append(thread)
            else:
                patch.unlink(missing_ok=True)

        with tqdm(total=len(tasks)) as pbar:
            for f in as_completed(tasks):
                try:
                    repo, patch, modified_files = f.result(timeout=300)
                    results[repo][patch] = modified_files
                except Exception as e:
                    print_failed('processThread timeout')
                pbar.update()
    return results


def filter_patches(patch_all_path, repo, cve_name, diff, patches_data):
    """找出有相同路径或文件名的补丁"""
    f1_filenames = get_modified_files(diff, mode='name')
    fi_paths = get_modified_files(diff, mode='path')

    patches1 = [
        patch_all_path.joinpath(repo, f2)
        for f2, f2_files in patches_data[repo].items()
        if any(i.split('/')[-1] in f1_filenames for i in f2_files)
    ]
    patches2 = [
        patch_all_path.joinpath(repo, f2)
        for f2, f2_files in patches_data[repo].items()
        if any('/'.join(i.split('/')[:-1]) in fi_paths for i in f2_files)
    ]

    return set(patches1 + patches2)


def scan_patches(repo, cve_name, patches, diff_data, patch_data='', strict=False):
    """扫描补丁打没打"""
    result = []
    for patch in patches:
        f2 = open(patch.with_suffix('.diff')).read()
        ratio = fuzz.ratio(diff_data, f2)  # 优先扫描diff相似度
        if ratio < 60:
            continue

        print_focus(f'[{repo}] {cve_name} found ({ratio}%): {patch.stem}')
        if ratio >= 80:
            result.append(f'{ratio}% {patch.stem}')
            # 非strict模式下找到一个就返回
            if not strict:
                break
        elif patch_data:
            # 其次扫描patch相似度
            f2 = open(patch.with_suffix('.patch')).read()
            ratio = fuzz.ratio(patch_data, f2)
            if ratio < 60:
                continue

            print_focus(f'[{repo}] {cve_name} found ({ratio}%): {patch.stem}')
            if ratio >= 80:
                result.append(f'{ratio}% {patch.stem}')
                if not strict:
                    break

    return result


def extract_patch_info(cve: Path):
    with open(cve, 'r') as cve_fd:
        diff_flag = False
        modify_flag = False
        sFilename = ''
        file_modify = {}
        diff_info = []

        for line in cve_fd:
            info = re.findall(r'^diff --git a(.*) b(.*)', line)
            if len(info) == 1:
                modify_flag = False
                sFilename = ''
                diff_info = copy.deepcopy(info)
                diff_flag = True
                continue

            if diff_flag == True:
                file_path_a = re.findall(r'^--- a(.*)', line)
                if len(file_path_a) == 1:
                    sFilename = file_path_a[0]
                else:
                    file_path_b = re.findall(r'^\+\+\+ b(.*)', line)
                    if len(file_path_b) == 1:
                        sFilename = file_path_b[0]

                if (sFilename == diff_info[0][0]) and (sFilename == diff_info[0][1]):
                    file_modify[sFilename] = {'add': [], 'del': []}
                    modify_flag = True
                    diff_flag = False
                continue

            if (line[0] == '-') and (line[1] != '-'):
                if modify_flag == True and len(line[1:].strip()) > 5:
                    file_modify[sFilename]['del'].append(line[1:].strip())
            elif (line[0] == '+') and (line[1] != '+'):
                if modify_flag == True and len(line[1:].strip()) > 5:
                    file_modify[sFilename]['add'].append(line[1:].strip())

            finish = re.findall(r'^cgit', line)
            if len(finish) == 1:
                break

    return file_modify


def compareThread2(cve: Path):
    """提取某个CVE补丁信息，到源码中进行对比"""

    cve_name = '-'.join(cve.stem.split('-')[:3])
    result = {
        'url': f'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=linux-{cve.parent.name}.y&id={cve.stem.split("-")[-1]}',
        'poc': get_poc(cve_name),
        'scan': {'modify': [], 'unmodify':[], 'ratio':0}
    }

    file_modify = extract_patch_info(cve)
    modify_patch = 0
    all_patch = 0

    for filename in file_modify:
        source_all_path = repo_path.joinpath(filename[1:])
        if not source_all_path.exists():
            break

        all_patch += len(file_modify[filename]['add'])+len(file_modify[filename]['del'])

        with open(source_all_path, 'r+') as f:
            kernel_code = mmap.mmap(f.fileno(), 0)
            for add_patch in file_modify[filename]['add']:
                add_idx = kernel_code.find(add_patch.encode())
                if add_idx == -1:
                    result['scan']['unmodify'].append(f'[+] {add_patch}')
                elif add_idx >= 0:
                    result['scan']['modify'].append(f'[+] {add_patch}')
                    kernel_code.seek(add_idx)
                    modify_patch += 1

            for del_patch in file_modify[filename]['del']:
                del_idx = kernel_code.find(del_patch.encode())
                if del_idx == -1:
                    result['scan']['modify'].append(f'[-] {del_patch}')
                    modify_patch += 1
                elif del_idx >= 0:
                    result['scan']['unmodify'].append(f'[-] {del_patch}')

    score = 1 if all_patch == 0 else modify_patch / all_patch
    result['scan']['ratio'] = score

    if score > 0.6:
        print_success(f'{cve_name} not found, code modify ratio: {score:.2%}')
    else:
        print_failed(f'{cve_name} found, code modify ratio: {score:.2%}')

    return cve_name, result
