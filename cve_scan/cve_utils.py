import re
import sys
import json
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
    if not score:
        return None

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


def parse_nvdlib_cve(cve):
    """解析nvdlib返回的CVE数据"""
    poc = get_poc(cve.id)
    references = [i.url for i in cve.references] + [f'https://nvd.nist.gov/vuln/detail/{cve.id}']
    return {
        'cvss': cve.score[1],
        'cvssVector': getattr(cve, 'v31vector', getattr(cve, 'v30vector', getattr(cve, 'v2vector', ''))),
        'summary': cve.descriptions[0].value,
        'poc': poc,
        'references': references
    }


def get_cve_detail(cve_id: str):
    """获取CVE详情"""
    result = {}
    try:
        r = nvdlib.searchCVE(cveId=cve_id, key=NVD_KEY)[0]
        result = parse_nvdlib_cve(r)
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


def search_cve(cpe: str):
    """
    通过CPE搜索CVE，vendor/product/version三个部分是必须的
    示例：cpe:2.3:a:denx:u-boot:2022.01
    ”"""
    fix_keywords = ['/commit/', '/pull/','lore.kernel.org']
    result = {}
    try:
        r = nvdlib.searchCVE(cpeName=cpe, key=NVD_KEY)
        for cve in r:
            cve_data = parse_nvdlib_cve(cve)
            cve_data['cve_id'] = cve.id
            cve_data['fixes'] = []
            for ref in cve_data['references']:
                for keyword in fix_keywords:
                    if keyword in ref:
                        cve_data['fixes'].append(ref)
            result[cve.id] = cve_data
    except Exception as e:
        print_failed(f'{cpe} search failed: {e}')

    print_focus(f'{cpe}: {len(result)}')
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
    def gitiles(url: str):
        meta = requests.get(f'{url}?format=JSON').text[5:]
        r = requests.get(f'{url}^!/?format=TEXT')
        diff = base64.b64decode(r.text).decode()
        return meta, diff

    def gerrit(url: str):
        class shadow:
            def __init__(self, browser):
                self.browser = browser

            def get_shadow(self, shadow, by: str, value: str):
                element = shadow.find_element(by, value)
                shadow = self.browser.execute_script('return arguments[0].shadowRoot', element)
                return shadow

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
        return gitiles(url)

    # patch包括meta和diff
    patch = ''
    meta = ''
    diff = ''
    url = url.strip('/')

    # 通用
    if 'github.com' in url:
        patch = requests.get(f'{url}.patch').text
        if not patch.startswith('From'):
            print(f'Format error: {url}')
            patch = ''
        else:
            meta, diff = parse_patch(patch)

    # ARM
    elif 'git.trustedfirmware.org' in url:
        meta, diff = gitiles(url)
    elif 'review.trustedfirmware.org' in url:
        meta, diff = gerrit(url)

    # 高通
    elif 'source.codeaurora.org' in url or 'git.codelinaro.org' in url:
        url = format_qcom_url(url)
        patch = requests.get(f'{url}.patch').text
        if not patch.startswith('From'):
            print(f'Format error: {url}')
            patch = ''
        else:
            meta, diff = parse_patch(patch)

    # AOSP
    elif 'android.googlesource.com' in url or 'chromium.googlesource.com' in url:
        meta, diff = gitiles(url)
    elif 'android-review.googlesource.com' in url:
        meta, diff = gerrit(url)

    # 内核
    elif 'git.kernel.org' in url:
        patch = requests.get(url.replace('commit', 'patch')).text
        if not patch.startswith('From'):
            print(f'Format error: {url}')
            patch = ''
        else:
            meta, diff = parse_patch(patch)
    elif 'lore.kernel.org' in url:
        url = url.replace('%40', '@')
        if 'patchwork' in url:
            r = requests.get(url)
            url = r.history[-1].headers['Location']
        patch, _ = shell_cmd(f'b4 -q am -o- {url.split("/")[-1]}')
        if not patch.startswith('From'):
            print(f'Format error: {url}')
            patch = ''
        else:
            meta, diff = parse_patch(patch)

    # U-Boot
    elif 'source.denx.de' in url:
        patch = requests.get(f'{url}.patch').text
        if not patch.startswith('From'):
            print(f'Format error: {url}')
            patch = ''
        else:
            meta, diff = parse_patch(patch)

    else:
        print_failed(f'Format error: {url}')
    return patch, meta, diff


def parse_patch(patch_data: str):
    """将补丁分成meta和diff"""
    lines = patch_data.splitlines()
    diff_index = next((i for i, line in enumerate(lines) if line.startswith('diff --git')), -1)
    if diff_index == -1:
        print_failed(f'Not found "diff --git": {patch_data}')
        return '', ''

    meta_part = '\n'.join(lines[:diff_index])
    diff_part = '\n'.join(lines[diff_index:-3])
    return meta_part, diff_part


class Patcher:
    def __init__(self, proj, report_path,
                 version='', repo_path='', strict=False,
                 cve_exclude=[], repo_exclude=[], repo_migrate={}) -> None:
        self.patch_all_path = report_path.joinpath(f'patch_all_{proj}')
        self.patch_sec_path = report_path.joinpath(f'patch_sec_{proj}')
        self.report_file = report_path.joinpath(f'cve_patch_{proj}.json')
        self.report_html = self.report_file.with_suffix('.html')
        self.version = version
        self.repo_path = repo_path
        self.strict = strict
        self.cve_exclude = cve_exclude.get(version, [])
        self.repo_exclude = repo_exclude
        self.repo_migrate = repo_migrate.get(version, {})
        self.repo_tool = repo_path.joinpath('.repo/repo/repo')
        self.all_patches = self.patch_all_path.joinpath('all_patches.json')
        self.sec_cves = self.patch_sec_path.joinpath('sec_cves.json')
        self.cve_fixes = self.patch_sec_path.joinpath('cve_fixes.json')
        self.patches_data = json.load(open(self.all_patches)) if self.all_patches.exists() else {}
        self.cves_data = json.load(open(self.sec_cves))[version] if self.sec_cves.exists() else {}
        self.fixes_data = json.load(open(self.cve_fixes)) if self.cve_fixes.exists() else {}

    def get_local_repos(self):
        """获取本地仓库"""
        all_repos = {}
        output, ret_code = shell_cmd(f'cd {self.repo_path} && {self.repo_tool} list')
        for line in output.splitlines():
            path = line.split(':')[0].strip()
            repo = line.split(':')[1].strip()
            all_repos[repo] = self.repo_path.joinpath(path)
        return all_repos

    def get_sec_repos(self, all_repos: dict, fix_repos: set):
        """根据本地仓库中涉及CVE的仓库"""
        sec_repos = {key: all_repos[key] for key in fix_repos if key in all_repos}
        not_found = fix_repos - sec_repos.keys()
        print_focus(f'Repo found: {len(sec_repos)}, Repo not found: {len(not_found)}')
        print(not_found) if not_found else None
        return sec_repos

    def get_repo(self, url: str):
        """从fix url获取仓库名"""
        repo = ''
        if 'googlesource.com' in url:
            repo = url.split('googlesource.com/')[1].split('/+/')[0]
        elif 'codelinaro.org' in url:
            repo = '/'.join(url.split('/-/')[0].split('/')[5:])
        else:
            print_focus(f'No repo in url: {url}')

        if repo in self.repo_exclude:
            repo = ''
        if repo in self.repo_migrate:
            repo = self.repo_migrate[repo]
        return repo

    def get_fix_repos(self):
        repos = set()
        for cve_data in self.cves_data.values():
            for url in cve_data['fixes']:
                if repo := self.get_repo(url):
                    repos.add(repo)
        print_focus(f'Repos: {len(repos)}\n{repos}')
        return repos

    def gen_patches_date(self, repos, date):
        """根据日期生成所有补丁"""
        executor = ProcessPoolExecutor(os.cpu_count()-1)
        tasks = [executor.submit(self.generateThread, name, path, date) for name, path in repos.items()]
        executor.shutdown(True)

        success = []
        error = []
        for task in tasks:
            name, number = task.result()
            success.append(name) if number != -1 else error.append(name)
        print_focus(f'Success: {len(success)}, Error: {len(error)}')
        print(error)

    def generateThread(self, repo_name, repo_path, date):
        target_path = self.patch_all_path.joinpath(repo_name)
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
        num = self.gen_patches_one_repo(repo_path, target_path, prev_commit)
        return repo_name, num

    def gen_patches_one_repo(self, repo_path, target_path, commit):
        """为单个仓库生成补丁"""
        cmd = f'git format-patch --histogram -N {commit} -o {target_path}'
        output, ret_code = shell_cmd(cmd, env={'cwd': repo_path})
        number, _ = shell_cmd(f'ls {target_path} | wc -l')
        if ret_code != 0:
            print_failed(f'Generate patches Error: {target_path}\n{output}')
            return -1

        print_success(f'Generate {number.strip()} patchs: {target_path}')
        return int(number)

    def process_patches(self):
        """处理生成的补丁"""
        results = defaultdict(dict)
        patch_paths = list(self.patch_all_path.glob('**/*.patch'))
        with ProcessPoolExecutor(os.cpu_count()-1) as executor:
            tasks = []
            for patch in patch_paths:
                # 安全补丁通常小于50KB
                if patch.stat().st_size < 50 * 1024:
                    thread = executor.submit(self.processThread, patch)
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

        with open(self.all_patches, 'w+') as f:
            json.dump(results, f, indent=4)
            print_success(f'Patches saved in {self.all_patches}')

    def processThread(self, patch_path):
        repo_path = str(patch_path.relative_to(self.patch_all_path).parent)
        try:
            # 提取diff部分
            patch_data = patch_path.read_text(errors='ignore')
            meta, diff = parse_patch(patch_data)
            if not meta or not diff:
                print_failed(f'Parse failed: {patch_path}')
                return repo_path, patch_path.name, []
            with open(patch_path.with_suffix('.meta'), 'w+') as f:
                f.write(meta)
            with open(patch_path.with_suffix('.diff'), 'w+') as f:
                f.write(diff)

            # 找出修改的文件
            modified_files = self.get_modified_files(diff)
            return repo_path, patch_path.name, modified_files
        except Exception as e:
            print_failed(f'processThread failed: {patch_path}\n{e}')
            return repo_path, patch_path.stem, []

    def get_modified_files(self, patch_data, mode='all'):
        """获取补丁中修改的文件"""
        modified_files = []
        for line in patch_data.splitlines():
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

    def scanThread(self, repo, cve_path):
        """对比某个CVE补丁与所有补丁"""
        cve_name = cve_path.stem
        cve_id = '-'.join(cve_name.split('-')[:3])
        diff_data = open(cve_path).read()
        patch_data = open(cve_path.with_suffix('.patch')).read()

        ret_code = 0
        result = []
        if patches := self.filter_patches(repo, diff_data):
            result = self.scan_one_patch(repo, cve_name, patches, diff_data, patch_data)
            if not result:
                print_failed(f'[{repo}] {cve_name} not found!')
                ret_code = 2
        else:
            print_failed(f'[{repo}] {cve_name} Files not exists!')
            ret_code = 1

        return ret_code, cve_id, {cve_name: result}

    def filter_patches(self, repo, diff):
        """找出有相同路径或文件名的补丁"""
        f1_filenames = self.get_modified_files(diff, mode='name')
        fi_paths = self.get_modified_files(diff, mode='path')

        patches1 = [
            self.patch_all_path.joinpath(repo, f2)
            for f2, f2_files in self.patches_data[repo].items()
            if any(i.split('/')[-1] in f1_filenames for i in f2_files)
        ]
        patches2 = [
            self.patch_all_path.joinpath(repo, f2)
            for f2, f2_files in self.patches_data[repo].items()
            if any('/'.join(i.split('/')[:-1]) in fi_paths for i in f2_files)
        ]

        return set(patches1 + patches2)

    def scan_one_patch(self, repo, cve_name, patches, diff_data, patch_data=''):
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
                if not self.strict:
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
                    if not self.strict:
                        break

        return result

    def download_and_write_patches(self, ver, cve_data):
        """下载并保存补丁文件"""
        cve_id = cve_data['cve_id']
        urls = cve_data['fixes']
        if not urls:
            print_failed(f'{cve_id} no fixes')
            return

        for idx, url in enumerate(urls):
            idx = idx + 1 if len(urls) > 1 else 0
            try:
                patch, meta, diff = get_patch(url)
                if not patch and not meta and not diff:
                    print_failed(f'Download failed: {url}')
                    continue
            except Exception as e:
                print_failed(f'Download failed: {url}')
                print(e, cve_data)
                continue

            write_path = self.patch_sec_path.joinpath(ver)
            self.write_files(write_path, cve_id, patch, meta, diff, idx)

    def write_files(self, write_path, cve_id, patch, meta, diff, idx):
        """保存补丁文件"""
        write_path.mkdir(parents=True, exist_ok=True)
        file_suffix = f'-{idx}' if idx != 0 else ''
        patch_path = write_path.joinpath(f'{cve_id}{file_suffix}.patch')
        diff_path = write_path.joinpath(f'{cve_id}{file_suffix}.diff')
        meta_path = write_path.joinpath(f'{cve_id}{file_suffix}.meta')
        for path, data in zip((patch_path, diff_path, meta_path), (patch, diff, meta)):
            with open(path, 'w+') as f:
                f.write(data)

    def write_sec_data(self, cves_data):
        """保存update阶段的数据"""
        # 按仓库名组织数据，减少计算量
        fixes_data = defaultdict(dict)
        for cve, cve_data in cves_data[self.version].items():
            if fixes := cve_data['fixes']:
                for fix in fixes:
                    repo = self.get_repo(fix) or self.version
                    fixes_data[repo][cve] = cve_data

        with open(self.cve_fixes, 'w+') as f:
            json.dump(fixes_data, f, indent=4)
        with open(self.sec_cves, 'w+') as f:
            json.dump(cves_data, f, indent=4)

        print_focus(f'CVE: {len(cves_data[self.version])}, CVE fixes: {len(fixes_data)}')
        print_success(f'Results saved in {self.sec_cves}')

    def scan_patches(self, sec_patches, threadFunc):
        def get_repo_patch(repo, cve_id):
            """仅返回在该repo中的补丁"""
            def in_repo(repo1, patch):
                temp = patch.stem.split('-')
                idx = int(temp[-1]) if len(temp) == 4 else 0
                if idx != 0:
                    fix = self.fixes_data[repo][cve_id]['fixes'][idx-1]
                    repo2 = self.get_repo(fix) or self.version
                    return repo1 == repo2
                return True

            result = []
            for patch in sec_patches:
                if cve_id in patch.stem and in_repo(repo, patch):
                    result.append(patch)
            return result

        sec_patches = list(sec_patches) # 转列表后可以多次迭代
        results = defaultdict(dict)
        for cve, cve_data in self.cves_data.items():
            if not cve_data['fixes']:
                results['no_fixes'][cve] = cve_data

        tasks = []
        executor = ProcessPoolExecutor(os.cpu_count()-1)

        for repo, cve_dict in self.fixes_data.items():
            print(repo, len(cve_dict))

            # 排除没有的本地仓库
            if repo not in self.patches_data:
                print_failed(f'[{repo}] Repo not exists!')
                results['no_repo'][repo] = cve_dict
                continue

            for cve_id, cve_data in cve_dict.items():
                # 排除部分漏洞
                if cve_id in self.cve_exclude:
                    results['exclude'][cve_id] = cve_data
                    continue

                for cve_path in get_repo_patch(repo, cve_id):
                    thread = executor.submit(threadFunc, repo, cve_path)
                    tasks.append(thread)

        executor.shutdown(True)
        for task in tasks:
            # 先全部放到patched里面
            ret_code, cve_id, result = task.result()
            cve_data = self.cves_data[cve_id]

            if ret_code == 1:
                results['no_files'][cve_id] = cve_data
                continue

            if cve_id in results['patched']:
                cve_data['scan'].update(result)
            else:
                cve_data['scan'] = result
                results['patched'][cve_id] = cve_data

        # 将未修复的移到unpatched里面
        pop_list = []
        for cve_id, cve_data in results['patched'].items():
            # strict模式下，只要有一个补丁未修复，就认为该漏洞未修复
            if self.strict:
                if any(i == [] for i in cve_data['scan'].values()):
                    results['unpatched'][cve_id] = cve_data
                    pop_list.append(cve_id)
            # 非strict模式下，只要有一个补丁修复，就认为该漏洞修复
            elif all(i == [] for i in cve_data['scan'].values()):
                results['unpatched'][cve_id] = cve_data
                pop_list.append(cve_id)
        for i in pop_list:
            results['patched'].pop(i)

        with open(self.report_file, 'w+') as f:
            json.dump(results, f, indent=4)
            print_success(f'Results saved in {self.report_file}')


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


def scanThread2(cve: Path):
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
