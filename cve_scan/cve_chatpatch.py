#!/usr/bin/python3

import re
import time
import html
import json
import openai
import tiktoken
import requests
import pyfiglet
import xmltodict
import translators
from pathlib import Path
from thefuzz import fuzz
from pprint import pprint
from pygerrit2 import GerritRestAPI, HTTPBasicAuth


def count_tokens(messages: list):
    """计算请求需要的token数"""

    encoding = tiktoken.encoding_for_model(model)
    tokens_per_message = 4
    tokens_per_name = -1

    num_tokens = 0
    for message in messages:
        num_tokens += tokens_per_message
        for key, value in message.items():
            num_tokens += len(encoding.encode(value))
            if key == 'name':
                num_tokens += tokens_per_name
    num_tokens += 3
    return num_tokens


def download_patches(username: str, password: str, jql: str, project: str):
    """下载补丁"""

    jira_url = ''
    gerrit_url = ''

    auth = HTTPBasicAuth(username, password)
    client = GerritRestAPI(url=gerrit_url, auth=auth)

    # JIRA
    query_url = f'{jira_url}/sr/jira.issueviews:searchrequest-rss/temp/SearchRequest.xml?jqlQuery={jql}&tempMax=1000'

    project_path = Path(project)
    project_path.mkdir(parents=True, exist_ok=True)

    # 获取并解码
    r = requests.get(query_url, auth=(username, password))
    comments_xml = html.unescape(r.text)

    with open(project_path.joinpath('comments.xml'), 'w+') as f:
        f.write(comments_xml)

    comments = xmltodict.parse(r.text)['rss']['channel']['item']

    issues = []
    pattern = r'<a href="([^"]+)"'
    for item in comments:
        matches = re.findall(pattern, item['description'], re.DOTALL)
        issues.append({
            'title': item['title'],
            'link': item['link'],
            'changes': list(set(matches))
        })

    with open(project_path.joinpath('issues.json'), 'w+') as f:
        json.dump(issues, f, indent=4, ensure_ascii=False)

    change_num = 0
    for issue in issues:
        issue_title = issue['title'].replace('/', '_')
        issue_path = project_path.joinpath(issue_title)
        issue_path.mkdir(parents=True, exist_ok=True)
        print(issue_title, issue['link'])

        for change in issue['changes']:
            try:
                if 'gerrit' in change:
                    # 获取commit ID
                    change_id = change.split('/+/')[1]
                    revision = client.get(f'/changes/{change_id}/revisions/current/commit')
                    subject = revision['subject'].replace('/', '_')
                    commit_id = revision['commit']

                    # 获取补丁
                    patch = client.get(f'/changes/{commit_id}/revisions/current/patch')

                    with open(issue_path.joinpath(f'{change_id} {subject}.patch'), 'w+') as f:
                        f.write(patch)
                    change_num += 1
                    print('\t', subject, change)
                else:
                    print('\t', f'\033[1;31;40m {change} \033[0m')
            except Exception as e:
                print(e)
                print('\t', f'\033[1;31;40m {change} \033[0m')

    return change_num


def chatgpt_scan(key: str, project: str):
    """ChatGPT代码审查"""

    def scan_match(match: str):
        # 优先从缓存中查找
        for cache_match in cache:
            ratio = fuzz.ratio(match, cache_match['match'])
            if ratio > 70:
                print('cache', ratio)
                return {'match': match, 'content_en': cache_match['content_en'], 'content_zh': cache_match['content_zh']}

        match2 = '\n'.join(match.split('\n')[4:])    # 去掉前面的diff信息
        messages = [{'role': 'user', 'content': prompt_en + match2}]

        if count_tokens(messages) < 4096:
            for _ in range(3):
                try:
                    completion = openai.ChatCompletion.create(model=model, messages=messages)
                    content_en = completion['choices'][0]['message']['content']
                    content_zh = translators.translate_text(content_en, translator='sogou')

                    return {'match': match, 'content_en': content_en, 'content_zh': content_zh}
                except Exception as e:
                    print(e)
                    time.sleep(20)

        return {'match': match, 'content_en': '', 'content_zh': '扫描失败'}

    # OpenAI
    proxy_url = 'http://127.0.0.1:7890'
    proxy = {'http': proxy_url, 'https': proxy_url} if proxy_url else {'http': None, 'https': None}
    openai.proxy = proxy
    openai.api_key = key

    prompt_en = 'Bellow is the code patch, please help me do a code review, if any bug risk, security vulnerability and improvement suggestion are welcome.\n'
    prompt_zh = '下面是一个代码补丁，请帮我做代码审查，如果有任何错误风险，安全漏洞和改进建议，欢迎提出来。\n'

    # 遍历所有补丁
    for subdir in [d for d in Path(project).iterdir() if d.is_dir()]:
        cache = []  # 缓存已经扫描过的补丁
        for patch in subdir.rglob('*.patch'):
            print(patch)
            patch_text = patch.read_text()

            # 按单个文件分割
            results = []
            pattern = r"diff --git.*?(?=diff --git|$)"
            matches = re.findall(pattern, patch_text, re.DOTALL)
            for match in matches:
                if 'Binary files differ' in match:
                    continue

                print('----------'*10)
                result = scan_match(match)
                results.append(result)
                if result['content_en']:
                    pprint(result)
                else:
                    print(f'\033[1;31;40m {match} \033[0m')

            with open(patch.parent.joinpath(f'{patch.stem}.txt'), 'w+') as f:
                for result in results:
                    f.write('\n\n' + '\n\n'.join(result.values()))
            cache.extend(results)


if __name__ == '__main__':
    print(pyfiglet.figlet_format('cve_chatpatch'))

    # OA账号密码
    username = ''
    password = ''
    # OpenAI密钥
    openai_key = ''
    # JIRA查询语句
    projects = {}
    jql_base = ''
    for project in projects:
        jql = jql_base.format(project=project)

        change_num = download_patches(username, password, jql, project)
        print(f'补丁总数：{change_num}')

        model = 'gpt-3.5-turbo'
        chatgpt_scan(openai_key, project)
