#!/usr/bin/python3

import re
import time
import html
import json
import openai
import requests
import xmltodict
import translators
from pathlib import Path
from pprint import pprint
from pygerrit2 import GerritRestAPI, HTTPBasicAuth


def download_patches(username: str, password: str, jql: str, project: str):
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
        issue_title = issue['title']
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

    def scan_match(match: str):
        match2 = '\n'.join(match.split('\n')[4:])    # 去掉前面的diff信息
        prompt = prompt_en + match2
        try:
            completion = openai.ChatCompletion.create(model='gpt-3.5-turbo', messages=[{'role': 'user', 'content': prompt}])
            content_en = completion['choices'][0]['message']['content']
            content_zh = translators.translate_text(content_en, translator='sogou')

            return {'match': match, 'content_en': content_en, 'content_zh': content_zh}
        except Exception as e:
            print(e)
            return {'match': match, 'content_en': '', 'content_zh': ''}

    # OpenAI
    proxy_url = 'http://127.0.0.1:7890'
    proxy = {'http': proxy_url, 'https': proxy_url} if proxy_url else {'http': None, 'https': None}
    openai.proxy = proxy
    openai.api_key = key

    prompt_en = 'Bellow is the code patch, please help me do a code review, if any bug risk, security vulnerability and improvement suggestion are welcome.\n'
    prompt_zh = '下面是一个代码补丁，请帮我做代码审查，如果有任何错误风险，安全漏洞和改进建议，欢迎提出来。\n'

    # 遍历所有补丁
    for patch in Path(project).rglob('*.patch'):
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
                time.sleep(10)
            else:
                print(f'\033[1;31;40m {match} \033[0m')
                time.sleep(20)

        with open(patch.parent.joinpath(f'{patch.stem}.txt'), 'w+') as f:
            for result in results:
                f.write('\n\n' + '\n\n'.join(result.values()))


if __name__ == '__main__':
    # OA账号密码
    username = ''
    password = ''
    # OpenAI密钥
    openai_key = ''
    # JIRA查询语句
    jql = ''

    project = re.search(r'component = (\S+)', jql)[1]

    change_num = download_patches(username, password, jql, project)
    print(f'补丁总数：{change_num}')

    chatgpt_scan(openai_key, project)
