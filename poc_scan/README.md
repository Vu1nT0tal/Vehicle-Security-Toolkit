# poc_scan

- [poc_scan](#poc_scan)
  - [poc_suggester.py](#poc_suggesterpy)
  - [poc_chatpatch.py](#poc_chatpatchpy)
  - [poc_patch_linux.py](#poc_patch_linuxpy)
  - [poc_patch_android.py](#poc_patch_androidpy)
  - [poc_patch_qualcomm.py](#poc_patch_qualcommpy)
  - [poc_dirtypipe.py](#poc_dirtypipepy)

## poc_suggester.py

检测 Android/Linux 设备可能存在的内核漏洞。

```sh
$ python3 poc_suggester.py --connect [adb|ssh] --device ip:port
```

## poc_chatpatch.py

通过 chatgpt 对补丁文件进行代码审查，运行前需要填写 OA 账号、OpenAI 密钥和 JIRA 查询语句 JQL。

```sh
$ python3 poc_chatpatch.py
```

## poc_patch_linux.py

检测 Linux 内核仓库中已合并及未合并的所有 CVE 补丁。

```sh
$ python3 poc_patch_linux.py update   # 更新CVE补丁库
$ python3 poc_patch_linux.py scan --repo ~/kernel --version 5.10
```

## poc_patch_android.py

检测 Android 系统仓库中已合并及未合并的所有 CVE 补丁。

```sh
$ python3 poc_patch_android.py update --version 11  # 更新CVE补丁库
$ python3 poc_patch_android.py scan --repo ~/hmi --version 11
```

## poc_patch_qualcomm.py

检测 Android 内核仓库中已合并及未合并的所有 CVE 补丁。

```sh
$ python3 poc_patch_qualcomm.py update  # 更新CVE补丁库
```

## poc_dirtypipe.py

检测设备是否存在 CVE-2022-0847 漏洞：https://dirtypipe.cm4all.com/

```sh
$ python3 poc_dirtypipe.py --arch [x64|arm|aarch64] --connect [adb|ssh] --device ip:port
```
