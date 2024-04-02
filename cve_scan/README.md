# cve_scan

- [cve\_scan](#cve_scan)
  - [cve\_suggester.py](#cve_suggesterpy)
  - [cve\_chatpatch.py](#cve_chatpatchpy)
  - [cve\_source\_linux.py](#cve_source_linuxpy)
  - [cve\_patch\_linux.py](#cve_patch_linuxpy)
  - [cve\_patch\_android.py](#cve_patch_androidpy)
  - [cve\_patch\_qualcomm.py](#cve_patch_qualcommpy)
  - [cve\_poc\_dirtypipe.py](#cve_poc_dirtypipepy)

## cve_suggester.py

通过系统版本号检测 Android/Linux 设备可能存在的内核漏洞。

```sh
$ python3 cve_suggester.py --connect [adb|ssh] --device ip:port
```

## cve_chatpatch.py

通过 chatgpt 对补丁文件进行代码审查，运行前需要填写 OA 账号、OpenAI 密钥和 JIRA 查询语句 JQL。

```sh
$ python3 cve_chatpatch.py
```

## cve_source_linux.py

通过源码级匹配的方式检测 Linux 内核仓库中未修复的 CVE 漏洞。

```sh
$ python3 cve_source_linux.py update   # 更新元数据和规则库
$ python3 cve_source_linux.py scan --repo ~/kernel
```

## cve_patch_linux.py

通过补丁对比的方式检测 Linux 内核仓库中已合并及未合并的所有 CVE 补丁。

```sh
$ python3 cve_patch_linux.py update --version 5.10  # 更新CVE补丁库
$ python3 cve_patch_linux.py format --repo ~/kernel --commit xxxx --version 5.10  # 生成仓库补丁
$ python3 cve_patch_linux.py scan --version 5.10  # 检测补丁
```

## cve_patch_android.py

通过补丁对比的方式检测 Android 系统仓库中已合并及未合并的所有 AOSP CVE 补丁。

```sh
$ python3 cve_patch_android.py update --version 11  # 更新CVE补丁库
$ python3 cve_patch_android.py format --repo ~/hmi --date 2022-01-01 --version 11 # 生成仓库补丁
$ python3 cve_patch_android.py scan --version 11  # 检测补丁
```

## cve_patch_qualcomm.py

通过补丁对比的方式检测 Android 系统仓库中已合并及未合并的所有高通 CVE 补丁。

```sh
$ python3 cve_patch_qualcomm.py update --chip SA8155P # 更新CVE补丁库
$ python3 cve_patch_qualcomm.py format --repo ~/hmi --date 2022-01-01 --chip SA8155P  # 生成仓库补丁
$ python3 cve_patch_qualcomm.py scan --chip SA8155P # 检测补丁
```

## cve_poc_dirtypipe.py

通过 PoC 的方式检测设备是否存在 CVE-2022-0847 漏洞：https://dirtypipe.cm4all.com/

```sh
$ python3 cve_poc_dirtypipe.py --arch [x64|arm|aarch64] --connect [adb|ssh] --device ip:port
```
