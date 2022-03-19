# poc_scan

- [poc_scan](#poc_scan)
  - [poc_suggester.py](#poc_suggesterpy)
  - [poc_patch.py](#poc_patchpy)
  - [poc_dirtypipe.py](#poc_dirtypipepy)

## poc_suggester.py

检测 Android/Linux 设备可能存在的内核漏洞。

```sh
$ python3 poc_suggester.py --connect [adb|ssh] --device ip:port
```

## poc_patch.py

检测 Linux 内核仓库中已合并及未合并的所有 CVE 补丁。

```sh
$ python3 poc_patch.py update   # 更新CVE补丁库
$ python3 poc_patch.py scan --repo ~/kernel --version 5.10
```

## poc_dirtypipe.py

检测设备是否存在 CVE-2022-0847 漏洞：https://dirtypipe.cm4all.com/

```sh
$ python3 poc_dirtypipe.py --arch [x64|arm|aarch64] --connect [adb|ssh] --device ip:port
```
