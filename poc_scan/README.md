# poc_scan

- [poc\_scan](#poc_scan)
  - [poc\_suggester.py](#poc_suggesterpy)
  - [poc\_patch\_linux.py](#poc_patch_linuxpy)
  - [poc\_patch\_android.py](#poc_patch_androidpy)
  - [poc\_patch\_qualcomm.py](#poc_patch_qualcommpy)
  - [poc\_dirtypipe.py](#poc_dirtypipepy)

## poc_suggester.py

检测 Android/Linux 设备可能存在的内核漏洞。

```sh
$ python3 poc_suggester.py --connect [adb|ssh] --device ip:port
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
