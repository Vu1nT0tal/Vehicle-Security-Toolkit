# Vehicle-Security-Toolkit

汽车/安卓/固件/代码安全测试工具集

- [Vehicle-Security-Toolkit](#vehicle-security-toolkit)
  - [安装](#安装)
    - [init_local.sh](#init_localsh)
    - [init_remote.sh](#init_remotesh)
  - [固件提取](#固件提取)
    - [img-extract.sh](#img-extractsh)
    - [adb-extract.sh](#adb-extractsh)
  - [APK 测试](#apk-测试)
    - [apk-allinone.py](#apk-allinonepy)
  - [二进制测试](#二进制测试)
    - [bin-allinone.py](#bin-allinonepy)
  - [源码测试](#源码测试)
    - [src-allinone_java.py](#src-allinone_javapy)
    - [src-allinone_c.py](#src-allinone_cpy)
  - [系统测试](#系统测试)
  - [漏洞测试](#漏洞测试)
  - [隐私合规测试](#隐私合规测试)
  - [APK Fuzz 测试](#apk-fuzz-测试)
  - [其他工具](#其他工具)
  - [LICENSE](#license)

## 安装

在 Ubuntu20.04（Python3.8及以上）完整安装可能需要几个小时。如果担心破坏本地环境，可以使用虚拟机，具体请看 [dev](./dev)。

### init_local.sh

本地 Linux 设备安装 Android SDK，然后执行 `init_local.sh`。

```sh
$ sudo snap install android-studio --classic  # 完成后打开android-studio进行设置

$ git clone https://github.com/firmianay/Vehicle-Security-Toolkit.git
$ cd Vehicle-Security-Toolkit && ./init_local.sh
```

### init_remote.sh

远程 Android 设备连接 ADB，然后执行 `init_remote.sh`：

```sh
$ ./init_remote.sh [android|linux] [adb|ssh ip:port]
```

注：Android 设备只有板子没有屏幕时可以使用 scrcpy 投屏。

## 固件提取
### img-extract.sh

下载 fastboot.zip 包，解压后从 images 目录下取出 super.img。

一键从 Android ROM 提取固件。

```sh
$ ./img-extract.sh [super.img|fastboot.zip]
```

### adb-extract.sh

一键从 Android 设备提取固件。

```sh
$ ./adb-extract.sh
******************* adb-extract.sh ********************
    1. Collect basic information, init and selinux
    2. Execute live commands
    3. Execute package manager commands
    4. Execute bugreport, dumpsys, appops
    5. Acquire /system folder
    6. Acquire /sdcard folder
    7. Extract APK files
    8. Extract data from content providers
    9. Extract databases and keys
    10. Extract compressed and bin files
    11. Acquire an ADB Backup
    12. Do all of the above
Choose an option: 
```

## APK 测试
### apk-allinone.py

一站式调用所有 APK 工具进行单个或批量扫描。[apk_scan](./apk_scan) 目录下的工具作为库被调用，也可以独立使用。

```sh
$ docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
$ docker-compose -f ./tools/mobileAudit-main/docker-compose.yaml up

$ find ~/apks -name "*.apk" | xargs realpath > ./data/apk.list
$ python3 apk-allinone.py --config ./data/apk.list --decompile
```

## 二进制测试
### bin-allinone.py

一站式调用所有二进制工具进行单个或批量扫描。[bin_scan](./bin_scan) 目录下的工具作为库被调用，也可以独立使用。

```sh
$ find ~/apks -type f | xargs file | grep "ELF" | cut -d ":" -f 1 | xargs realpath > ./data/bin.list
$ python3 bin-allinone.py --config ./data/bin.list
```

## 源码测试
### src-allinone_java.py

一站式调用所有 Java/Android 源码工具进行单个或批量扫描。[src_scan](./src_scan) 目录下的工具作为库被调用，也可以独立使用。

```sh
$ readlink -f ~/hmi/apps/* > ./data/src.list
$ python3 src-allinone_java.py --config ./data/src.list --build_config ./demo/build_config.json --build
```

### src-allinone_c.py

一站式调用所有 C/Cpp 源码工具进行批量扫描。

```sh
$ python3 src-allinone_c.py --src ~/source
```

## 系统测试

一站式对 Android 内核配置、安全启动、SELinux 等进行扫描。

```sh
$ python3 sys-allinone.py --sys ~/source
```

## 漏洞测试

一站式对 Android/Linux 设备进行漏洞扫描，[poc_scan](./poc_scan) 目录下的工具作为库被调用，也可以独立使用。

```sh
$ python3 poc_allinone.py --arch [x64|arm|aarch64] --connect [adb|ssh] --device ip:port
```

## 隐私合规测试

Android App 隐私合规测试。

```sh
$ python3 tools/camille-master/camille.py -ns -t 3 -f demo.xls
```

## APK Fuzz 测试

基于 drozer 实现的 Fuzz 工具。[apk_fuzz](./apk_fuzz)

## 其他工具

[其他工具](./others)

## LICENSE

[GNU General Public License v3.0](./LICENSE)

[![Stargazers over time](https://starchart.cc/VulnTotal-Team/Vehicle-Security-Toolkit.svg)](https://starchart.cc/VulnTotal-Team/Vehicle-Security-Toolkit)
