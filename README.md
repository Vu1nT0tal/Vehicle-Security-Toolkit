# Vehicle-Security-Toolkit

汽车/安卓/固件安全测试工具集

- [Vehicle-Security-Toolkit](#vehicle-security-toolkit)
  - [安装](#安装)
    - [init.sh](#initsh)
  - [固件提取](#固件提取)
    - [img-extract.sh](#img-extractsh)
    - [adb-extract.sh](#adb-extractsh)
  - [APK 测试](#apk-测试)
    - [apk-allinone.py](#apk-allinonepy)
  - [二进制测试](#二进制测试)
    - [bin-allinone.py](#bin-allinonepy)
  - [源码测试](#源码测试)
    - [src-allinone.py](#src-allinonepy)
  - [其他工具](#其他工具)
  - [开源协议](#开源协议)
  - [Stargazers over time](#stargazers-over-time)

## 安装
### init.sh

首先安装 Android SDK，然后执行 `init.sh`。

```sh
$ sudo snap install android-studio --classic  # 完成后打开android-studio进行设置

$ git clone https://github.com/firmianay/Vehicle-Security-Toolkit.git
$ cd Vehicle-Security-Toolkit && ./init.sh
```

可选，Android 设备连接 ADB 后安装 frida：

```sh
$ ./frida.sh
```

注：Android 设备只有板子没有屏幕时可以使用 scrcpy 投屏。

## 固件提取
### img-extract.sh

一键从 Android ROM 提取固件。

```sh
$ ./img-extract.sh <original_super_image>
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
### src-allinone.py

一站式调用所有源码工具进行单个或批量扫描。[src_scan](./src_scan) 目录下的工具作为库被调用，也可以独立使用。

```sh
$ readlink -f ~/hmi/apps/* > ./data/src.list
$ python3 src-allinone.py --config ./data/src.list --build_config ./demo/build_config.json --build
```

## 其他工具

[其他工具](./others)

## 开源协议

Vehicle-Security-Toolkit use SATA(Star And Thank Author) [License](./LICENSE), so you have to star this project before using. 🙏

## Stargazers over time

[![Stargazers over time](https://starchart.cc/firmianay/Vehicle-Security-Toolkit.svg)](https://starchart.cc/firmianay/Vehicle-Security-Toolkit)
