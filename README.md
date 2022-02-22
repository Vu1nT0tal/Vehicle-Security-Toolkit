# Vehicle-Security-Toolkit

汽车/安卓/固件安全测试工具集

- [Vehicle-Security-Toolkit](#vehicle-security-toolkit)
  - [安装](#安装)
    - [img-extract.sh](#img-extractsh)
    - [adb-export.sh](#adb-exportsh)
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

首先安装 Android SDK，然后执行 `init.sh`。

```sh
$ sudo snap install android-studio --classic  # 安装完成后打开android-studio进行设置

$ git clone https://github.com/firmianay/Vehicle-Security-Toolkit.git
$ cd Vehicle-Security-Toolkit && ./init.sh
```

连接 ADB 后安装 frida：

```sh
$ ./frida.sh
```

### img-extract.sh

Android ROM 解包：

```sh
# 将 Android sparse image 转换成 raw image
$ cp <original_super_image> ./data
$ simg2img ./data/super.img ./data/super.img_raw

# 从 raw image 提取分区镜像文件
$ mkdir ./data/system ./data/vendor
$ ./tools/lpunpack ./data/super.img_raw ./data

# 挂载镜像文件
$ sudo mount -o ro ./data/system_a.img ./data/system
$ sudo mount -o ro ./data/vendor_a.img ./data/vendor

# 搜索所有 APK
$ find ./data -name "*.apk" 2>/dev/null
```

也可以使用脚本自动化完成：

```sh
$ ./img-extract.sh <original_super_image>
```

解析和重打包镜像文件：

```sh
$ cd ./tools/Android_boot_image_editor-master
$ cp <original_boot_image> boot.img
$ ./gradlew unpack
$ ./gradlew pack
```

### adb-export.sh

当拿到一个车机不知道该下载或查看哪些东西的时候，使用该脚本一键搞定。

```sh
$ ./adb-export.sh
******************* adb-export.sh ********************
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
$ readlink -f ~/hmi/apps/* > src.list
$ python3 src-allinone.py --config ./data/src.list --build
```

## 其他工具

[其他工具](./others)

## 开源协议

Vehicle-Security-Toolkit use SATA(Star And Thank Author) [License](./LICENSE), so you have to star this project before using. 🙏

## Stargazers over time

[![Stargazers over time](https://starchart.cc/firmianay/Vehicle-Security-Toolkit.svg)](https://starchart.cc/firmianay/Vehicle-Security-Toolkit)
