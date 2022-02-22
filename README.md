# Vehicle-Security-Toolkit

汽车安全测试工具集（持续更新）

- [Vehicle-Security-Toolkit](#vehicle-security-toolkit)
  - [安装](#安装)
    - [img-extract.sh](#img-extractsh)
    - [adb-export.sh](#adb-exportsh)
  - [APK 测试](#apk-测试)
    - [apk-allinone.py](#apk-allinonepy)
  - [二进制测试](#二进制测试)
    - [bin-cwechecker.py](#bin-cwecheckerpy)
    - [bin-cvescan.py](#bin-cvescanpy)
  - [源码测试](#源码测试)
    - [src-qark.py](#src-qarkpy)
    - [src-mobsf.py](#src-mobsfpy)
    - [src-fireline.py](#src-firelinepy)
    - [src-depcheck.py](#src-depcheckpy)
    - [src-sonarqube.py](#src-sonarqubepy)
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
### bin-cwechecker.py

使用 `apk_decompile.py` 得到所有反编译代码后，使用该脚本批量静态分析 SO/ELF 文件并生成报告。

```sh
$ python bin-cwechecker.py --help
***************** bin-cwechecker.py ******************
usage: bin_cwechecker.py [-h] --dir DIR

optional arguments:
  -h, --help  show this help message and exit
  --dir DIR   A directory containing bin files to run static analysis
```

### bin-cvescan.py

使用 `adb-export.sh` 导出 system 目录后，使用该脚本批量扫描开源组件并获取 CVE 详情。

```sh
$ python3 bin-cvescan.py --help
******************* bin-cvescan.py *******************
usage: bin-cvescan.py [-h] -f FILE [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File or directory to scanning
  -o OUTPUT, --output OUTPUT
                        Write to file results
```

- 开源组件漏洞扫描，得到CVE号：[cve-bin-tool](https://github.com/intel/cve-bin-tool)
- 已知版本号查找 CVE：[cve-search](https://github.com/cve-search/cve-search)
- Android
  - APK 第三方库(`.jar`)识别。[paper](https://arxiv.org/pdf/2108.01964.pdf)
    - [LibDetect](https://sites.google.com/view/libdetect/)
    - [LibScout](https://github.com/reddr/LibScout)
    - [LibRadar](https://github.com/pkumza/LibRadar)
    - [LibPecker](https://github.com/yuanxzhang/LibPecker)
  - APK 第三方库(`.so`)识别。
- Linux
  - `TODO: 动态链接库调用关系`

## 源码测试
### src-qark.py

批量扫描 Android 源码并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > src.list
$ python3 src-qark.py --config ./data/src.list
```

### src-mobsf.py

批量扫描 Android 源码并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > src.list
$ python3 src-mobsf.py --config ./data/src.list
```

### src-fireline.py

批量扫描 Android 源码并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > src.list
$ python3 src-fireline.py --config ./data/src.list
```

### src-depcheck.py

批量扫描第三方库 CVE 漏洞并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > src.list
$ python3 src-depcheck.py --config ./data/src.list
```

### src-sonarqube.py

批量扫描 Android 源码。打开 `http://localhost:9000/`，默认密码 admin/admin，首次登录后请手动修改为 admin/admin123。

```sh
$ docker run -it --rm -p 9000:9000 sonarqube:community
$ readlink -f ~/hmi/apps/* > src.list
$ python3 src-sonarqube.py --config ./data/src.list [--key KEY]
```

## 其他工具

[其他工具](./others)

## 开源协议

Vehicle-Security-Toolkit use SATA(Star And Thank Author) [License](./LICENSE), so you have to star this project before using. 🙏

## Stargazers over time

[![Stargazers over time](https://starchart.cc/firmianay/Vehicle-Security-Toolkit.svg)](https://starchart.cc/firmianay/Vehicle-Security-Toolkit)
