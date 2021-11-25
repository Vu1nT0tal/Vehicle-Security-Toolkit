# Vehicle-Security-Toolkit

汽车安全测试工具集（持续更新）

## 安装

首先安装 Android SDK，然后执行 `init.sh`。

```sh
$ sudo snap install android-studio --classic  # 安装完成后打开android-studio进行设置

$ ./init.sh
```

## top-activity.sh

连接ADB，获取顶层 App 及 Activity：

```sh
$ ./top-activity.sh
*************** top-activity.sh ***************
  mCurrentFocus=Window{33eb3e7 u0 com.fce.btphone/com.fce.btphone.activity.BtActivity}
```

## adb-export.sh

当拿到一个车机不知道该下载或查看哪些东西的时候，使用该脚本一键搞定。

```sh
$ ./adb-export.sh
***************** adb-export script *****************
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

## apk-decompile.py

使用 `adb-export.sh` 导出所有 APK 后，使用该脚本批量解码资源文件并反编译为 smali 和 java，为后续分析做准备。

```sh
$ python3 apk-decompile.py --help
****************** apk-decompile.py ******************
usage: apk-decompile.py [-h] [-a] [-j] -d DIR [-c]

optional arguments:
  -h, --help         show this help message and exit
  -a, --apktool      Use apktool get smali
  -j, --jadx         Use jadx get java
  -d DIR, --dir DIR  Target directory
  -c, --clean        Clean all file above
```

## apk-leaks.py

使用 `apk-decompile.py` 得到所有反编译代码后，使用该脚本批量搜索 IP、URL、Key 等敏感信息。推荐把所有控制台输出转存一份 `>&1 | tee result.txt`。

```sh
$ python3 apk-leaks.py --help
******************** apk-leaks.py ********************
usage: apk-leaks.py [-h] [-f FILE] [-d DECOMPILED] [-o OUTPUT] [-a ARGS]

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  APK file to scanning
  -d DECOMPILED, --decompiled DECOMPILED
                        Path to decompiled files
  -o OUTPUT, --output OUTPUT
                        Write to file results
  -a ARGS, --args ARGS  Disassembler arguments (e.g. --deobf)
```

## apk-mobsf.py

使用 `adb-export.sh` 导出所有 APK 后，使用该脚本批量静态分析并生成报告。

```sh
$ docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
$ python3 apk-mobsf.py --help
******************* apk-mobsf.py *********************
usage: apk-mobsf.py [-h] -k KEY [-f FILE] [-d DIR]

optional arguments:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     Mobsf REST API key
  -f FILE, --file FILE  APK file to scanning
  -d DIR, --dir DIR     Target directory
```

## apk-qark.py

使用 `adb-export.sh` 导出所有 APK 后，使用该脚本批量静态分析并生成报告。

```sh
$ python3 apk-qark.py --help
******************** apk-qark.py *********************
usage: apk-qark.py [-h] [--apk APK] [--java JAVA] [--report REPORT]

optional arguments:
  -h, --help       show this help message and exit
  --apk APK        A directory containing APK to decompile and run static analysis
  --java JAVA      A directory containing Java code to run static analysis.
  --report REPORT  Type of report to generate [html|xml|json|csv]
```

## apk-androbugs.py

使用 `adb-export.sh` 导出所有 APK 后，使用该脚本批量静态分析并生成报告。

```sh
$ python3 apk-androbugs.py --help         
****************** apk-androbugs.py ******************
usage: apk-androbugs.py [-h] --apk APK

optional arguments:
  -h, --help  show this help message and exit
  --apk APK   A directory containing APK to run static analysis
```

## apk-scanner.py

使用 `adb-export.sh` 导出所有 APK 后，使用该脚本批量静态分析并生成报告。

```sh
$ python3 apk-scanner.py --help          
******************* apk-scanner.py *******************
usage: apk-scanner.py [-h] --apk APK

optional arguments:
  -h, --help  show this help message and exit
  --apk APK   A directory containing APK to run static analysis
```

## apk-mariana.py

使用 `apk-decompile.py` 得到所有反编译代码后，使用该脚本批量静态分析并生成报告。

```sh
$ source ./tools/mariana-trench/bin/activate
$ python3 apk-mariana.py --help          
******************* apk-mariana.py *******************
usage: apk-mariana.py [-h] --apk APK

optional arguments:
  -h, --help  show this help message and exit
  --apk APK   A directory containing APK to run static analysis

# 分析完成后查看报告。目前漏洞代码定位有问题: https://github.com/skylot/jadx/issues/476
$ sapp --database-name {sample-mariana.db} server --source-directory {jadx_java/sources}
```

## lib-cvescan.py

使用 `adb-export.sh` 导出 system 目录后，使用该脚本批量扫描开源组件并获取 CVE 详情。

```sh
$ python3 lib-cvescan.py --help
******************* lib-cvescan.py *******************
usage: lib-cvescan.py [-h] -f FILE [-o OUTPUT]

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

## can-countid.py

统计 CAN ID 出现次数，并过滤数据。`TODO：将有变化的数据高亮显示`

```sh
$ python3 cantool.py log.asc 
******************* can-countid.py *******************
c9: 1743
128: 872
12a: 174
e1: 35
please input id: c9
0.009100: 84 0d 04 00 00 80 c0 d5
0.019100: 84 0d 04 00 00 80 00 15
0.029100: 84 0d 04 00 00 80 40 55
0.039100: 84 0d 0e 00 00 80 80 9f
```

## idps-test

制造系统网络异常状况，看是否会触发 IDSP 告警。

`killcpu.sh` 死循环占用 CPU：

```sh
$ ./killcpu.sh   
USAGE: ./killcpu.sh <cpus>
cpus: 2
```

`killmemory.sh` 创建大文件占用内存：

```sh
$ ./killmemory.sh 
USAGE: sudo ./killmemory.sh <memory/M>
MemFree: 190 M
MemAvailable: 829 M
```

## mem-heapdump.sh

app 堆内存 dump，得到 hprof 文件，并使用 [MAT](https://www.eclipse.org/mat) 进行后续分析：

```sh
$ ./app-heapdump.sh com.fce.fcesettings 
******************* mem-heapdump.sh ******************
restarting adbd as root
remount succeeded
system        3912  2058 2 14:28:31 ?     00:00:01 com.fce.fcesettings
[*] Dumping managed heap...
/data/local/tmp/original.hprof: 1 file pulled. 7.0 MB/s (21028468 bytes in 2.871s)
[*] Converting hprof format...
[*] Executing MAT analysis...
[*] Managed dump and analysis succeeded
```

## 进程间通信抓取

- [Frida Android libbinder](https://bhamza.me/2019/04/24/Frida-Android-libbinder.html)
- Man-In-The-Binder: He Who Controls IPC Controls The Droid. [slides](https://www.blackhat.com/docs/eu-14/materials/eu-14-Artenstein-Man-In-The-Binder-He-Who-Controls-IPC-Controls-The-Droid.pdf) | [wp](https://sc1.checkpoint.com/downloads/Man-In-The-Binder-He-Who-Controls-IPC-Controls-The-Droid-wp.pdf)
- [binder transactions in the bowels of the linux kernel](https://www.synacktiv.com/en/publications/binder-transactions-in-the-bowels-of-the-linux-kernel.html)
- [Android’s Binder – in depth](http://newandroidbook.com/files/Andevcon-Binder.pdf)
- <https://android.googlesource.com/platform/frameworks/native/+/jb-dev/libs/binder>

## 开源协议

Vehicle-Security-Toolkit use SATA(Star And Thank Author) [License](./LICENSE), so you have to star this project before using. 🙏

## Stargazers over time

[![Stargazers over time](https://starchart.cc/firmianay/Vehicle-Security-Toolkit.svg)](https://starchart.cc/firmianay/Vehicle-Security-Toolkit)
