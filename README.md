# Vehicle-Security-Toolkit

汽车安全测试工具集（持续更新）

## 安装

```
$ ./init.sh
```

## adb-export.sh

当拿到一个车机不知道该下载或查看哪些东西的时候，使用该脚本一键搞定。

```sh
$ ./adb-export.sh
*************** adb-export script ***************
    1. Collect basic information, init and selinux
    2. Execute live commands
    3. Execute package manager commands
    4. Execute bugreport, dumpsys, appops
    5. Acquire /system folder
    6. Acquire /sdcard folder
    7. Extract APK files
    8. Extract data from content providers
    9. Extract databases and keys
    10. Extract compressed files
    11. Acquire an ADB Backup
    12. Do all of the above
Choose an option: 
```

## apk-decompile.py

使用 `adb-export.sh` 导出所有 APK 后，使用该脚本批量解码资源文件并反编译代码为 smali 和 java，为后续分析做准备。

```sh
$ python3 apk-decompile.py --help                                           
***************** apk-decompile.py *****************
usage: apk-decompile.py [-h] [-a] [-j] -d DIR [-c]

optional arguments:
  -h, --help         show this help message and exit
  -a, --apktool      Use apktool get smali
  -j, --jadx         Use jadx get java
  -d DIR, --dir DIR  Target directory
  -c, --clean        Clean all file above
```

## apk-leaks.py

使用 `apk-decompile.py` 得到所有反编译代码后，使用该脚本批量搜索 IP、URL、Key 等敏感信息。

```sh
$ python3 apk-leaks.py --help    
******************** apkleaks.py ********************
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

## 开源协议

Vehicle-Security-Toolkit use SATA(Star And Thank Author) [License](./LICENSE), so you have to star this project before using. 🙏
