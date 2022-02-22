# 其他工具

- [其他工具](#其他工具)
  - [top-activity.sh](#top-activitysh)
  - [HTTPS 抓包](#https-抓包)
  - [can-countid.py](#can-countidpy)
  - [idps-test](#idps-test)
  - [mem-heapdump.sh](#mem-heapdumpsh)
  - [进程间通信抓取](#进程间通信抓取)

## top-activity.sh

连接 ADB，获取顶层 App 及 Activity：

```sh
$ adb shell dumpsys window | grep mCurrentFocus
```

## HTTPS 抓包

从 Android7 开始，系统不再信任用户 CA 证书，想要抓 HTTPS 数据，有三种方法：

1. 使用旧版本Android；
2. 使用已root的设备，将 BurpSuite 的 CA 证书安装到系统证书目录；
3. 修改目标 APK 文件，重新启用用户证书目录。

这里使用第三种方法：

```sh
$ apk-mitm --debuggable <path-to-apk>
```

## can-countid.py

统计 CAN ID 出现次数，并过滤数据。`TODO：将有变化的数据高亮显示`

```sh
$ python3 cantool.py log.asc 
******************* can-countid.py *******************
c9: 1743
128: 872
12a: 174
please input id: c9
0.009100: 84 0d 04 00 00 80 c0 d5
0.019100: 84 0d 04 00 00 80 00 15
0.029100: 84 0d 04 00 00 80 40 55
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
[*] Dumping managed heap...
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
