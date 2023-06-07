# 其他工具

- [其他工具](#其他工具)
  - [top-activity.sh](#top-activitysh)
  - [HTTPS 抓包](#https-抓包)
  - [can-countid.py](#can-countidpy)
  - [idps-test](#idps-test)
  - [mem-heapdump.sh](#mem-heapdumpsh)
  - [进程间通信抓取](#进程间通信抓取)
  - [git\_compare](#git_compare)

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

## git_compare

批量比较文件夹 git 差异。

1. 读取 config 文件中的文件夹列表。
2. 遍历文件夹列表，找到对应的 git 库，获取 git 库的基本信息。
3. 获得对应 git 库下，两个比较标签之间的差异提交列表。
4. 遍历提交列表，获取对应 change id 和 gerrit 信息，包括 url、分支等。
5. 反向获取两个标签之间的差异列表，并合并两个差异列表，去除里面重复的 commit。去重的策略是根据 change id，去掉不同分支上同一个提交，commit id不同的。
6. 整合信息，按页保存到 excel 文件中。

```sh
$ python3 git_compare.py --help
usage: git_compare.py [-h] -r <repo_root> -f <files> [<files> ...] -s <tag|branch|commit> -t <tag|branch|commit> [-u <gerrit_user_name>]

optional arguments:
  -h, --help            show this help message and exit
  -r <repo_root>, --repo <repo_root>
                        the code root of repo
  -f <files> [<files> ...], --files <files> [<files> ...]
                        the file list concerned folders
  -s <tag|branch|commit>, --tag_from <tag|branch|commit>
                        the compare start tag or branch or commit id
  -t <tag|branch|commit>, --tag_to <tag|branch|commit>
                        the compare end tag or branch or commit id
  -u <gerrit_user_name>, --user <gerrit_user_name>
                        the user name of gerrit
```
