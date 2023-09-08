# fuzz

- [fuzz](#fuzz)
  - [fuzzinozer](#fuzzinozer)
  - [fuzz\_null.py](#fuzz_nullpy)
  - [drozer\_scan.py](#drozer_scanpy)
  - [fuzz\_deeplink.sh](#fuzz_deeplinksh)
  - [fuzz\_deeplink.py](#fuzz_deeplinkpy)

连接 Android 设备并启动 drozer：

```sh
$ adb forward tcp:31415 tcp:31415
$ source ./tools/drozer/drozer-env/bin/activate
$ drozer console connect [--server 192.168.0.10] [--debug]
```

## fuzzinozer

官方的 Intent fuzz 模块：

```sh
dz> module install fuzzinozer
dz> run intents.fuzzinozer --help
```

## fuzz_null.py

该模块用于测试 NullPointerException 异常导致的拒绝服务。

```sh
dz> module install ./fuzz/fuzz_null.py
dz> run fuzz.deny com.example.app

# 另开一个终端监听异常
$ adb logcat | grep java.lang.RuntimeException
```

## drozer_scan.py

使用该脚本批量扫描目录遍历和注入漏洞，结果存放在 `./drozer_data`

```sh
$ adb shell pm list packages | grep -E "example" | cut -d ":" -f 2 > ../data/package.list

$ source ../tools/drozer/drozer-env/bin/activate
$ python2 drozer_scan.py --config ../data/package.list [--ip 127.0.0.1] [--port 31415]
```

## fuzz_deeplink.sh

测试Deep Links。

```sh
$ ./deeplink-fuzz.sh deeplinks
$ ./deeplink-fuzz.sh activities
```

## fuzz_deeplink.py

测试Deep Links。

```sh
$ ../tools/Android-App-Link-Verification-Tester-main/deeplink_analyser.py -op list-all -apk <apk_name>
```
