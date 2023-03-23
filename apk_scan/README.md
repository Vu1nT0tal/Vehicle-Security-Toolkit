# apk_scan

- [apk_scan](#apk_scan)
  - [apk_decompile.py](#apk_decompilepy)
  - [apk_id.py](#apk_idpy)
  - [apk_leaks.py](#apk_leakspy)
  - [apk_qark.py](#apk_qarkpy)
  - [apk_speck.py](#apk_speckpy)
  - [apk_keyfinder.py](#apk_keyfinderpy)
  - [apk_mobsf.py](#apk_mobsfpy)
  - [apk_audit.py](#apk_auditpy)
  - [apk_androbugs.py](#apk_androbugspy)
  - [apk_scanner.py](#apk_scannerpy)
  - [apk_hunt.py](#apk_huntpy)
  - [apk_shark.py](#apk_sharkpy)
  - [apk_walker.py](#apk_walkerpy)
  - [apk_mariana.py](#apk_marianapy)
  - [apk_quark.py](#apk_quarkpy)
  - [apk_exodus.py](#apk_exoduspy)
  - [apk_cryptoguard.py](#apk_cryptoguardpy)
  - [apk_jni.py](#apk_jnipy)
  - [apk-diff.py](#apk-diffpy)
  - [apk-repack.sh](#apk-repacksh)

## apk_decompile.py

导出所有 APK 后，使用该脚本批量解码资源文件并反编译为 smali 和 java，为后续分析做准备。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_decompile.py --config ../data/apk.list --apktool --jadx
$ python3 apk_decompile.py --config ../data/apk.list --clean   # 清理
```

## apk_id.py

导出所有 APK 后，使用该脚本批量检查加壳、混淆、反调试等保护情况。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_id.py --config ../data/apk.list
```

## apk_leaks.py

使用 `apk_decompile.py` 得到所有反编译代码后，使用该脚本批量搜索 IP、URL、Key 等敏感信息。推荐把所有控制台输出转存一份 `>&1 | tee result.txt`。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_leaks.py --config ../data/apk.list
```

## apk_qark.py

使用 `apk_decompile.py` 得到所有反编译代码后，使用该脚本批量静态分析并生成报告。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_qark.py --config ../data/apk.list --report html
```

## apk_speck.py

使用 `apk_decompile.py` 得到所有反编译代码后，使用该脚本批量静态分析并生成报告。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_speck.py --config ../data/apk.list
```

## apk_keyfinder.py

使用 `apk_decompile.py` 得到所有反编译代码后，使用该脚本批量静态分析并生成报告。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_keyfinder.py --config ../data/apk.list
```

## apk_mobsf.py

导出所有 APK 后，使用该脚本批量静态分析并生成报告。打开 `http://localhost:8000/`。

```sh
$ docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_mobsf.py --config ../data/apk.list --key [API_KEY]
```

## apk_audit.py

导出所有 APK 后，使用该脚本批量静态分析。打开 `http://localhost:8888/`，账号密码 auditor/audit123。

```sh
$ docker-compose -f ./tools/mobileAudit-main/docker-compose.yaml up
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_audit.py --config ../data/apk.list
```

## apk_androbugs.py

导出所有 APK 后，使用该脚本批量静态分析并生成报告。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_androbugs.py --config ../data/apk.list
```

## apk_scanner.py

导出所有 APK 后，使用该脚本批量静态分析并生成报告。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_scanner.py --config ../data/apk.list
```

## apk_hunt.py

导出所有 APK 后，使用该脚本批量静态分析并生成报告。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_hunt.py --config ../data/apk.list
```

## apk_shark.py

导出所有 APK 后，使用该脚本批量静态分析并生成报告。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_shark.py --config ../data/apk.list
```

## apk_walker.py

导出所有 APK 后，使用该脚本批量静态分析并生成报告。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_walker.py --config ../data/apk.list
```

## apk_mariana.py

使用 `apk_decompile.py` 得到所有反编译代码后，使用该脚本批量静态分析并生成报告。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_mariana.py --config ../data/apk.list

# 分析完成后查看报告。目前漏洞代码定位有问题: https://github.com/skylot/jadx/issues/476
$ ../tools/mariana-trench/bin/sapp --database-name {sample-mariana.db} server --source-directory {jadx_java/sources}
```

## apk_quark.py

导出所有 APK 后，使用该脚本批量静态分析并生成报告。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_quark.py --config ../data/apk.list
```

## apk_exodus.py

导出所有 APK 后，使用该脚本批量静态分析并生成报告。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_exodus.py --config ../data/apk.list
```

## apk_cryptoguard.py

导出所有 APK 后，使用该脚本批量静态分析并生成报告。

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_cryptoguard.py --config ../data/apk.list
```

## apk_jni.py

导出所有 APK 后，使用该脚本批量提取 JNI 函数特征，可导入到 IDA 和 Ghidra，提升逆向效率。[JNI Helper](https://github.com/evilpan/jni_helper)

```sh
$ find ~/apks -name "*.apk" | xargs realpath > ../data/apk.list
$ python3 apk_jni.py --config ../data/apk.list
```

## apk-diff.py

使用 `apk_decompile.py` 得到新旧版本 APK 的反编译代码后，使用该脚本进行包和 smali 代码的对比。

```sh
$ python3 apk-diff.py <apk1> <apk2>
```

## apk-repack.sh

使用 apktool 自动化重打包并签名：

```sh
$ ./apk-repack.sh <smali_folder> <apk_name>
```
