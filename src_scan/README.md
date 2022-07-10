# src_scan

- [src_scan](#src_scan)
  - [Java/Android](#javaandroid)
    - [src_build.py](#src_buildpy)
    - [src_qark.py](#src_qarkpy)
    - [src_mobsf.py](#src_mobsfpy)
    - [src_fireline.py](#src_firelinepy)
    - [src_speck.py](#src_speckpy)
    - [src_keyfinder.py](#src_keyfinderpy)
    - [src_depcheck.py](#src_depcheckpy)
    - [src_sonarqube.py](#src_sonarqubepy)
  - [C/Cpp](#ccpp)
    - [flawfinder](#flawfinder)
    - [TscanCode](#tscancode)
    - [cppcheck](#cppcheck)
    - [snyk](#snyk)
  - [Python](#python)
    - [bandit](#bandit)
  - [Go](#go)
    - [gosec](#gosec)
  - [Semgrep](#semgrep)
  - [CodeQL](#codeql)

## Java/Android
### src_build.py

APK 源码编译，可选择提供环境配置文件。

```sh
$ readlink -f ~/hmi/apps/* > ../data/src.list
$ python3 src_build.py --config ../data/src.list --build_config ../demo/build_config.json
```

### src_qark.py

批量扫描 Android 源码并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > ../data/src.list
$ python3 src_qark.py --config ../data/src.list
```

### src_mobsf.py

批量扫描 Android 源码并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > ../data/src.list
$ python3 src_mobsf.py --config ../data/src.list
```

### src_fireline.py

批量扫描 Android 源码并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > ../data/src.list
$ python3 src_fireline.py --config ../data/src.list
```

### src_speck.py

批量扫描 Android 源码并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > ../data/src.list
$ python3 src_speck.py --config ../data/src.list
```

### src_keyfinder.py

批量扫描 Android 源码并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > ../data/src.list
$ python3 src_keyfinder.py --config ../data/src.list
```

### src_depcheck.py

批量扫描 Android 源码，得到第三方库 CVE 漏洞并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > ../data/src.list
$ python3 src_depcheck.py --config ../data/src.list
```

### src_sonarqube.py

使用 `src_build.py` 编译代码后，批量扫描程序仓库。打开 `http://localhost:9000/`，默认密码 admin/admin，首次登录后请手动修改为 admin/admin123。

```sh
$ docker run -it --rm -v $PWD/tools/sonarqube_extensions:/opt/sonarqube/extensions -p 9000:9000 sonarqube:community
$ readlink -f ~/hmi/apps/* > ../data/src.list
$ python3 src_sonarqube.py --config ../data/src.list [--key KEY]
```

## C/Cpp
### flawfinder

依据可能的漏洞标记（例如函数名）快速扫描。

```sh
$ ../tools/flawfinder-env/bin/flawfinder --context --quiet --html [--minlevel=4] ~/source > flawfinder.html
```

### TscanCode

支持 C/Cpp、C# 和 Lua 语言扫描。

```sh
$ ./tools/TscanCode/TscanCode/tscancode --enable=all --xml ~/source 2>tscancode.xml >/dev/null

$ ./tools/TscanCode/TscLua/tsclua --json ~/source 2>tsclua.json
$ ./tools/TscanCode/TscSharp/TscSharp --help
```

### cppcheck

TODO: 后续集成 Sonarqube。

```sh
$ ./tools/cppcheck/bin/cppcheck [--bug-hunting] ~/source 2>&1 | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" > cppcheck.txt
```

### snyk

支持 Java、C/Cpp、Python、Go 等多种语言扫描。[生成 API_TOKEN](https://app.snyk.io/)

```sh
$ ./tools/snyk auth [<API_TOKEN>]
$ ./tools/snyk code test --json-file-output=snky.json ~/source
```

## Python
### bandit

Python AST 安全问题扫描。

```sh
$ bandit -r ~/source [-n 3] [-lll]
```

## Go
### gosec

Go AST 安全问题扫描。

```sh
$ gosec ~/source [-fmt=html] [-out=gosec.html]
```

## Semgrep

```sh
$ semgrep ~/source --config auto
```

## CodeQL
