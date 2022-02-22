# src_scan

- [src_scan](#src_scan)
  - [src_qark.py](#src_qarkpy)
  - [src_mobsf.py](#src_mobsfpy)
  - [src_fireline.py](#src_firelinepy)
  - [src_speck.py](#src_speckpy)
  - [src_depcheck.py](#src_depcheckpy)
  - [src_sonarqube.py](#src_sonarqubepy)

## src_qark.py

批量扫描 Android 源码并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > ../data/src.list
$ python3 src_qark.py --config ../data/src.list
```

## src_mobsf.py

批量扫描 Android 源码并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > ../data/src.list
$ python3 src_mobsf.py --config ../data/src.list
```

## src_fireline.py

批量扫描 Android 源码并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > ../data/src.list
$ python3 src_fireline.py --config ../data/src.list
```

## src_speck.py

批量扫描 Android 源码并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > ../data/src.list
$ python3 src_speck.py --config ../data/src.list
```

## src_depcheck.py

批量扫描第三方库 CVE 漏洞并生成报告。

```sh
$ readlink -f ~/hmi/apps/* > ../data/src.list
$ python3 src_depcheck.py --config ../data/src.list
```

## src_sonarqube.py

批量扫描 Android 源码。打开 `http://localhost:9000/`，默认密码 admin/admin，首次登录后请手动修改为 admin/admin123。

```sh
$ docker run -it --rm -p 9000:9000 sonarqube:community
$ readlink -f ~/hmi/apps/* > ../data/src.list
$ python3 src_sonarqube.py --config ../data/src.list [--key KEY]
```
