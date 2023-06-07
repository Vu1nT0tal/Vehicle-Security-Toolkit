# bin_scan

- [bin\_scan](#bin_scan)
  - [bin\_checksec.py](#bin_checksecpy)
  - [bin\_stacs.py](#bin_stacspy)
  - [bin\_capa.py](#bin_capapy)
  - [bin\_cwechecker.py](#bin_cwecheckerpy)
  - [bin\_absinspector.py](#bin_absinspectorpy)
  - [bin\_cvescan.py](#bin_cvescanpy)


## bin_checksec.py

使用该脚本批量分析 SO/ELF 文件并生成安全属性报告。

```sh
$ python3 bin_checksec.py --config ../data/elf.list
```

## bin_stacs.py

使用该脚本批量扫描静态凭证等敏感数据。

```sh
$ python3 bin_stacs.py --config ../data/elf.list
```

## bin_capa.py

使用该脚本批量分析 SO/ELF 文件并生成行为报告。

```sh
$ python3 bin_capa.py --config ../data/elf.list
```

## bin_cwechecker.py

使用该脚本批量静态分析 SO/ELF 文件并生成漏洞报告。

```sh
$ find ~/apks -type f ! -path "*jadx_java*" ! -regex ".*\(apk\|java\|smali\|dex\|xml\|yml\|json\|ini\|txt\|png\|jpg\|wav\|webp\|svg\|kcm\|version\|SF\|RSA\|MF\|data\|dat\|pak\|zip\|kotlin.*\|lifecycle.*\)$" | xargs file | grep "ELF" | cut -d ":" -f 1 | xargs realpath > ../data/elf.list
$ python bin_cwechecker.py --config ../data/elf.list
```

## bin_absinspector.py

使用该脚本批量静态分析 SO/ELF 文件并生成漏洞报告。（耗时较长）

```sh
$ python bin_absinspector.py --config ../data/elf.list
```

## bin_cvescan.py

导出 system 目录后，使用该脚本批量扫描开源组件并获取 CVE 详情。

```sh
$ python3 bin_cvescan.py --config ../data/elf.list
```

- APK 第三方库(`.jar`)识别。[paper](https://arxiv.org/pdf/2108.01964.pdf)
  - [LibDetect](https://sites.google.com/view/libdetect/)
  - [LibScout](https://github.com/reddr/LibScout)
  - [LibRadar](https://github.com/pkumza/LibRadar)
  - [LibPecker](https://github.com/yuanxzhang/LibPecker)
