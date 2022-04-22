# bin_scan

- [bin_scan](#bin_scan)
  - [bin_stacs.py](#bin_stacspy)
  - [bin_cwechecker.py](#bin_cwecheckerpy)
  - [bin_absinspector.py](#bin_absinspectorpy)
  - [bin_cvescan.py](#bin_cvescanpy)

## bin_stacs.py

使用该脚本批量扫描静态凭证等敏感数据。

```sh
$ python3 bin_stacs.py --config ../data/elf.list
```

## bin_cwechecker.py

使用该脚本批量静态分析 SO/ELF 文件并生成报告。

```sh
$ find ~/apks -type f ! -path "*jadx_java*" ! -regex ".*\(apk\|java\|smali\|dex\|xml\|yml\|json\|ini\|txt\|png\|jpg\|wav\|webp\|svg\|kcm\|version\|SF\|RSA\|MF\|data\|dat\|pak\|zip\|kotlin.*\|lifecycle.*\)$" | xargs file | grep "ELF" | cut -d ":" -f 1 | xargs realpath > ../data/elf.list
$ python bin_cwechecker.py --config ../data/elf.list
```

## bin_absinspector.py

使用该脚本批量静态分析 SO/ELF 文件并生成报告。（耗时较长）

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
