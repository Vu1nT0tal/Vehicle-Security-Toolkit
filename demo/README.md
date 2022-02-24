# demo

- [demo](#demo)
  - [download.sh](#downloadsh)
  - [build_config.json](#build_configjson)

## download.sh

下载或更新镜像或代码仓库。

```sh
$ ./download.sh src [clone|pull] PATH
$ ./download.sh apk [X01|W01] PATH
```

## build_config.json

配置 APK 编译环境，作为源码测试工具的输入。

```json
{
    "apk1": {
        "java": 11,
        "gradle": 6,
        "build": "gradlew"
    }
}
```
