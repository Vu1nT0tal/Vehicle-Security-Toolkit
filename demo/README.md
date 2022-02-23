# demo

- [demo](#demo)
  - [download_app.sh](#download_appsh)
  - [build_config.json](#build_configjson)

## download_app.sh

下载或更新代码仓库。

```sh
$ ./download_app.sh [clone|pull] ~/hmi/app
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
