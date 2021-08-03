# Vehicle-Security-Toolkit

汽车安全测试工具集

## adb-export

当拿到一个车机不知道该下载或查看哪些东西的时候，使用该脚本一键搞定。

```sh
$ ./adb-export.sh
*************** adb-export script ***************
    1. Collect basic information, init and selinux
    2. Execute live commands
    3. Execute package manager commands
    4. Execute bugreport, dumpsys, appops
    5. Acquire /system folder
    6. Acquire /sdcard folder
    7. Extract APK files
    8. Extract data from content providers
    9. Extract databases and keys
    10. Extract compressed files
    11. Acquire an ADB Backup
    12. Do all of the above
Choose an option: 
```
