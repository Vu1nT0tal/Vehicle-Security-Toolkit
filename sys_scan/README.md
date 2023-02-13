# sys_scan

- [sys\_scan](#sys_scan)
  - [sys\_boot.py](#sys_bootpy)
  - [sys\_kernel.py](#sys_kernelpy)
  - [sys\_selinux.py](#sys_selinuxpy)
  - [sys\_syzkaller.py](#sys_syzkallerpy)

## sys_boot.py

## sys_kernel.py

检测 Linux 内核 kconfig 安全强化选项配置错误。

```sh
$ python3 sys_kernel.py --config ~/kernel/arch/arm64/configs/s32gen1_defconfig
```

## sys_selinux.py

## sys_syzkaller.py

使用 syzkaller 对内核进行 fuzz。

```sh
$ cd ~/github/syzkaller && make TARGETOS=linux TARGETARCH=arm64
```
