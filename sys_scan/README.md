# sys_scan

- [sys_scan](#sys_scan)
  - [sys_boot.py](#sys_bootpy)
  - [sys_kernel.py](#sys_kernelpy)
  - [sys_selinux.py](#sys_selinuxpy)

## sys_boot.py

## sys_kernel.py

检测 Linux 内核 kconfig 安全强化选项配置错误。

```sh
$ python3 sys_kernel.py --config ~/kernel/arch/arm64/configs/s32gen1_defconfig
```

## sys_selinux.py
