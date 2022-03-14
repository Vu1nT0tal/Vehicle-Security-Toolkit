# poc_scan

- [poc_scan](#poc_scan)
  - [linux-exploit-suggester.sh](#linux-exploit-suggestersh)
  - [poc_dirtycow.py](#poc_dirtycowpy)

## linux-exploit-suggester.sh

```sh
$ ../tools/linux-exploit-suggester.sh -f -d -u "$(uname -a)"
```

## poc_dirtycow.py

CVE-2022-0847：https://dirtypipe.cm4all.com/

```sh
$ python3 poc_dirtycow.py --arch [x64|arm|aarch64] --connect [adb|ssh] --device ip:port
```
