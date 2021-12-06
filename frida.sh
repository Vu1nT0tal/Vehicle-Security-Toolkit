#!/bin/bash

set -e

python3 -m pip install frida frida-tools

VER=`frida --version`
ABI=`adb shell getprop ro.product.cpu.abi`
wget https://github.com/frida/frida/releases/download/$VER/frida-server-$VER-android-$ABI.xz
xz -d frida-server-$VER-android-$ABI.xz

adb root
adb push frida-server-$VER-android-$ABI /data/local/tmp/frida
adb shell "chmod 755 /data/local/tmp/frida" 
adb shell "/data/local/tmp/frida"

rm frida-server-$VER-android-$ABI.xz frida-server-$VER-android-$ABI
