#!/bin/bash

set -e
adb root

VER=$(frida --version)
ABI=$(adb shell getprop ro.product.cpu.abi)
if [[ $ABI == *arm64* ]]; then
    ABI="arm64"
fi

wget -q https://github.com/frida/frida/releases/download/$VER/frida-server-$VER-android-$ABI.xz -O frida-server.xz
xz -d frida-server.xz
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
rm frida-server

adb install ./tools/drozer/drozer.apk
adb install ./tools/wadb.apk
