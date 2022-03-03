#!/bin/bash

set -e

init_android () {
    adb root

    VER=$(frida --version)
    ABI=$(adb shell getprop ro.product.cpu.abi)
    if [[ $ABI == *arm64* ]]; then
        frida_ABI="arm64"
        other_ABI="aarch64"
    fi

    wget -q https://github.com/frida/frida/releases/download/$VER/frida-server-$VER-android-$frida_ABI.xz -O frida-server.xz
    xz -d frida-server.xz
    chmod +x frida-server && adb push frida-server /data/local/tmp/

    wget -q https://github.com/ernw/static-toolbox/releases/download/tcpdump-v4.9.3/tcpdump-4.9.3-$other_ABI -O tcpdump
    chmod +x tcpdump && adb push tcpdump /data/local/tmp/

    wget -q https://github.com/ernw/static-toolbox/releases/download/nmap-v7.91SVN/nmap-7.91SVN-$other_ABI-portable.zip -O nmap.zip
    adb push nmap.zip /data/local/tmp/
    adb shell "cd /data/local/tmp && unzip -q nmap.zip -d nmap && rm nmap.zip"

    wget -q https://github.com/ernw/static-toolbox/releases/download/gdb-v10.1/gdbserver-10.1-$other_ABI -O gdbserver
    chmod +x gdbserver && adb push gdbserver /data/local/tmp/

    rm frida-server tcpdump nmap.zip gdbserver

    adb install ./tools/drozer/drozer.apk
    adb install ./tools/wadb.apk
    adb install ./tools/SnoopSnitch.apk
}

init_linux () {
    echo
}

help () {
    echo "help: $ ./init_remote.sh [android|linux]"
}

if [ $# -eq 1 ]; then
    if [ $1 == "android" ]; then
        init_android
    elif [ $1 == "linux" ]; then
        init_linux
    else
        help
    fi
else
    help
fi
