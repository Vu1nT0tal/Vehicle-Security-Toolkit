#!/bin/bash

echo "******************* mem-heapdump.sh ******************"

if [ $# != 1 ]; then
    echo -e "USAGE: $0 <PROCESS>\n\t\t\tprocess name or pid\n"
    #adb shell ps -ef
    exit 1
fi

# managed heap
adb root
adb remount

MAT="/home/firmy/mat"   # 设置MAT地址

MANAGED="/data/local/tmp/original.hprof"
PKGNAME=$1
adb shell ps -ef | grep $PKGNAME

if [ "$?" != "0" ]; then
    echo "[!] The process does not exists!"
    exit 1
fi

if [ ! -d "$PKGNAME" ]; then
    mkdir $PKGNAME
fi

echo "[*] Dumping managed heap..."
adb shell am dumpheap $PKGNAME $MANAGED
sleep 8

adb pull $MANAGED $PKGNAME
adb shell rm $MANAGED

echo "[*] Converting hprof format..."
hprof-conv -z $PKGNAME/original.hprof $PKGNAME/converted.hprof

echo "[*] Executing MAT analysis..."
$MAT/ParseHeapDump.sh $PKGNAME/converted.hprof org.eclipse.mat.api:suspects org.eclipse.mat.api:overview org.eclipse.mat.api:top_components > /dev/null
rm -rf workspace

if [ "$?" != "0" ]; then
    echo "[!] Managed dump and analysis failed"
else
    echo "[*] Managed dump and analysis succeeded"
fi

# native heap
# https://github.com/aosp-mirror/platform_development/blob/master/scripts/native_heapdump_viewer.py

# NATIVE="/data/local/tmp/native_heap.txt"
# adb shell stop
# adb shell setprop libc.debug.malloc.program app_process
# adb shell setprop libc.debug.malloc.options backtrace=64
# adb shell start

# echo "[*] Dumping native heap..."
# adb shell am dumpheap -n $PKGNAME $NATIVE
# sleep 8

# adb pull $NATIVE $PKGNAME
# adb shell rm $NATIVE

# echo "[*] Native dump and analysis succeeded"
