#!/bin/sh

if [ $# != 1 ]; then
    echo "USAGE: sudo $0 <memory/M>"
    echo "MemFree:" $(expr $(cat /proc/meminfo | grep MemFree | awk '{print $2}') / 1024) "M"
    echo "MemAvailable:" $(expr $(cat /proc/meminfo | grep MemAvailable | awk '{print $2}') / 1024) "M"
    exit 1;
fi

mkdir /tmp/memory
mount -t tmpfs -o size=$1M tmpfs-test /tmp/memory
dd if=/dev/zero of=/tmp/memory/block

sleep 60

rm /tmp/memory/block
umount /tmp/memory
rmdir /tmp/memory
