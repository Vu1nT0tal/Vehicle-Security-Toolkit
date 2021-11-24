#!/bin/bash

adb push result.txt /data/local/tmp 2>/dev/null

adb shell rm /system/xbin/sh 2>/dev/null
