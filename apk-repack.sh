#!/bin/bash

folder=$1
app=$2

# 生成keystore
keytool -genkey -keyalg RSA -keysize 2048 -validity 700 -noprompt -alias apkpatcheralias1 -dname "CN=apk.patcher.com, OU=ID, O=APK, L=Patcher, S=Patch, C=BR" -keystore apkpatcherkeystore -storepass password -keypass password 2>/dev/null

# 重打包
java -jar ./tools/apktool.jar b -f $folder -o $app

# 签名
jarsigner=`find ~/Android/Sdk -name "apksigner" | tail -1`
$jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore apkpatcherkeystore -storepass password $app apkpatcheralias1 >/dev/null 2>&1

# 对齐
zipalign=`find ~/Android/Sdk -name "zipalign" | tail -1`
$zipalign -c 4 $app

# 清理
rm -rf $folder/build
rm apkpatcherkeystore
