#!/bin/bash

echo "[+] Converting Android sparse images to raw images"
cp $1 ./data
simg2img ./data/super.img ./data/super.img_raw
rm ./data/super.img

echo "[+] Extracting partition images from super"
mkdir ./data/system ./data/vendor
./tools/lpunpack ./data/super.img_raw ./data
rm ./data/super.img_raw

sudo mount -o ro ./data/system_a.img ./data/system
sudo mount -o ro ./data/vendor_a.img ./data/vendor

echo "[+] Extracting APK files"
APK_DIR="./data/apk"
mkdir -p $APK_DIR/system $APK_DIR/vendor
find ./data -name "*.apk" 1>$APK_DIR/apk_list.txt 2>/dev/null
cp -r ./data/system/system/app $APK_DIR/system
cp -r ./data/system/system/priv-app $APK_DIR/system
cp -r ./data/vendor/app $APK_DIR/vendor

sudo umount ./data/system
sudo umount ./data/vendor
rm -rf ./data/system ./data/vendor ./data/*.img
echo "[+] Done"
