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
cp -r ./data/system/system/app $APK_DIR/system
cp -r ./data/system/system/priv-app $APK_DIR/system
cp -r ./data/vendor/app $APK_DIR/vendor
find $APK_DIR -name "*.apk" -exec md5sum {} + > $APK_DIR/apk_list.txt

sudo umount ./data/system
sudo umount ./data/vendor
rm -rf ./data/system ./data/vendor ./data/*.img
echo "[+] Done"
