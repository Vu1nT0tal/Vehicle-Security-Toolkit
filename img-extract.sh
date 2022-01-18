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
APK_LIST=$APK_DIR/apk_list.txt
LIB_LIST=$APK_DIR/lib_list.txt
mkdir -p $APK_DIR/system/product $APK_DIR/vendor
cp -rL ./data/system/system/app $APK_DIR/system 2>&1 | cut -d "'" -f 2 > $LIB_LIST
cp -rL ./data/system/system/priv-app $APK_DIR/system 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
cp -rL ./data/system/system/product/app $APK_DIR/system/product 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
cp -rL ./data/system/system/product/priv-app $APK_DIR/system/product 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
cp -rL ./data/vendor/app $APK_DIR/vendor 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
find $APK_DIR -name "*.apk" -exec md5sum {} + > $APK_LIST

echo "[+] Extracting lib files"
while read -r line
do
    if [[ $line == *"data/system"* ]]; then
        remote_path=./data/system`file $line | cut -d " " -f 6`
        local_path=$APK_DIR${line#*"./data/system"}
    elif [[ $line == *"data/vendor"* ]]; then
        remote_path=./data/vendor`file $line | cut -d " " -f 6`
        local_path=$APK_DIR${line#*"./data"}
    else
        echo "cannot found $line"
    fi
    cp $remote_path $local_path
done < $LIB_LIST
find $APK_DIR -name "*.so" -exec md5sum {} + > $LIB_LIST

sudo umount ./data/system
sudo umount ./data/vendor
rm -rf ./data/system ./data/vendor ./data/*.img
echo "[+] Done"
