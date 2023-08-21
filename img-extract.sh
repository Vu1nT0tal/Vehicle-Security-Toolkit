#!/bin/bash

# 将 Android sparse image 转换成 raw image
# $ cp super.img ./data
# $ simg2img ./data/super.img ./data/super.img_raw
#
# 从 raw image 提取分区镜像文件
# $ mkdir ./data/system ./data/system_ext ./data/vendor ./data/product
# $ ./tools/lpunpack ./data/super.img_raw ./data
#
# 挂载镜像文件
# $ sudo mount -o ro ./data/system_a.img ./data/system
# $ sudo mount -o ro ./data/system_ext_a.img ./data/system_ext
# $ sudo mount -o ro ./data/vendor_a.img ./data/vendor
# $ sudo mount -o ro ./data/product_a.img ./data/product
#
# 搜索所有 APK
# $ find ./data -name "*.apk" 2>/dev/null
#
# 解析和重打包镜像文件
# $ cd ./tools/Android_boot_image_editor-master
# $ cp <original_boot_image> boot.img
# $ ./gradlew unpack
# $ ./gradlew pack


extract () {
    echo "[+] Converting Android sparse images to raw images"
    simg2img $dirpath/super.img $dirpath/super.img_raw
    rm $dirpath/super.img

    echo "[+] Extracting partition images from super"
    mkdir -p $dirpath/system $dirpath/system_ext $dirpath/vendor $dirpath/product
    ./tools/lpunpack $dirpath/super.img_raw $dirpath
    rm $dirpath/super.img_raw

    sudo mount -o ro $dirpath/system_a.img $dirpath/system
    sudo mount -o ro $dirpath/system_ext_a.img $dirpath/system_ext
    sudo mount -o ro $dirpath/vendor_a.img $dirpath/vendor
    sudo mount -o ro $dirpath/product_a.img $dirpath/product

    echo "[+] Extracting APK files"
    APK_DIR=$dirpath/apk
    APK_LIST=$APK_DIR/apk_list.txt
    LIB_LIST=$APK_DIR/lib_list.txt
    mkdir -p $APK_DIR/system/product $APK_DIR/system_ext $APK_DIR/vendor $APK_DIR/product $APK_DIR/libjni
    cp -rL $dirpath/system/system/app $APK_DIR/system 2>&1 | cut -d "'" -f 2 > $LIB_LIST
    cp -rL $dirpath/system/system/priv-app $APK_DIR/system 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
    # cp -rL $dirpath/system/system/apex $APK_DIR/system 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
    cp -rL $dirpath/system/system/prebuilt $APK_DIR/system 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
    # cp -rL $dirpath/system/system/framework/framework-res.apk $APK_DIR/system 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
    # cp -rL $dirpath/system/system/product/app $APK_DIR/system/product 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
    # cp -rL $dirpath/system/system/product/priv-app $APK_DIR/system/product 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
    cp -rL $dirpath/system_ext/app $APK_DIR/system_ext 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
    cp -rL $dirpath/system_ext/priv-app $APK_DIR/system_ext 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
    cp -rL $dirpath/vendor/app $APK_DIR/vendor 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
    cp -rL $dirpath/product/app $APK_DIR/product 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
    cp -rL $dirpath/product/priv-app $APK_DIR/product 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
    cp -rL $dirpath/product/overlay $APK_DIR/product 2>&1 | cut -d "'" -f 2 >> $LIB_LIST
    find $APK_DIR -name "*.apk" -exec md5sum {} + > $APK_LIST

    echo "[+] Extracting lib files"
    while read -r line
    do
        if [[ $line == *"$dirpath/system/"* ]]; then
            remote_path=$dirpath/system$(file $line | cut -d " " -f 6)
            local_path=$APK_DIR${line#*"$dirpath/system"}
        elif [[ $line == *"$dirpath/vendor/"* ]]; then
            remote_path=$dirpath$(file $line | cut -d " " -f 6)
            local_path=$APK_DIR${line#*"$dirpath"}
        elif [[ $line == *"$dirpath/product/"* ]]; then
            remote_path=$dirpath$(file $line | cut -d " " -f 6)
            local_path=$APK_DIR${line#*"$dirpath"}
        else
            echo "cannot found $line"
        fi
        cp $remote_path $local_path
    done < $LIB_LIST

    find $dirpath/system -type f -name "lib*jni*.so" 2>/dev/null > $LIB_LIST
    find $dirpath/system_ext -type f -name "lib*jni*.so" 2>/dev/null >> $LIB_LIST
    find $dirpath/vendor -type f -name "lib*jni*.so" 2>/dev/null >> $LIB_LIST
    find $dirpath/product -type f -name "lib*jni*.so" 2>/dev/null >> $LIB_LIST
    while read -r line
    do
        local_path=$APK_DIR/libjni/`echo $line | awk -F / '{print $(NF-2)"_"$(NF-1)"_"$NF}'`
        cp $line $local_path
    done < $LIB_LIST
    find $APK_DIR -name "*.so" -exec md5sum {} + > $LIB_LIST

    sudo umount $dirpath/system $dirpath/system_ext $dirpath/vendor $dirpath/product
    rm -rf $dirpath/system $dirpath/system_ext $dirpath/vendor $dirpath/product $dirpath/*.img
    echo "[+] Done"
}


help () {
    echo "help: $ ./img-extract.sh [super.img|fastboot.zip]"
}


if [ $# -eq 1 ]; then
    today=$(date +%Y%m%d)
    if [ ${1:0-3} == "zip" ]; then
        echo "[+] Unzipping fastboot"
        unzip -q $1 -d ./data

        dirpath="./data/image_$today"
        mkdir -p $dirpath

        cp ./data/HU_fastboot/images/super.img $dirpath
        rm -rf ./data/HU_fastboot
        extract
    elif [ ${1:0-3} == "img" ]; then
        dirpath="./data/image_$today"
        mkdir -p $dirpath

        cp $1 $dirpath/super.img
        extract
    else
        help
    fi
else
    help
fi
