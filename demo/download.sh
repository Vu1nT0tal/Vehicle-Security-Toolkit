#!/bin/bash

git_clone () {
    MASTER="R-X01-MASTER"

    git clone -q -b $MASTER "ssh://username@gerrit.company.com:1234/hmi/app/apk1"
}


git_pull () {
    for line in `ls`; do
       echo '[+]' $line
       cd $line && git pull -q && cd ..
    done
}


help () {
    echo "help: $ ./download.sh src [clone|pull] PATH"
    echo "help: $ ./download.sh apk [X01|W01] PATH"
}


if [ $# -eq 3 ]; then
    cd $3
    if [ $1 == "src" ]; then
        if [ $2 == "clone" ] ; then
            git_clone
        elif [ $2 == "pull" ] ; then
            git_pull
        else
            help
        fi
    elif [ $1 == "apk" ]; then
        read -p "请输入用户名：" username
        stty -echo
        read -p "请输入密码：" password
        stty echo

        today=$(date +%Y%m%d)
        url=""

        wget --user $username --password $password "$url/fastboot.zip"
    else
        help
    fi
else
    help
fi
