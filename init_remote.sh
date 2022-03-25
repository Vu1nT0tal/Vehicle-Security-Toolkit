#!/bin/bash

set -e

init_android () {
    if [ $2 == "adb" ]; then
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
    elif [ $2 == "ssh" ]; then
        help
    else
        help
    fi
}

init_linux () {
    if [ $1 == "adb" ]; then
        help
    elif [ $1 == "ssh" ]; then
        read -p "请输入用户名：" username
        stty -echo
        read -p "请输入密码：" password
        stty echo
        if [ $username == "root" ]; then
            prompt=":~# "
        else
            prompt=":~$ "
        fi

output=$(/usr/bin/expect<<EOF
    set timeout 10
    spawn ssh $username@${ip%:*} -p ${ip#*:}
    expect {
        "(yes/no)? " { send "yes\r"; exp_continue }
        "password: " { send "$password\r" }
    }
    expect "$prompt"
    send "uname -a\r"
    expect eof
EOF
)

        if [[ $output == *aarch64* ]]; then
            ABI="aarch64"
        elif [[ $output == *arm* ]]; then
            ABI="armhf"
        elif [[ $output == *x86_64* ]]; then
            ABI="x86_64"
        elif [[ $output == *x86* ]]; then
            ABI="x86"
        fi
        wget -q https://github.com/ernw/static-toolbox/releases/download/tcpdump-v4.9.3/tcpdump-4.9.3-$ABI -O $tools/tcpdump
        wget -q https://github.com/ernw/static-toolbox/releases/download/nmap-v7.91SVN/nmap-7.91SVN-$ABI-portable.zip -O $tools/nmap.zip
        wget -q https://github.com/ernw/static-toolbox/releases/download/gdb-v10.1/gdbserver-10.1-$ABI -O $tools/gdbserver

/usr/bin/expect<<EOF
    set timeout 10
    spawn scp -r -P ${ip#*:} $tools $username@${ip%:*}:/tmp
    expect {
        "(yes/no)? " { send "yes\r"; exp_continue }
        "password: " { send "$password\r" }
    }
    expect eof
EOF

    else
        help
    fi
}

help () {
    echo "help: $ ./init_remote.sh [android|linux] [adb|ssh ip:port]"
}

tools="./tools/remote_tools"
mkdir -p $tools
if [ $# -eq 3 ]; then
    ip=$3
else
    ip=""
fi

if [ $1 == "android" ]; then
    init_android $2 $ip
elif [ $1 == "linux" ]; then
    init_linux $2 $ip
else
    help
fi
