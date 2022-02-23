#!/bin/bash

git_clone () {
    MASTER="R-MASTER"

    git clone -q -b $MASTER "ssh://username@gerrit.company.com:1234/hmi/app/apk1"
}

git_pull () {
    for line in `ls`; do
       echo '[+]' $line
       cd $line && git pull -q && cd ..
    done
}

help () {
    echo "help: $ ./download_app.sh [clone|pull] PATH"
}

if [ $# -eq 2 ]; then
    cd $2
    if [ $1 == "clone" ] ; then
        git_clone
    elif [ $1 == "pull" ] ; then
        git_pull
    else
        help
    fi
else
    help
fi
