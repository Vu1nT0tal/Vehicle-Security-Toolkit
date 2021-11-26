#!/bin/bash

set -e

sudo apt-get update && sudo apt-get -y install git python3-dev python3-pip python3-venv openjdk-11-jdk unzip npm graphviz
python3 -m pip install wheel pyaxmlparser requests_toolbelt cve-bin-tool tqdm qark lief rich quark-engine
sudo npm -g install js-beautify

freshquark

wget -q https://github.com/iBotPeaches/Apktool/releases/download/v2.6.0/apktool_2.6.0.jar -O ./tools/apktool.jar

wget -q https://github.com/skylot/jadx/releases/download/v1.3.0/jadx-1.3.0.zip -O jadx.zip
unzip -q jadx.zip -d ./tools/jadx && chmod +x ./tools/jadx/bin/* && rm jadx.zip

wget -q https://github.com/paradiseduo/ApplicationScanner/archive/refs/heads/main.zip
unzip -q main.zip -d ./tools/ && rm main.zip

sudo docker pull danmx/docker-androbugs
sudo docker pull opensecurity/mobile-security-framework-mobsf:latest

# 不按照这个顺序会出错，不知道为什么
python3 -m venv ./tools/mariana-trench
source ./tools/mariana-trench/bin/activate

python3 -m pip install flask-graphql graphene-sqlalchemy
python3 -m pip install mariana-trench
