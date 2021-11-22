#!/bin/bash

sudo apt-get update && sudo apt-get -y install python3-dev python3-pip python3-venv openjdk-11-jdk unzip
python3 -m pip install pyaxmlparser requests_toolbelt cve-bin-tool tqdm qark

wget https://nightly.link/skylot/jadx/workflows/build/master/jadx-1.2.0.174-0efca29e.zip -O jadx.zip
unzip -q jadx.zip -d ./tools/jadx && chmod +x ./tools/jadx/bin/* && rm jadx.zip

sudo docker pull danmx/docker-androbugs
sudo docker pull opensecurity/mobile-security-framework-mobsf:latest
