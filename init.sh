#!/bin/bash

sudo apt-get update && sudo apt-get -y install python3-dev python3-pip unzip
python3 -m pip install pyaxmlparser

wget https://nightly.link/skylot/jadx/workflows/build/master/jadx-1.2.0.98-5f24193c.zip -O jadx.zip
unzip -q jadx.zip -d jadx && chmod +x jadx/bin/* && rm jadx.zip
