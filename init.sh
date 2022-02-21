#!/bin/bash

set -e

curl -s https://get.sdkman.io | bash
source "$HOME"/.sdkman/bin/sdkman-init.sh
sdk install java 8.0.312-tem
sdk install java 11.0.13-tem
sdk install gradle 4.10.3
sdk install gradle 5.6.4
sdk install gradle 6.9.2

sudo apt-get update && sudo apt-get -y install zsh apt-transport-https git python3-dev python3-pip python3-venv unzip npm graphviz dexdump simg2img meld maven golang
python3 -m pip install wheel pyaxmlparser requests_toolbelt apkid cve-bin-tool tqdm lief rich quark-engine future exodus-core androguard==3.4.0a1 meson ninja docker-compose python-sonarqube-api
sudo npm -g install js-beautify apk-mitm

echo "export PATH=\$HOME/.local/bin:\$PATH" >> "$HOME"/.profile
source "$HOME"/.profile
freshquark

wget -q https://github.com/iBotPeaches/Apktool/releases/download/v2.6.0/apktool_2.6.0.jar -O ./tools/apktool.jar
wget -q https://github.com/JakeWharton/diffuse/releases/download/0.1.0/diffuse-0.1.0-binary.jar -O ./tools/diffuse.jar

wget -q https://github.com/skylot/jadx/releases/download/v1.3.3/jadx-1.3.3.zip -O jadx.zip
unzip -q jadx.zip -d ./tools/jadx && chmod +x ./tools/jadx/bin/* && rm jadx.zip

wget -q https://github.com/paradiseduo/ApplicationScanner/archive/refs/heads/main.zip
unzip -q main.zip -d ./tools/ && rm main.zip

wget -q https://github.com/evilpan/jni_helper/archive/refs/heads/master.zip
unzip -q master.zip -d ./tools/ && rm master.zip

wget -q https://github.com/cfig/Android_boot_image_editor/archive/refs/heads/master.zip
unzip -q master.zip -d ./tools/ && rm master.zip

wget -q https://github.com/jeremylong/DependencyCheck/releases/download/v6.5.3/dependency-check-6.5.3-release.zip -O dependency-check.zip
unzip -q dependency-check.zip -d ./tools/ && rm dependency-check.zip

wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb && rm packages-microsoft-prod.deb
sudo apt-get update && sudo apt-get -y install dotnet-sdk-3.1

wget -q https://github.com/facebook/infer/releases/download/v1.1.0/infer-linux64-v1.1.0.tar.xz -O infer.tar.xz
tar -xf infer.tar.xz && mv infer-linux64-v1.1.0 ./tools/infer && rm infer.tar.xz

wget -q http://magic.360.cn/fireline_1.7.3.jar -O ./tools/fireline.jar

sudo docker pull danmx/docker-androbugs
sudo docker pull opensecurity/mobile-security-framework-mobsf
sudo docker pull opensecurity/mobsfscan
sudo docker pull frantzme/cryptoguard
sudo docker pull fkiecad/cwe_checker
sudo docker pull sonarqube:community
sudo docker pull sonarsource/sonar-scanner-cli

wget -q https://github.com/abhi-r3v0/Adhrit/archive/refs/heads/master.zip
unzip -q master.zip -d ./tools/ && rm master.zip
docker-compose -f ./tools/Adhrit-master/docker-compose.yml build -q

wget -q https://github.com/mpast/mobileAudit/archive/refs/heads/main.zip
unzip -q main.zip -d ./tools/ && rm main.zip
docker-compose -f ./tools/mobileAudit-main/docker-compose.yml build -q

python3 -m venv ./tools/qark
source ./tools/qark/bin/activate
python3 -m pip install wheel
python3 -m pip install git+https://github.com/linkedin/qark.git
deactivate

python3 -m venv ./tools/mariana-trench
source ./tools/mariana-trench/bin/activate
python3 -m pip install mariana-trench "graphene<3"
deactivate

git clone https://github.com/rizinorg/rizin
cd rizin && meson --buildtype=release --prefix=~/.local build && ninja -C build && ninja -C build install && cd .. && rm -rf rizin
