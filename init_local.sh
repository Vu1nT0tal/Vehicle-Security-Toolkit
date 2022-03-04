#!/bin/bash

set -e
export PATH=$HOME/.local/bin:$PATH
root_path=$PWD
mkdir -p ~/github

echo "################# Vehicle-Security-Toolkit #################"

cat /dev/null | sudo tee /etc/apt/sources.list
sudo tee /etc/apt/sources.list >/dev/null << EOF
deb http://mirrors.aliyun.com/ubuntu/ focal main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ focal-security main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal-security main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ focal-updates main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal-updates main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ focal-proposed main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal-proposed main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ focal-backports main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal-backports main restricted universe multiverse
EOF
sudo apt-get update && sudo apt-get -y upgrade

sudo apt-get -y install python3-dev python3-pip python3-venv zip unzip npm graphviz simg2img meld maven scrcpy
python3 -m pip install virtualenv wheel pyaxmlparser requests_toolbelt future

echo "[+] Installing zsh ..."
sudo apt-get -y install git zsh expect
echo Y | sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
git clone --depth=1 https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
git clone --depth=1 https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
sed -i "/^plugins/c\plugins=(git zsh-autosuggestions zsh-syntax-highlighting)" ~/.zshrc
echo "export PATH=\$HOME/.local/bin:\$PATH" >> $HOME/.zshrc

echo "[+] Installing golang"
sudo add-apt-repository -y ppa:longsleep/golang-backports
sudo apt-get update && sudo apt-get -y install golang-go
echo "export PATH=\$HOME/go/bin:\$PATH" >> $HOME/.zshrc

echo "[+] Installing sdkman ..."
curl -s https://get.sdkman.io | bash
source $HOME/.sdkman/bin/sdkman-init.sh
sdk install java 8.0.322-tem
echo Y | sdk install java 11.0.14-tem
sdk install gradle 4.10.3
echo n | sdk install gradle 5.6.4
echo Y | sdk install gradle 6.9.2
echo n | sdk install gradle 7.4

echo "[+] Installing docker ..."
sudo apt-get -y install apt-transport-https ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo \
  "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update && sudo apt-get -y install docker-ce docker-ce-cli containerd.io
python3 -m pip install docker-compose
sudo gpasswd -a $USER docker
newgrp docker
sudo systemctl restart docker

echo "######################### apk_scan #########################"

echo "[+] Installing apktool ..."
wget -q https://github.com/iBotPeaches/Apktool/releases/download/v2.6.1/apktool_2.6.1.jar -O ./tools/apktool.jar

echo "[+] Installing jadx ..."
wget -q https://github.com/skylot/jadx/releases/download/v1.3.3/jadx-1.3.3.zip -O jadx.zip
unzip -q jadx.zip -d ./tools/jadx && chmod +x ./tools/jadx/bin/* && rm jadx.zip

echo "[+] Installing apkid ..."
python3 -m pip install apkid

echo "[+] Installing exodus-core ..."
sudo apt-get -y install dexdump
python3 -m pip install exodus-core

echo "[+] Installing quark ..."
python3 -m pip install androguard==3.4.0a1 quark-engine
freshquark

echo "[+] Installing ApplicationScanner ..."
python3 -m pip install lief rich
sudo npm -g install js-beautify
wget -q https://github.com/paradiseduo/ApplicationScanner/archive/refs/heads/main.zip
unzip -q main.zip -d ./tools/ && rm main.zip

echo "[+] Installing jni_helper ..."
wget -q https://github.com/evilpan/jni_helper/archive/refs/heads/master.zip
unzip -q master.zip -d ./tools/ && rm master.zip

echo "[+] Installing infer ..."
wget -q https://github.com/facebook/infer/releases/download/v1.1.0/infer-linux64-v1.1.0.tar.xz -O infer.tar.xz
tar -xf infer.tar.xz && mv infer-linux64-v1.1.0 ./tools/infer && rm infer.tar.xz

echo "[+] Installing fireline ..."
wget -q http://magic.360.cn/fireline_1.7.3.jar -O ./tools/fireline.jar

echo "[+] Installing SPECK"
wget -q https://github.com/SPRITZ-Research-Group/SPECK/archive/refs/heads/main.zip
unzip -q main.zip -d ./tools/ && rm main.zip

echo "[+] Installing androbugs ..."
sudo docker pull danmx/docker-androbugs

echo "[+] Installing MobSF ..."
sudo docker pull opensecurity/mobile-security-framework-mobsf

echo "[+] Installing cryptoguard ..."
sudo docker pull frantzme/cryptoguard

# wget -q https://github.com/abhi-r3v0/Adhrit/archive/refs/heads/master.zip
# unzip -q master.zip -d ./tools/ && rm master.zip
# docker-compose -f ./tools/Adhrit-master/docker-compose.yml build -q

echo "[+] Installing qark ..."
python3 -m venv ./tools/qark-env
./tools/qark-env/bin/pip install wheel colorama
./tools/qark-env/bin/pip install git+https://github.com/linkedin/qark.git

echo "[+] Installing mariana-trench ..."
python3 -m venv ./tools/mariana-trench-env
./tools/mariana-trench-env/bin/pip install colorama mariana-trench "graphene<3"

echo "[+] Installing mobileAudit ..."
wget -q https://github.com/mpast/mobileAudit/archive/refs/heads/main.zip
unzip -q main.zip -d ./tools/ && rm main.zip
docker-compose -f ./tools/mobileAudit-main/docker-compose.yaml build -q

echo "######################## src_scan ########################"

echo "[+] Installing mobsfscan ..."
sudo docker pull opensecurity/mobsfscan

echo "[+] Installing DependencyCheck ..."
wget -q https://github.com/jeremylong/DependencyCheck/releases/download/v6.5.3/dependency-check-6.5.3-release.zip -O dependency-check.zip
unzip -q dependency-check.zip -d ./tools/ && rm dependency-check.zip

wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb && rm packages-microsoft-prod.deb
sudo apt-get update && sudo apt-get -y install dotnet-sdk-3.1

echo "[+] Installing sonarqube ..."
python3 -m pip install python-sonarqube-api

sudo docker pull sonarqube:community
sudo docker pull sonarsource/sonar-scanner-cli

mkdir -p ./tools/sonarqube_extensions/plugins && cd ./tools/sonarqube_extensions/plugins
wget -q https://github.com/SonarOpenCommunity/sonar-cxx/releases/download/cxx-2.1.x-beta1/sonar-cxx-plugin-2.0.6.2921.jar
wget -q https://github.com/dependency-check/dependency-check-sonar-plugin/releases/download/3.0.1/sonar-dependency-check-plugin-3.0.1.jar
wget -q https://github.com/spotbugs/sonar-findbugs/releases/download/4.0.6/sonar-findbugs-plugin-4.0.6.jar
wget -q https://github.com/jensgerdes/sonar-pmd/releases/download/3.3.1/sonar-pmd-plugin-3.3.1.jar
wget -q https://github.com/xuhuisheng/sonar-l10n-zh/releases/download/sonar-l10n-zh-plugin-9.2/sonar-l10n-zh-plugin-9.2.jar
cd $root_path

echo "[+] Installing flawfinder ..."
# 使用 python2 避免 utf8 编码问题
virtualenv -p /usr/bin/python2 ./tools/flawfinder-env
./tools/flawfinder-env/bin/pip install flawfinder

echo "[+] Installing TscanCode ..."
wget -q https://github.com/Tencent/TscanCode/archive/refs/heads/master.zip
unzip -q master.zip -d ./tools/ && cp -r ./tools/TscanCode-master/release/linux ./tools/TscanCode && rm -rf master.zip ./tools/TscanCode-master
find ./tools/TscanCode -name "TscanCode*linux" | xargs -I {} mv {} ./tools/TscanCode/TscanCode
find ./tools/TscanCode -name tscancode -o -name tsclua -o -name TscSharp | xargs chmod +x

echo "[+] Installing cppcheck ..."
sudo apt-get -y install cmake libpcre3 libpcre3-dev
wget -q https://github.com/danmar/cppcheck/archive/refs/tags/2.7.zip
unzip -q 2.7.zip && mkdir -p ./tools/cppcheck && cd ./tools/cppcheck
cmake -DHAVE_RULES=ON -DUSE_MATCHCOMPILER=ON ../../cppcheck-2.7 && cmake --build .
cd $root_path && rm -rf 2.7.zip cppcheck-2.7

echo "[+] Installing bandit ..."
python3 -m pip install bandit

echo "[+] Installing gosec"
go install github.com/securego/gosec/v2/cmd/gosec@latest

# echo "[+] Installing scanmycode-ce"
# wget -q https://github.com/marcinguy/scanmycode-ce/archive/refs/heads/master.zip
# unzip -q master.zip -d ./tools/ && rm master.zip
# cd ./tools/scanmycode-ce-master/dockerhub && ./start.sh && cd $root_path

echo "######################### bin_scan #########################"

echo "[+] Installing cwe_checker ..."
sudo docker pull fkiecad/cwe_checker

echo "[+] Installing cve-bin-tool ..."
python3 -m pip install cve-bin-tool

echo "####################### init_remote ########################"

echo "[+] Installing frida"
python3 -m pip install frida frida-tools objection
git clone --depth=1 https://github.com/CreditTone/hooker.git ~/github/hooker
python3 -m pip install -r ~/github/hooker/requirements.txt

echo "[+] Installing wadb.apk ..."
wget -q https://github.com/RikkaApps/WADB/releases/download/v5.1.1/wadb-v5.1.1.r161.b5b65a7-release.apk -O ./tools/wadb.apk

echo "[+] Installing SnoopSnitch.apk ..."
wget -q https://opensource.srlabs.de/attachments/download/185/SnoopSnitch-2.0.11.apk -O ./tools/SnoopSnitch.apk

echo "Installing drozer ..."
# sudo docker pull fsecurelabs/drozer

mkdir -p ./tools/drozer && cd ./tools/drozer
wget -q https://github.com/FSecureLABS/drozer-agent/releases/download/2.5.0/drozer-2.5.0.apk -O drozer.apk
wget -q https://github.com/FSecureLABS/drozer/releases/download/2.4.4/drozer-2.4.4-py2-none-any.whl
cd $root_path

virtualenv -p /usr/bin/python2 ./tools/drozer/drozer-env
./tools/drozer/drozer-env/bin/pip install protobuf pyopenssl twisted service_identity
./tools/drozer/drozer-env/bin/pip install ./tools/drozer/drozer-2.4.4-py2-none-any.whl
cp ./fuzz/drozer_config ~/.drozer_config

echo "########################## others ##########################"

sudo npm -g install apk-mitm

wget -q https://github.com/JakeWharton/diffuse/releases/download/0.1.0/diffuse-0.1.0-binary.jar -O ./tools/diffuse.jar

wget -q https://github.com/cfig/Android_boot_image_editor/archive/refs/heads/master.zip
unzip -q master.zip -d ./tools/ && rm master.zip

echo "[+] Installing pwn ..."
sudo apt-get -y install gdb-multiarch tcpdump netcat
python3 -m pip install pwntools

git clone --depth=1 https://github.com/hugsy/gef.git ~/github/gef
echo "source ~/github/gef/gef.py" > ~/.gdbinit

echo "[+] Installing qemu ..."
sudo apt-get -y install qemu-system qemu-user-static

echo "[+] Installing rizin ..."
python3 -m pip install meson ninja
git clone --depth=1 https://github.com/rizinorg/rizin ~/github/rizin
cd ~/github/rizin && meson --buildtype=release --prefix=~/.local build && ninja -C build && ninja -C build install && cd $root_path
