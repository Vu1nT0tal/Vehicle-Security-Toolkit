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
python3 -m pip install virtualenv wheel pyaxmlparser requests_toolbelt future paramiko pyfiglet rich colorama openpyxl beautifulsoup4 lxml nvdlib

echo "[+] Installing zsh ..."
sudo apt-get -y install git zsh expect
echo Y | sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
git clone --depth=1 https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
git clone --depth=1 https://github.com/zsh-users/zsh-syntax-highlighting ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
sed -i "/^plugins/c\plugins=(git zsh-autosuggestions zsh-syntax-highlighting)" ~/.zshrc
echo "export PATH=\$HOME/.local/bin:\$PATH" >> $HOME/.zshrc

echo "[+] Installing vscode ..."
sudo apt-get -y install wget gpg apt-transport-https
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/
sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
rm -f packages.microsoft.gpg
sudo apt-get update && sudo apt-get -y install code

echo "[+] Install selenium ..."
python3 -m pip install selenium
wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O chrome.deb
wget -q https://chromedriver.storage.googleapis.com/113.0.5672.63/chromedriver_linux64.zip -O chromedriver.zip
sudo dpkg -i chrome.deb && rm chrome.deb
unzip -q chromedriver.zip && sudo mv chromedriver /usr/bin && rm chromedriver.zip

echo "[+] Installing playwright ..."
python3 -m pip install playwright
playwright install-deps
playwright install chromium

echo "[+] Installing golang ..."
sudo add-apt-repository -y ppa:longsleep/golang-backports
sudo apt-get update && sudo apt-get -y install golang-go
echo "export PATH=\$HOME/go/bin:\$PATH" >> $HOME/.zshrc

echo "[+] Installing rust ..."
echo 1 | curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

echo "[+] Installing sdkman ..."
curl -s https://get.sdkman.io | bash
source $HOME/.sdkman/bin/sdkman-init.sh
sdk install java 8.0.372-tem
echo Y | sdk install java 11.0.19-tem
echo n | sdk install java 17.0.7-tem
sdk install gradle 4.10.3
echo n | sdk install gradle 5.6.4
echo Y | sdk install gradle 6.9.4
echo n | sdk install gradle 7.6.1

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
wget -q https://github.com/iBotPeaches/Apktool/releases/download/v2.8.1/apktool_2.8.1.jar -O ./tools/apktool.jar

echo "[+] Installing jadx ..."
wget -q https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip -O jadx.zip
unzip -q jadx.zip -d ./tools/jadx && chmod +x ./tools/jadx/bin/* && rm jadx.zip

echo "[+] Installing apkid ..."
python3 -m pip install apkid

echo "[+] Installing exodus-core ..."
# sudo apt-get -y install dexdump
# mv /usr/bin/dexdump /usr/bin/dexdump2
wget -q https://dl.google.com/android/repository/build-tools_r33-linux.zip
unzip -q build-tools_r33-linux.zip -d ./tools/ && rm build-tools_r33-linux.zip
sudo ln -s ./tools/android-13/dexdump /usr/bin/dexdump
python3 -m pip install exodus-core

echo "[+] Installing quark ..."
python3 -m pip install androguard==3.4.0a1 quark-engine
mkdir -p ./tools/quark && cd ./tools/quark
git clone --depth=1 https://github.com/quark-engine/quark-rules rules
git clone --depth=1 https://github.com/quark-engine/quark-script scripts
cd $root_path

echo "[+] Installing DISintegrity ..."
python3 -m pip install jinja2 tqdm
wget -q https://github.com/user1342/DISintegrity/archive/refs/heads/main.zip
unzip -q main.zip -d ./tools/ && rm main.zip

echo "[+] Installing ApplicationScanner ..."
python3 -m pip install lief
sudo npm -g install js-beautify
wget -q https://github.com/paradiseduo/ApplicationScanner/archive/refs/heads/main.zip
unzip -q main.zip -d ./tools/ && rm main.zip
cp ./tools/apktool.jar ./tools/ApplicationScanner-main/ThirdTools/apktool.jar

echo "[+] Installing AppInfoScanner ..."
wget -q https://github.com/kelvinBen/AppInfoScanner/archive/refs/heads/master.zip
unzip -q master.zip -d ./tools/ && rm master.zip
cp ./tools/apktool.jar ./tools/AppInfoScanner-master/tools/apktool.jar
python3 -m pip install -r ./tools/AppInfoScanner-master/requirements.txt

echo "[+] Installing jni_helper ..."
wget -q https://github.com/evilpan/jni_helper/archive/refs/heads/master.zip
unzip -q master.zip -d ./tools/ && rm master.zip

echo "[+] Installing infer ..."
wget -q https://github.com/facebook/infer/releases/download/v1.1.0/infer-linux64-v1.1.0.tar.xz -O infer.tar.xz
tar -xf infer.tar.xz && mv infer-linux64-v1.1.0 ./tools/infer && rm infer.tar.xz

echo "[+] Installing fireline ..."
wget -q http://magic.360.cn/fireline_1.7.3.jar -O ./tools/fireline.jar

echo "[+] Installing SPECK ..."
wget -q https://github.com/SPRITZ-Research-Group/SPECK/archive/refs/heads/main.zip
unzip -q main.zip -d ./tools/ && rm main.zip

echo "[+] Installing keyfinder ..."
python3 -m pip install python-magic pyOpenSSL
wget -q https://github.com/CERTCC/keyfinder/archive/refs/heads/master.zip
unzip -q master.zip -d ./tools/ && rm master.zip

echo "[+] Installing APKHunt ..."
# wget -q https://github.com/Cyber-Buddy/APKHunt/archive/refs/heads/main.zip
go build -o ./tools/apkhunt ./tools/apkhunt.go

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
./tools/qark-env/bin/pip install wheel
./tools/qark-env/bin/pip install git+https://github.com/linkedin/qark

echo "[+] Installing SimpleWalker ..."
wget -q https://github.com/zkwlx/SimpleWalker/releases/download/1.3/release.zip
unzip -q release.zip && mv release ./tools/SimpleWalker && rm release.zip

echo "[+] Installing AppShark ..."
wget -q https://github.com/bytedance/appshark/archive/refs/heads/main.zip
unzip -q main.zip -d ./tools/ && rm main.zip
wget -q https://github.com/bytedance/appshark/releases/download/v0.1.2/AppShark-0.1.2-all.jar -O ./tools/appshark-main/AppShark.jar
cp ./tools/appshark-rules/*.json ./tools/appshark-main/config/rules

echo "[+] Installing mariana-trench ..."
python3 -m venv ./tools/mariana-trench-env
./tools/mariana-trench-env/bin/pip install wheel mariana-trench

echo "[+] Installing mobileAudit ..."
wget -q https://github.com/mpast/mobileAudit/archive/refs/heads/main.zip
unzip -q main.zip -d ./tools/ && rm main.zip
docker-compose -f ./tools/mobileAudit-main/docker-compose.yaml build -q

echo "[+] Installing AndRoPass ..."
wget -q https://github.com/koengu/AndRoPass/archive/refs/heads/main.zip
unzip -q main.zip -d ./tools/ && rm main.zip

echo "[+] Installing Android-App-Link-Verification-Tester ..."
wget -q https://github.com/inesmartins/Android-App-Link-Verification-Tester/archive/refs/heads/main.zip
unzip -q main.zip -d ./tools/ && rm main.zip

echo "######################## src_scan ########################"

echo "[+] Installing mobsfscan ..."
sudo docker pull opensecurity/mobsfscan

echo "[+] Installing DependencyCheck ..."
wget -q https://github.com/jeremylong/DependencyCheck/releases/download/v8.2.1/dependency-check-8.2.1-release.zip -O dependency-check.zip
unzip -q dependency-check.zip -d ./tools/ && rm dependency-check.zip

wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb && rm packages-microsoft-prod.deb
sudo apt-get update && sudo apt-get -y install dotnet-sdk-3.1

echo "[+] Installing sonarqube ..."
python3 -m pip install python-sonarqube-api

sudo docker pull sonarqube:community
sudo docker pull sonarsource/sonar-scanner-cli

mkdir -p ./tools/sonarqube_extensions/plugins && cd ./tools/sonarqube_extensions/plugins
wget -q https://github.com/SonarOpenCommunity/sonar-cxx/releases/download/cxx-2.1.0/sonar-cxx-plugin-2.1.0.428.jar
wget -q https://github.com/dependency-check/dependency-check-sonar-plugin/releases/download/4.0.0/sonar-dependency-check-plugin-4.0.0.jar
wget -q https://github.com/spotbugs/sonar-findbugs/releases/download/4.2.3/sonar-findbugs-plugin-4.2.3.jar
wget -q https://github.com/jborgers/sonar-pmd/releases/download/3.4.0/sonar-pmd-plugin-3.4.0.jar
wget -q https://github.com/xuhuisheng/sonar-l10n-zh/releases/download/sonar-l10n-zh-plugin-10.0/sonar-l10n-zh-plugin-10.0.jar
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
wget -q https://github.com/danmar/cppcheck/archive/refs/tags/2.10.zip
unzip -q 2.10.zip && mkdir -p ./tools/cppcheck && cd ./tools/cppcheck
cmake -DHAVE_RULES=ON -DUSE_MATCHCOMPILER=ON ../../cppcheck-2.10 && cmake --build .
cd $root_path && rm -rf 2.10.zip cppcheck-2.10

echo "[+] Installing weggli ..."
cargo install weggli

echo "[+] Installing bandit ..."
python3 -m pip install bandit

echo "[+] Installing gosec ..."
go install github.com/securego/gosec/v2/cmd/gosec@latest

echo "[+] Installing snyk ..."
wget -q https://github.com/snyk/cli/releases/download/v1.1156.0/snyk-linux -O ./tools/snyk && chmod +x ./tools/snyk

echo "[+] Installing codeql ..."
mkdir -p ~/github/codeql-home && cd ~/github/codeql-home
wget -q https://github.com/github/codeql-cli-binaries/releases/download/v2.13.1/codeql-linux64.zip && unzip -q codeql-linux64.zip
export PATH=$HOME/github/codeql-home/codeql:$PATH && echo "export PATH=\$HOME/github/codeql-home/codeql:\$PATH" >> $HOME/.zshrc
git clone --depth=1 https://github.com/github/codeql codeql-repo
rm codeql-linux64.zip && cd $root_path

echo "[+] Installing semgrep ..."
mkdir -p ./tools/semgrep && cd ./tools/semgrep
python3 -m pip install semgrep
git clone --depth=1 https://github.com/returntocorp/semgrep-rules default
git clone --depth=1 https://github.com/0xdea/semgrep-rules c_cpp
git clone --depth=1 https://github.com/mindedsecurity/semgrep-rules-android-security android
cd $root_path

echo "[+] Installing cq ..."
python3 -m pip install regex
wget -q https://github.com/nccgroup/cq/archive/refs/heads/main.zip
unzip -q main.zip -d ./tools/ && rm main.zip

echo "[+] Installing codechecker ..."
sudo apt-get install clang clang-tidy build-essential gcc-multilib
curl -sL https://deb.nodesource.com/setup_16.x | sudo -E bash - && sudo apt-get install -y nodejs
python3 -m pip install codechecker

# echo "[+] Installing scanmycode-ce"
# wget -q https://github.com/marcinguy/scanmycode-ce/archive/refs/heads/master.zip
# unzip -q master.zip -d ./tools/ && rm master.zip
# cd ./tools/scanmycode-ce-master/dockerhub && mkdir -p data1 data2/tasks && docker-compose build && cd $root_path

echo "######################### bin_scan #########################"

echo "[+] Installing stacs ..."
git clone --depth=1 https://github.com/stacscan/stacs-rules ./tools/stacs-rules
sudo apt-get -y install libarchive-dev
python3 -m pip install stacs

echo "[+] Installing capa ..."
wget -q https://github.com/mandiant/capa/releases/download/v5.1.0/capa-v5.1.0-linux.zip -O capa.zip
unzip -q capa.zip -d ./tools/ && rm capa.zip

echo "[+] Installing cwe_checker ..."
sudo docker pull fkiecad/cwe_checker

echo "[+] Installing BinAbsInspector ..."
wget -q https://github.com/KeenSecurityLab/BinAbsInspector/archive/refs/heads/main.zip
unzip -q main.zip && mv BinAbsInspector-main tools/BinAbsInspector && rm main.zip
cd ./tools && cp BinAbsInspector/Dockerfile ./ && docker build . -t absinspector && rm Dockerfile && cd $root_path

echo "[+] Installing cve-bin-tool ..."
python3 -m pip install cve-bin-tool && cve-bin-tool -u now

echo "######################### sys_scan #########################"

echo "[+] Installing kconfig-hardened-check ..."
python3 -m pip install git+https://github.com/a13xp0p0v/kconfig-hardened-check

echo "[+] Installing syzkaller ..."
sudo apt-get -y install gcc gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
git clone --depth=1 https://github.com/google/syzkaller ~/github/syzkaller

echo "######################### cve_scan #########################"

python3 -m pip install openai tiktoken translators pygerrit2 xmltodict

echo "[+] Installing linux-exploit-suggester ..."
wget -q https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -P ./tools
chmod +x ./tools/linux-exploit-suggester.sh

echo "[+] Installing linux_kernel_cves ..."
python3 -m pip install "thefuzz[speedup]"
python3 -m pip install cve_searchsploit && cve_searchsploit -u
git clone --depth=1 https://github.com/nluedtke/linux_kernel_cves ~/github/linux_kernel_cves

echo "[+] Installing CVEhound ..."
yes | sudo add-apt-repository ppa:npalix/coccinelle
sudo apt install coccinelle libpython2.7
python3 -m pip install git+https://github.com/evdenis/cvehound
cvehound_update_rules # && cvehound_update_metadata

echo "####################### init_remote ########################"

echo "[+] Installing frida"
python3 -m pip install frida frida-tools objection
git clone --depth=1 https://github.com/CreditTone/hooker ~/github/hooker
python3 -m pip install -r ~/github/hooker/requirements.txt

echo "[+] Installing wadb.apk ..."
wget -q https://github.com/RikkaApps/WADB/releases/download/v7.0.0/wadb-v7.0.0.r212.65458e8-release.apk -O ./tools/wadb.apk

echo "[+] Installing SnoopSnitch.apk ..."
wget -q https://opensource.srlabs.de/attachments/download/188/SnoopSnitch-2.0.12.apk -O ./tools/SnoopSnitch.apk

echo "[+] Installing camille ..."
python3 -m pip install xlwt click
wget -q https://github.com/zhengjim/camille/archive/refs/heads/master.zip
unzip -q master.zip -d ./tools/ && rm master.zip

echo "[+] Installing radamsa ..."
git clone --depth=1 https://gitlab.com/akihe/radamsa
cd radamsa && make && sudo make install
cd $root_path && rm -rf radamsa

echo "[+] Installing drozer ..."
# sudo docker pull fsecurelabs/drozer
mkdir -p ./tools/drozer && cd ./tools/drozer
wget -q https://github.com/FSecureLABS/drozer-agent/releases/download/2.5.2/agent-debug.apk -O drozer.apk
wget -q https://github.com/FSecureLABS/drozer/releases/download/2.4.4/drozer-2.4.4-py2-none-any.whl
cd $root_path

virtualenv -p /usr/bin/python2 ./tools/drozer/drozer-env
./tools/drozer/drozer-env/bin/pip install protobuf pyopenssl twisted service_identity
./tools/drozer/drozer-env/bin/pip install ./tools/drozer/drozer-2.4.4-py2-none-any.whl
cp ./fuzz/drozer_config ~/.drozer_config

echo "########################## others ##########################"

wget -q https://github.com/google/bundletool/releases/download/1.15.4/bundletool-all-1.15.4.jar -O ./tools/bundletool.jar

sudo npm -g install apk-mitm

wget -q https://github.com/JakeWharton/diffuse/releases/download/0.1.0/diffuse-0.1.0-binary.jar -O ./tools/diffuse.jar

wget -q https://github.com/cfig/Android_boot_image_editor/archive/refs/heads/master.zip
unzip -q master.zip -d ./tools/ && rm master.zip

echo "[+] Installing pwn ..."
sudo dpkg --add-architecture i386
sudo apt-get -y install gdb-multiarch patchelf tcpdump netcat socat nasm libc6-dbg libc6-dbg:i386 ruby-dev
sudo apt-get -y install glibc-source && tar -xf /usr/src/glibc/glib*.tar.xz
sudo gem install one_gadget seccomp-tools
python3 -m pip install pwntools ropper ropgadget capstone keystone
git clone --depth=1 https://github.com/hugsy/gef ~/github/gef
echo "source ~/github/gef/gef.py" > ~/.gdbinit

echo "[+] Installing qemu ..."
sudo apt-get -y install qemu-system qemu-user-static

echo "[+] Installing rizin ..."
python3 -m pip install meson ninja
git clone --depth=1 https://github.com/rizinorg/rizin ~/github/rizin
cd ~/github/rizin && meson --buildtype=release --prefix=~/.local build && ninja -C build && ninja -C build install && cd $root_path
