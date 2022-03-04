# 开发环境

基于 VirtualBox 和 Vagrant 的开发环境。

```sh
$ sudo apt install virtualbox virtualbox-ext-pack

$ curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
$ sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
$ sudo apt update && sudo apt install vagrant
```

查看 Vagrantfile 并修改相关配置。启动后本目录会映射到 `/vagrant`，作为共享目录。

```sh
$ vagrant up        # 启动
$ vagrant ssh       # 连接
$ vagrant suspend   # 暂停
$ vagrant halt      # 关闭
$ vagrant destroy   # 删除

$ vagrant box list      # 列出镜像
$ vagrant box remove    # 删除镜像

$ vagrant package   # 打包镜像
```
