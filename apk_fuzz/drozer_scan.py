#!/usr/bin/python2
# -*- coding: UTF-8 -*-

import os
import re
import time
import pyfiglet
import argparse

from drozer.console.session import Session
from drozer.connector import ServerConnector


class Arguments:
    def __init__(self, ip):
        self.server = ip

    accept_certificate = False
    command = "connect"
    debug = False
    device = None
    file = []
    no_color = False
    onecmd = None
    password = False
    ssl = False


class DrozerServer:
    def __init__(self, ip):
        args = Arguments(ip)
        server = ServerConnector(args, None)
        device = server.listDevices().system_response.devices[0].id
        response = server.startSession(device, None)
        session_id = response.system_response.session_id
        self.session = Session(server, session_id, args)

    def getSession(self):
        return self.session


class Fuzz:
    def __init__(self, ip, port, scanner_types, components_types, report_path):
        ip_adrr = "%s:%s" % (ip, port)
        self.session = DrozerServer(ip_adrr).getSession()
        self.initConfig(ip, port)
        self.scanner_types = scanner_types
        self.components_types = components_types
        self.report_path = report_path

    def initConfig(self, ip, port):
        cmd1 = "adb forward tcp:%s tcp:%s" % (port, port)
        cmd2 = "adb connect %s:%s" % (ip, port)
        cmd3 = 'adb shell "rm -rf /sdcard/tempimg && mkdir -p /sdcard/tempimg"'
        os.popen(cmd1)
        os.popen(cmd2)
        os.popen(cmd3)

    def analysis(self, package_list):
        # 获取所有应用的组件信息
        curred_app_num = 1
        for package_name in package_list:
            print("+ 总共"+str(len(package_list))+"个应用，正在处理第"+ str(curred_app_num) +"个：" + package_name)

            for components_type in self.components_types:
                self.getComponentsInfo(package_name, components_type)
                time.sleep(5)
            curred_app_num += 1

        # 拉取所有截图文件
        screencap_path = os.path.join(self.report_path, "screencap")
        if not os.path.exists(screencap_path):
            os.mkdir(screencap_path)

        cmd = "adb pull /sdcard/tempimg/ %s && adb shell rm -rf /sdcard/tempimg" % screencap_path
        os.popen(cmd)

    # 获取应用的组件信息
    def getComponentsInfo(self, package_name, components_type):
        components_info_path = os.path.join(self.report_path, package_name+"."+components_type)
        if not os.path.exists(components_info_path):
            with open(components_info_path, "w+") as f:
                self.session.stdout = f
                cmd = "app.%s.info -a %s" % (components_type, package_name)
                print("\t |- 正在查询组件信息："+cmd)
                self.session.do_run(cmd)
                time.sleep(2)

        modules = []
        components_names = self.getComponents(components_info_path, components_type)
        if components_type != "provider":
            print("\t\t |- 组件：" + components_type+"可导出的数量为："+str(len(components_names)))
        else:
            print("\t\t |- 组件："+components_type +"存在问题的数量为："+str(len(components_names)))

        components_num = 0
        for components_name in components_names:
            if components_type == "provider":
                pattern = re.compile(r'[0-9]@_@')
                print("\t\t\t |- 可能存在问题的组件为：" + re.sub(pattern, "", components_name))
            else:
                print("\t\t\t |- 可导出的组件为：" + components_name)
            if components_type == "activity":
                modules = ["start"]
            elif components_type == "service":
                modules = ["start", "stop"]
            elif components_type == "broadcast":
                modules =["send"]
            else:
                modules =["projection", "selection", ""]
            self.runComponents(components_type, modules, package_name, components_name, components_num)
            components_num += 1

    # 执行组件并进行截图
    def runComponents(self, components_type, modules, package_name, components_name, components_num):
        for module in modules:
            if components_type  == "provider":
                content_list = components_name.split("@_@")
                if content_list[0] == "1" and module.startswith("projection"):
                    self.injectioninQuery(package_name, content_list[1], module, components_num)
                    continue
                if content_list[0] == "2" and module.startswith("selection"):
                    self.injectioninQuery(package_name, content_list[1], module, components_num)
                    continue
                if content_list[0] == "3" and module.startswith(""):
                    self.injectioninQuery(package_name, content_list[1], module, components_num)
                    continue
            else:
                cmd = "app.%s.%s --component %s %s" % (components_type, module, package_name, components_name)
                print("\t\t\t\t |- 正在执行组件：" + cmd)
                self.session.do_run(cmd)
                time.sleep(2)
                screencap_cmd = "adb shell screencap -p /sdcard/tempimg/%s_%s_%s.png" % (components_type, package_name, components_name)
                os.popen(screencap_cmd)
                os.popen("adb shell am start com.mwr.dz/com.mwr.dz.activities.MainActivity")

    def getComponents(self, components_info_path, components_type):
        components_names = []

        # 忽略0kb大小的文件
        if os.path.getsize(components_info_path) == 0:
            return components_names

        with open(components_info_path, "r") as f:
            for line in f:
                le = line.replace(" ", "").replace("\n", "")
                # 忽略第一行的包信息
                if le.startswith("Package:"):
                    package = le.replace("Package:", "")
                    continue

                # 忽略没有组件导出的文件
                if le.startswith("Noexportedservices.") or le.startswith("Nomatchingreceivers.") or le.startswith(
                        "Nomatchingactivities.") or le.startswith("Nomatchingproviders."):
                    return components_names

                if components_type == "provider":
                    if le.startswith("ReadPermission:null") or le.startswith("WritePermission:null"):
                        provider_path = os.path.join(self.report_path, components_type)
                        if not os.path.exists(provider_path):
                            os.mkdir(provider_path)

                        self.scannerProvider(components_names, provider_path, package)
                        return components_names
                    else:
                        continue

                self.clStr(components_names, le)
        return components_names

    # 处理组件的基本信息
    def clStr(self, components_names, le):
        # 忽略所有Permission行
        if not le.startswith("Permission"):
            if not (le.startswith("ParentActivity:") or le.startswith("TargetActivity:")) and len(le) > 0:
                components_names.append(le)
        else:
            permission_package = le.replace("Permission:", "")
            if not permission_package.startswith("null") and len(components_names) != 0:
                components_names.remove(components_names[len(components_names)-1])

    # 扫描Provider组件漏洞
    def scannerProvider(self, components_names, provider_path, package_name):
        for scanner_type in self.scanner_types:
            scanner_provider_path = os.path.join(provider_path, package_name + "."+scanner_type)
            if not os.path.exists(scanner_provider_path):
                with open(scanner_provider_path, "w+") as f:
                    self.session.stdout = f
                    cmd = "scanner.provider.%s -a %s" % (scanner_type, package_name)
                    print("\t\t |- 正在扫描Provider组件漏洞："+cmd)
                    self.session.do_run(cmd)
                    time.sleep(2)

            flag = 0
            with open(scanner_provider_path, "r") as f:
                for line in f:
                    le = line.replace(" ", "").replace("\n", "")

                    if le.startswith("NotVulnerable") or le.startswith("Novulnerabilitiesfound") or le.startswith("Scanning"):
                        continue
                    elif le.startswith("InjectioninProjection"):
                        flag = 1
                        continue
                    elif le.startswith("InjectioninSelection"):
                        flag = 2
                        continue
                    elif le.startswith("VulnerableProviders"):
                        flag =3
                        continue

                    if flag != 0 and le.startswith("content://"):
                        components_names.append(str(flag)+"@_@"+le)

    # 注入
    def injectioninQuery(self, package_name, content_name, schme_type, components_num):
        injectionin_dir = os.path.join(self.report_path, "injectionin")
        if not os.path.exists(injectionin_dir):
            os.mkdir(injectionin_dir)

        schme_type_err_provider_path = os.path.join(injectionin_dir, "err_"+package_name + "_"+str(components_num) +"." + schme_type)
        if os.path.exists(schme_type_err_provider_path):
            os.remove(schme_type_err_provider_path)

        with open(schme_type_err_provider_path, "w+") as f:
            self.session.stderr = f

            cmd = "app.provider.query %s --%s %s" % (content_name, schme_type, '\"\'\"')
            print("\t\t\t\t |- 正在进行注入操作：" + cmd)

            self.session.do_run(cmd)
            f.write(cmd + "\r")

        return schme_type_err_provider_path

    # 对内容组件进行操作并截图
    def actionProvider(self, components_name):
        cmd = "scanner.provider.traversal -a %s" % (components_name)
        print("\t\t\t |- "+cmd)
        self.session.do_run(cmd)

        time.sleep(2)

        cmd = "scanner.provider.injection -a %s" % (components_name)
        print("\t\t\t |- "+cmd)
        self.session.do_run(cmd)


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='A config file containing APK package name', type=str, required=True)
    parser.add_argument('--ip', help='Ip of drozer device [default 127.0.0.1]', type=str, required=False)
    parser.add_argument('--port', help='Port of drozer device [default 31415]', type=str, required=False)
    return parser.parse_args()


if __name__ == '__main__':
    print(pyfiglet.figlet_format('drozer_scan'))
    args = argument()
    package_list = open(args.config, 'r').read().splitlines()

    ip = args.ip if args.ip else "127.0.0.1"
    port = args.port if args.port else "31415"

    report_path = "./drozer_data"
    if not os.path.exists(report_path):
        os.makedirs(report_path)

    scanner_types = ["traversal", "injection"]
    components_types = ["provider", "activity", "service", "broadcast"]

    Fuzz(ip, port, scanner_types, components_types, report_path).analysis(package_list)
