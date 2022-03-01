#!/usr/bin/python2
# -*- coding: UTF-8 -*-

from drozer import android
from drozer.modules import common, Module


class Null(Module, common.Filters, common.PackageManager):
    name = "find NullPointerException"
    examples = """dz> run fuzz.null com.example.app"""
    path = ["fuzz"]
    permissions = ["com.mwr.dz.permissions.GET_CONTEXT"]

    def add_arguments(self, parser):
        parser.add_argument("package", help="the identifier of the package to inspect")

    def attack(self, component, package, flags):
        act = None
        cat = None
        data = None
        comp = (package, component.name)
        extr = None
        flgs = None

        if flags == 'activity':
            flgs = ['ACTIVITY_NEW_TASK']

        intent = android.Intent(action=act, component=comp, category=cat, data_uri=None, extras=extr, flags=flgs, mimetype=None)

        if intent.isValid():
            if flags == 'activity':
                self.getContext().startActivity(intent.buildIn(self))
            if flags == 'service':
                self.getContext().startService(intent.buildIn(self))
            if flags == 'receiver':
                self.getContext().sendBroadcast(intent.buildIn(self))
        else:
            self.stderr.write("[-] Invalid Intent!\n")

    def execute(self, arguments):
        if arguments.package != None:
            package = self.packageManager().getPackageInfo(arguments.package, common.PackageManager.GET_ACTIVITIES | common.PackageManager.GET_RECEIVERS | common.PackageManager.GET_PROVIDERS | common.PackageManager.GET_SERVICES)
            application = package.applicationInfo

            activities = self.match_filter(package.activities, 'exported', True)
            receivers = self.match_filter(package.receivers, 'exported', True)
            providers = self.match_filter(package.providers, 'exported', True)
            services = self.match_filter(package.services, 'exported', True)

            self.stdout.write("Attack Surface:\n")
            self.stdout.write("  %d activities exported\n" % len(activities))
            self.stdout.write("  %d broadcast receivers exported\n" % len(receivers))
            self.stdout.write("  %d content providers exported\n" % len(providers))
            self.stdout.write("  %d services exported\n" % len(services))

            if (application.flags & application.FLAG_DEBUGGABLE) != 0:
                self.stdout.write("    is debuggable\n")

            if package.sharedUserId != None:
                self.stdout.write("    Shared UID (%s)\n" % package.sharedUserId)

            actions = [activities, receivers, services]
            action_str = ['activity', 'receiver', 'service']
            i = -1
            try:
                for action in actions:
                    i += 1
                    if len(action) > 0:
                        for tmp in action:
                            try:
                                if len(tmp.name) > 0:
                                    self.stdout.write(" [+]%s name:%s\n" % (action_str[i], tmp.name))
                                    self.attack(component=tmp, package=arguments.package, flags=action_str[i])
                            except Exception as e:
                                self.stdout.write(" error-->%s name:%s\n" % (action_str, tmp.name))
                                self.stdout.write(" errorcontent:%s\n" % e)
                                continue
            except Exception as e:
                self.stdout.write(" error")
        else:
            self.stdout.write("No package specified\n")
