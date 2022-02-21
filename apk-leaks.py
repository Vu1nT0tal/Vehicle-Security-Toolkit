#!/usr/bin/python3

import json
import logging.config
import os
import re
import sys
import threading
import argparse

from pathlib import Path


notkeyhacks = {
	"Sift_Key": "\\.with(?:AccountId|BeaconKey)\\([\"|'].*[\"|']\\)",
	"Sentry_DSN": "https?:\/\/(\\w+)(:\\w+)?@sentry\\.io\/[0-9]+",
	"Intercom_API_Key": "Intercom\\.initialize\\([\"|']?\\w+[\"|']?,\\s?[\"|']?\\w+[\"|']?,\\s?[\"|']?\\w+[\"|']?\\)",
	"Singular_Config": "SingularConfig\\([\"|']?[\\w._]+[\"|']?,\\s?[\"|']?[\\w._]+[\"|']?\\)",
	"Adjust_Config": [
		"AdjustConfig\\([\"|']?[\\w]+[\"|']?,\\s?[\"|']?[\\w]+[\"|']?(,\\s?[\"|']?[\\w]+[\"|']?)?\\)",
		"([a|A]djust)?[C|c]onfig\\.setAppSecret\\(.*\\)"
	],
	"Bitmovin_API_Key": "BITMOVIN_API_KEY\\s?=\\s?['|\"]?.*['|\"]?",
	"Salesforce_MarketingCloud_Token": "setAccessToken\\(\\w+.MC_ACCESS_TOKEN\\)",
	"AppDynamics_Key": "AgentConfiguration\\.builder\\(\\)(\\s*)?([\\.\\w\\(\\)\\s]+)\\.withAppKey\\(.*?\\)",
	"AppCenter_Secret": "AppCenter\\.(configure|start)\\(.*\\)"
}

regexes = {
	"Amazon_AWS_Access_Key_ID": "([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}",
	"Amazon_AWS_S3_Bucket": [
		"//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+",
		"//s3\\.amazonaws\\.com/[a-z0-9._-]+",
		"[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com",
		"[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)",
		"[a-z0-9.-]+\\.s3\\.amazonaws\\.com",
		"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
	],
	"Artifactory_API_Token": "(?:\\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}",
	"Artifactory_Password": "(?:\\s|=|:|\"|^)AP[\\dABCDEF][a-zA-Z0-9]{8,}",
	"Authorization_Basic": "basic\\s[a-zA-Z0-9_\\-:\\.=]+",
	"Authorization_Bearer": "bearer\\s[a-zA-Z0-9_\\-:\\.=]+",
	"AWS_API_Key": "AKIA[0-9A-Z]{16}",
	"Basic_Auth_Credentials": "(?<=:\/\/)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-zA-Z]+",
	"Cloudinary_Basic_Auth": "cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+",
	"DEFCON_CTF_Flag": "O{3}\\{.*\\}",
	"Discord_BOT_Token": "((?:N|M|O)[a-zA-Z0-9]{23}\\.[a-zA-Z0-9-_]{6}\\.[a-zA-Z0-9-_]{27})$",
	"Facebook_Access_Token": "EAACEdEose0cBA[0-9A-Za-z]+",
	"Facebook_ClientID": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K](.{0,20})?['\"][0-9]{13,17}",
	"Facebook_OAuth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
	"Facebook_Secret_Key": "([f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K]|[f|F][b|B])(.{0,20})?['\"][0-9a-f]{32}",
	"Firebase": "[a-z0-9.-]+\\.firebaseio\\.com",
	"Generic_API_Key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
	"Generic_Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
	"GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
	"GitHub_Access_Token": "([a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github.com*)$",
	"Google_API_Key": "AIza[0-9A-Za-z\\-_]{35}",
	"Google_Cloud_Platform_OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
	"Google_Cloud_Platform_Service_Account": "\"type\": \"service_account\"",
	"Google_OAuth_Access_Token": "ya29\\.[0-9A-Za-z\\-_]+",
	"HackerOne_CTF_Flag": "[h|H]1(?:[c|C][t|T][f|F])?\\{.*\\}",
	"HackTheBox_CTF_Flag": "[h|H](?:[a|A][c|C][k|K][t|T][h|H][e|E][b|B][o|O][x|X]|[t|T][b|B])\\{.*\\}$",
	"Heroku_API_Key": "[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
	"IP_Address": "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])",
	"JSON_Web_Token": "(?i)^((?=.*[a-z])(?=.*[0-9])(?:[a-z0-9_=]+\\.){2}(?:[a-z0-9_\\-\\+\/=]*))$",
	"LinkFinder": "(?:\"|')(((?:[a-zA-Z]{1,10}:\/\/|\/\/)[^\"'\/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:\/|\\.\\.\/|\\.\/)[^\"'><,;| *()(%%$^\/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-\/]{1,}\/[a-zA-Z0-9_\\-\/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-\/]{1,}\/[a-zA-Z0-9_\\-\/]{3,}(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\\?|#][^\"|']{0,}|)))(?:\"|')",
	"Mac_Address": "(([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{2}[-]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{4}[\\.]){2}[0-9A-Fa-f]{4})$",
	"MailChimp_API_Key": "[0-9a-f]{32}-us[0-9]{1,2}",
	"Mailgun_API_Key": "key-[0-9a-zA-Z]{32}",
	"Mailto": "(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9.-]+",
	"Password_in_URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
	"PayPal_Braintree_Access_Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
	"PGP_private_key_block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
	"Picatic_API_Key": "sk_live_[0-9a-z]{32}",
	"RSA_Private_Key": "-----BEGIN RSA PRIVATE KEY-----",
	"Slack_Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
	"Slack_Webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
	"Square_Access_Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
	"Square_OAuth_Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
	"SSH_DSA_Private_Key": "-----BEGIN DSA PRIVATE KEY-----",
	"SSH_EC_Private_Key": "-----BEGIN EC PRIVATE KEY-----",
	"Stripe_API_Key": "sk_live_[0-9a-zA-Z]{24}",
	"Stripe_Restricted_API_Key": "rk_live_[0-9a-zA-Z]{24}",
	"TryHackMe_CTF_Flag": "[t|T](?:[r|R][y|Y][h|H][a|A][c|C][k|K][m|M][e|E]|[h|H][m|M])\\{.*\\}$",
	"Twilio_API_Key": "SK[0-9a-fA-F]{32}",
	"Twitter_Access_Token": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
	"Twitter_ClientID": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R](.{0,20})?['\"][0-9a-z]{18,25}",
	"Twitter_OAuth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
	"Twitter_Secret_Key": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R](.{0,20})?['\"][0-9a-z]{35,44}"
}



class col:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class util:
    @staticmethod
    def write(message, color):
        sys.stdout.write("%s%s%s" % (color, message, col.ENDC))

    @staticmethod
    def writeln(message, color):
        util.write(message + "\n", color)

    @staticmethod
    def finder(pattern, path):
        matcher = re.compile(pattern)
        found = []
        for fp, _, files in os.walk(path):
            for fn in files:
                filepath = os.path.join(fp, fn)
                with open(filepath) as f:
                    try:
                        for line in f.readlines():
                            mo = matcher.search(line)
                            if mo:
                                found.append(mo.group())
                    except Exception:
                        pass
        return sorted(list(set(found)))


class APKLeaks:
    def __init__(self, apk_path: Path):
        self.file = apk_path
        self.tempdir = self.file.parent.joinpath("jadx_java")
        self.output = self.file.parent.joinpath(self.file.stem+'-apkleaks.json')
        self.fileout = open(self.output, "w+")  
        self.out_json = {}
        self.scanned = False
        logging.config.dictConfig({"version": 1, "disable_existing_loggers": True})

    def extract(self, name, matches):
        if len(matches):
            self.out_json["results"][name] = []
            util.writeln(f'\n[{name}]', col.OKGREEN)
            regexe = r"^.(L[a-z]|application|audio|fonts|image|kotlin|layout|multipart|plain|text|video|java).*\/.+"
            for secret in matches:
                if name == "LinkFinder":
                    if re.match(regexe, secret) is not None:
                        continue
                    secret = secret[len("'"):-len("'")]
                print(f'- {secret}')
                self.out_json["results"][name].append(secret)
            self.scanned = True

    def scanning(self):
        util.writeln(f"\n** Scanning against '{self.file}'", col.OKBLUE)
        self.out_json["results"] = {}

        for name, pattern in regexes.items():
            if isinstance(pattern, list):
                for p in pattern:
                    try:
                        thread = threading.Thread(target=self.extract, args=(name, util.finder(p, self.tempdir)))
                        thread.start()
                    except KeyboardInterrupt:
                        sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))
            else:
                try:
                    thread = threading.Thread(target=self.extract, args=(name, util.finder(pattern, self.tempdir)))
                    thread.start()
                except KeyboardInterrupt:
                    sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))

    def cleanup(self):
        if self.scanned:
            self.fileout.write("%s" % json.dumps(self.out_json, indent=4))
            self.fileout.close()
            print(f"{col.HEADER}\n** Results saved into '{col.ENDC}{col.OKGREEN}{self.output}{col.HEADER}'{col.ENDC}.")
        else:
            self.fileout.close()
            os.remove(self.output)
            util.writeln("\n** Done with nothing.", col.WARNING)


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="A config file containing APK path", type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    print('******************** apk-leaks.py ********************')
    args = argument()
    apk_dirs = open(args.config, 'r').read().splitlines()

    for apk in apk_dirs:
        init = APKLeaks(Path(apk))
        init.scanning()
        init.cleanup()
