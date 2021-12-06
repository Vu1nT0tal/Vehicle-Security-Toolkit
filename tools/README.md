# tools

- apktool: <https://github.com/iBotPeaches/Apktool>
- jadx: <https://github.com/skylot/jadx>

```sh
# 1. 反汇编
$ apktool d <APK_file> -o <directory_output>
# 2. 修改samli
# 3. 重打包
$ apktool b <directory_output> -o <new_APK_file> 
# 4. 签名
## 生成keystore
$ keytool -genkeypair -dname "cn=John Doe, ou=Security, o=Randorisec, c=FR" -alias <alias_name> -keystore <keystore_name> -storepass <keystore_password> -validity <days> -keyalg RSA -keysize 2048 -sigalg SHA1withRSA
## 签名
$ `find ~ -name "apksigner" | tail -1` sign --ks <keystore_name> --ks-pass pass:<keystore_password> <APK_file>

# 5. （可选）对齐
$ `find ~ -name "zipalign" | tail -1` -fv 4 <input_APK> <output_APK>
```
