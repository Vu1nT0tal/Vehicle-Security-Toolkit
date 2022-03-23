#!/bin/bash

time_update () { NOW=$(date +"%Y%m%d_%H_%M_%S"); }

check_tools() {
    TOOL="adb"
    if [ "$(command -v "$TOOL" | wc -l)" == "1" ]; then
        ADB="$(command -v "$TOOL")"
    else
        if [[ -f "./$TOOL" ]]; then
            ADB="./$TOOL"
        else
            echo "[!] $TOOL NOT FOUND! It's not be able to use adb-extract script"
            exit
        fi
    fi
}

set_var () {
    # generic commands
    SHELL_CMD="${ADB} shell"
    BACKUP_CMD="${ADB} backup"
    PULL_CMD="${ADB} pull"
    BUGREPORT_CMD="${ADB} bugreport"

    # Android ID
    ANDROID_ID=$($SHELL_CMD settings get secure android_id)
}

set_path () {
    time_update

    SPATH="${ANDROID_ID}"

    INFO_DIR="${SPATH}/${NOW}_info"
    INFO_TXT_FILE="${INFO_DIR}/device_info.txt"

    LIVE_DIR="${SPATH}"/${NOW}_live

    PM_DIR="${SPATH}"/${NOW}_package_manager

    DUMPSYS_DIR="${SPATH}/${NOW}_dumpsys"

    SDCARD_DIR="${SPATH}/${NOW}_sdcard"
    SDCARD_LOG_FILE="$SDCARD_DIR/log_sdcard_acquisition.txt"

    SYSTEM_DIR="${SPATH}/${NOW}_system"
    SYSTEM_LOG_FILE="$SYSTEM_DIR/log_system_acquisition.txt"

    APK_DIR="${SPATH}/${NOW}_apk"

    CONTENTPROVIDER_DIR="${SPATH}/${NOW}_contentprovider"

    DATABASE_DIR="${SPATH}/${NOW}_database"

    KEYS_DIR="${SPATH}/${NOW}_keys"

    CONF_DIR="${SPATH}/${NOW}_conf"

    COMPRESSED_DIR="${SPATH}/${NOW}_compressed"

    BIN_DIR="${SPATH}/${NOW}_bin"

    BACKUP_DIR="${SPATH}/${NOW}_backup"
}

check_device () {
    if [ -z "$ANDROID_ID" ]; then
        echo "[!] NO DEVICE CONNECTED!"
	fi
}

info_collect () {
    set_path
    mkdir -p $INFO_DIR

    $SHELL_CMD getprop > "$INFO_DIR/getprop.txt"
    $SHELL_CMD settings list system > "$INFO_DIR/settings_system.txt"
    $SHELL_CMD settings list secure > "$INFO_DIR/settings_secure.txt"
    $SHELL_CMD settings list global > "$INFO_DIR/settings_global.txt"

    PRODUCT=$($SHELL_CMD getprop ro.product.model)
    MANUFACTURER=$($SHELL_CMD getprop ro.product.manufacturer) 
    ANDROID_SERIAL_NUMBER=$($SHELL_CMD getprop ro.serialno)
    FINGERPRINT=$($SHELL_CMD getprop ro.build.fingerprint)
    DISPLAY_ID=$($SHELL_CMD getprop ro.build.display.id)
    ANDROID_VERSION=$($SHELL_CMD getprop ro.build.version.release)
    SDK_VERSION=$($SHELL_CMD getprop ro.build.version.sdk)
    BUILD_TYPE=$($SHELL_CMD getprop ro.build.type)
    BUILD_DATE=$($SHELL_CMD getprop ro.build.date)
    BUILD_ID=$($SHELL_CMD getprop ro.build.id)
    BOOTLOADER=$($SHELL_CMD getprop ro.boot.bootloader)
    SECURITY_PATCH=$($SHELL_CMD getprop ro.build.version.security_patch)
    BLUETOOTH_MAC=$($SHELL_CMD settings get secure bluetooth_address)
    BLUETOOTH_NAME=$($SHELL_CMD settings get secure bluetooth_name)
    TIMEZONE=$($SHELL_CMD getprop persist.sys.timezone)
    MANUFACTURER=$($SHELL_CMD getprop ro.product.manufacturer)
    DEVICE=$($SHELL_CMD getprop ro.product.device)
    NAME=$($SHELL_CMD getprop ro.product.name)
    CHIPNAME=$($SHELL_CMD getprop ro.chipname)
    SERIAL_NUMBER=$($SHELL_CMD getprop ril.serialnumber)
    BASEBAND_VERSION=$($SHELL_CMD getprop gsm.version.baseband)
    COUNTRY_CODE=$($SHELL_CMD getprop ro.csc.country_code)
    USB_CONFIGURATION=$($SHELL_CMD getprop persist.sys.usb.config)
    STORAGE_SIZE=$($SHELL_CMD getprop storage.mmc.size)
    ENCRYPTION=$($SHELL_CMD getprop ro.crypto.state)
    SELINUX=$($SHELL_CMD getenforce)

    ENCRYPTION_TYPE="none"
    if [[ ! $ENCRYPTION =~ "unecrypted" ]]; then
        ENCRYPTION_TYPE=$($SHELL_CMD getprop ro.crypto.type)
    fi

    IMEI=$($SHELL_CMD dumpsys iphonesubinfo | grep 'Device ID' | grep -o '[0-9]+')
    if [[ -z $IMEI ]]; then
        IMEI=$($SHELL_CMD service call iphonesubinfo 1 | awk -F "'" '{print $2}' | sed '1 d' | tr -d '.' | awk '{print}' ORS=)
    fi

    echo -e "
[+] Dumping info from device $MANUFACTURER $PRODUCT\n[+]
[*] Android_id: $ANDROID_ID
[*] Android Serial number: $ANDROID_SERIAL_NUMBER
[*] Serial number: $SERIAL_NUMBER
[*] IMEI: $IMEI
[*] Android version (SDK): $ANDROID_VERSION ($SDK_VERSION)
[*] Product Device: $DEVICE
[*] Product Name: $NAME
[*] Chipname: $CHIPNAME
[*] Android fingerprint: $FINGERPRINT
[*] Display ID: $DISPLAY_ID
[*] Build date: $BUILD_DATE
[*] Build ID: $BUILD_ID
[*] Build type: $BUILD_TYPE
[*] Bootloader: $BOOTLOADER
[*] Security Patch: $SECURITY_PATCH
[*] Bluetooth_address: $BLUETOOTH_MAC
[*] Bluetooth_name: $BLUETOOTH_NAME
[*] Timezone: $TIMEZONE
[*] USB Configuration: $USB_CONFIGURATION
[*] Storage Size: $STORAGE_SIZE
[*] SELinux: $SELINUX
[*] Device is $ENCRYPTION, Encryption type: $ENCRYPTION_TYPE" >&1 | tee "$INFO_TXT_FILE"

    # init files: https://android.googlesource.com/platform/system/core/+/master/init/README.md
    echo -e "[+]\n[+] Extracting init files\n[+]"
    mkdir -p "$INFO_DIR/init"

    $SHELL_CMD ls -1 init*.rc | while read line; do
        $PULL_CMD $line $INFO_DIR/init
    done

    # selinux
    echo -e "[+]\n[+] Extracting selinux files\n[+]"
    $PULL_CMD /etc/selinux $INFO_DIR/selinux
    $PULL_CMD /vendor/etc/selinux $INFO_DIR/selinux/vendor_selinux
    $PULL_CMD /system/etc/selinux $INFO_DIR/selinux/system_selinux
    $PULL_CMD /sys/fs/selinux/policy $INFO_DIR/selinux/sysfs_selinux_policy
    $SHELL_CMD dmesg | grep 'avc: ' > $INFO_DIR/selinux/avc_log.txt

    time_update
    echo -e "[+]\n[+] Dumping info completed at $NOW"
}

live_commands () {
    set_path
    mkdir -p "$LIVE_DIR"

    echo -e "\n[+] Executing live commands on the device\n[+]"

    echo "[*] id" && $SHELL_CMD id > $LIVE_DIR/id.txt
    echo "[*] uname -a" && $SHELL_CMD uname -a > $LIVE_DIR/uname-a.txt
    echo "[*] cat /proc/version" && $SHELL_CMD cat /proc/version > $LIVE_DIR/kernel_version.txt
    echo "[*] printenv" && $SHELL_CMD printenv > $LIVE_DIR/printenv.txt
    echo "[*] cat /proc/partitions" && $SHELL_CMD cat /proc/partitions > $LIVE_DIR/partitions.txt
    echo "[*] cat /proc/cpuinfo" && $SHELL_CMD cat /proc/cpuinfo > $LIVE_DIR/cpuinfo.txt
    echo "[*] cat /proc/diskstats" && $SHELL_CMD cat /proc/diskstats > $LIVE_DIR/diskstats.txt
    echo "[*] df -ah" && $SHELL_CMD df -ah > $LIVE_DIR/df-ah.txt
    echo "[*] mount" && $SHELL_CMD mount > $LIVE_DIR/mount.txt
    echo "[*] ip address show wlan0" && $SHELL_CMD ip address show wlan0 > $LIVE_DIR/ip_wlan0.txt
    echo "[*] ifconfig -a" && $SHELL_CMD ifconfig -a > $LIVE_DIR/ifconfig-a.txt
    echo "[*] netstat -anp" && $SHELL_CMD netstat -an > $LIVE_DIR/netstat-anp.txt
    echo "[*] lsof" && $SHELL_CMD lsof > $LIVE_DIR/lsof.txt
    echo "[*] ps -efZ" && $SHELL_CMD ps -efZ > $LIVE_DIR/ps-ef.txt
    echo "[*] top -n 1" && $SHELL_CMD top -n 1 > $LIVE_DIR/top.txt
    echo "[*] cat /proc/sched_debug" && $SHELL_CMD cat /proc/sched_debug > $LIVE_DIR/proc_sched_debug.txt
    echo "[*] vmstat" && $SHELL_CMD vmstat > $LIVE_DIR/vmstat.txt
    echo "[*] sysctl -a" && $SHELL_CMD sysctl -a > $LIVE_DIR/sysctl-a.txt
    echo "[*] ime list" && $SHELL_CMD ime list > $LIVE_DIR/ime_list.txt
    echo "[*] service list" && $SHELL_CMD service list > $LIVE_DIR/service_list.txt
    echo "[*] logcat -S -b all" && $SHELL_CMD logcat -S -b all > $LIVE_DIR/logcat-S-b_all.txt
    echo "[*] logcat -d -b all V:*" && $SHELL_CMD logcat -d -b all V:*  > $LIVE_DIR/logcat-d-b_all_V.txt
    echo "[*] ls -al /dev" && $SHELL_CMD ls -al /dev > $LIVE_DIR/ls-al_dev.txt

    time_update
    echo -e "[+]\n[+] Live acquisition completed at $NOW"
}

package_manager_commands () {
    set_path
    mkdir -p "$PM_DIR"

    echo -e "\n[+] Executing 'pm' commands on the device\n[+]"

    echo "[*] pm get-max-users" && $SHELL_CMD pm get-max-users > $PM_DIR/pm_get_max_users.txt
    echo "[*] pm list users" && $SHELL_CMD pm list users > $PM_DIR/pm_list_users.txt
    echo "[*] pm list features" && $SHELL_CMD pm list features > $PM_DIR/pm_list_features.txt
    echo "[*] pm list instrumentation" && $SHELL_CMD pm list instrumentation > $PM_DIR/pm_list_instrumentation.txt
    echo "[*] pm list libraries -f" && $SHELL_CMD pm list libraries -f > $PM_DIR/pm_list_libraries-f.txt
    echo "[*] pm list packages -f" && $SHELL_CMD pm list packages -f > $PM_DIR/pm_list_packages-f.txt
    echo "[*] pm list permissions -f" && $SHELL_CMD pm list permissions -f > $PM_DIR/pm_list_permissions-f.txt
    echo "[*] pm list permission-groups -f" && $SHELL_CMD pm list permission-groups -f > $PM_DIR/pm_list_permission-groups-f.txt

    echo "[*] cat /data/system/uiderrors.txt" && $SHELL_CMD cat /data/system/uiderrors.txt > $PM_DIR/uiderrors.txt

    time_update
    echo -e "[+]\n[+] PACKAGE MANAGER Acquisition completed at $NOW"
}

sdcard () {
    set_path
    mkdir -p "$SDCARD_DIR/sdcard"

    echo -e "\n[+] Extracting files from /sdcard"

    $SHELL_CMD ls /sdcard
    $PULL_CMD /sdcard ${SDCARD_DIR} > "$SDCARD_LOG_FILE"

    time_update
    echo "[+] SDCARD acquisition completed at $NOW"
}

dumpsys () {
    set_path
    mkdir -p "$DUMPSYS_DIR"

    echo -e "\n[+] Extracting bugreport, dumpsys and appops information\n[+]"

    echo "[*] bugreport" && $BUGREPORT_CMD $DUMPSYS_DIR/bugreport.zip
    echo "[*] dumpsys" && $SHELL_CMD dumpsys > $DUMPSYS_DIR/dumpsys.txt

    for item in $( adb shell dumpsys -l | tail -n +2 | sed 's/[[:space:]]//g' ); do
        if [[ "$item" != "meminfo" && "$item" != "procstats" ]]; then
            echo "[*] dumpsys $item"
            $SHELL_CMD dumpsys $item > $DUMPSYS_DIR/dumpsys_${item// /}.txt
        fi
    done

    echo "[*] dumpsys meminfo -a" && $SHELL_CMD dumpsys meminfo -a > $DUMPSYS_DIR/dumpsys_meminfo-a.txt
    echo "[*] dumpsys procstats --full-details" && $SHELL_CMD dumpsys procstats --full-details > $DUMPSYS_DIR/dumpsys_procstats--full-details.txt 

    # Process dumpsys diskstats: https://android.stackexchange.com/questions/220442/obtaining-app-storage-details-via-adb

    F_PKG_NAMES=$DUMPSYS_DIR/package_names.txt
    F_PKG_SIZE=$DUMPSYS_DIR/app_pkg_sizes.txt
    F_DAT_SIZE=$DUMPSYS_DIR/app_data_sizes.txt
    F_CACHE_SIZE=$DUMPSYS_DIR/app_cache_sizes.txt
    F_OUTPUT=$DUMPSYS_DIR/dumpsys_diskstats_ordered.txt
    sed -n '/Package Names:/p' $DUMPSYS_DIR/dumpsys_diskstats.txt | sed -e 's/,/\n/g' -e 's/"//g' -e 's/.*\[//g' -e 's/\].*//g' > $F_PKG_NAMES
    sed -n '/App Sizes:/p' $DUMPSYS_DIR/dumpsys_diskstats.txt | sed -e 's/,/\n/g' -e 's/.*\[//g' -e 's/\].*//g' > $F_PKG_SIZE
    sed -n '/App Data Sizes:/p' $DUMPSYS_DIR/dumpsys_diskstats.txt | sed -e 's/,/\n/g' -e 's/.*\[//g' -e 's/\].*//g' > $F_DAT_SIZE
    sed -n '/Cache Sizes:/p' $DUMPSYS_DIR/dumpsys_diskstats.txt | sed -e 's/,/\n/g' -e 's/.*\[//g' -e 's/\].*//g' > $F_CACHE_SIZE

    # Printing package names and their sizes
    ttl_apps=$(wc -l < "$F_PKG_NAMES")
    count=1
    while [ $count -le $ttl_apps ]; do
        pkg=$(sed -n "${count}p" "$F_PKG_NAMES")
        pkg_size=$(sed -n "${count}p" "$F_PKG_SIZE")
        dat_size=$(sed -n "${count}p" "$F_DAT_SIZE")
        csh_size=$(sed -n "${count}p" "$F_CACHE_SIZE")
        echo -e "Package Name: $pkg" >> "$F_OUTPUT"
        echo -e "\t Package Size=$pkg_size bytes" >> $F_OUTPUT
        echo -e "\t Data Size=$dat_size bytes" >> $F_OUTPUT
        echo -e "\t Cache Size=$csh_size bytes" >> $F_OUTPUT
        echo -e "\t Total Size=$(($pkg_size + $dat_size + $csh_size)) bytes\n" >> $F_OUTPUT
    count=$(( $count + 1));
    done
    rm -f $F_PKG_NAMES $F_PKG_SIZE $F_DAT_SIZE $F_CACHE_SIZE

    # Extract appops for every package: https://android.stackexchange.com/questions/226282/how-can-i-see-which-applications-is-reading-the-clipboard

    mkdir -p "$DUMPSYS_DIR/appops"
    for pkg in $( $SHELL_CMD pm list packages | sed 's/package://' ); do
        echo "[*] appops get $pkg" && $SHELL_CMD appops get $pkg > $DUMPSYS_DIR/appops/appops_$pkg.txt
    done

    time_update
    echo -e "[+]\n[+] DUMPSYS acquisition completed at $NOW"
}

system () {
    set_path
    mkdir -p "${SYSTEM_DIR}/system"

    echo -e "\n[+] Extracting files from /system"

    $SHELL_CMD ls /system
    $PULL_CMD /system ${SYSTEM_DIR} > $SYSTEM_LOG_FILE

    time_update
    echo "[+] SYSTEM acquisition completed at $NOW"
}

apk () {
    set_path
    mkdir -p "$APK_DIR"
    SELECTED_FILE=${APK_DIR}/${ANDROID_ID}_apk_list.txt

    echo -e "\n[+] Extracting APK files\n[+]"
 	$SHELL_CMD pm list packages -f -u > $SELECTED_FILE

    while read -r line
    do
        line=${line#"package:"}
        target_file=${line%%".apk="*}".apk"

        IFS='/' read -ra tokens <<<"$target_file"
        apk_type=${tokens[1]}
        app_folder=${tokens[2]}
        app_path=${tokens[3]}
        apk_name=${tokens[4]}

        remote_path=${apk_type}/${app_folder}/${app_path}
        local_path=${APK_DIR}/${apk_type}/${app_folder}
        mkdir -p $local_path
        $PULL_CMD $remote_path $local_path || $PULL_CMD $target_file $local_path
    done < $SELECTED_FILE

    time_update
    echo -e "[+]\n[+] APK Acquisition completed at $NOW"
}

content_provider () {
    set_path
    mkdir -p "$CONTENTPROVIDER_DIR"
    touch /tmp/tempfile

    echo -e "\n[+] Extracting data by using CONTENT PROVIDERS\n[+]"
    ${SHELL_CMD} dumpsys package providers > ${CONTENTPROVIDER_DIR}/content_providers_list.txt

    echo "[*] QUERY CALENDAR CONTENT"
    calendar_array=(calendar_entities calendars attendees event_entities events properties reminders
                    calendar_alerts colors extendedproperties syncstate)
    for item in ${calendar_array[@]}; do
        echo "content://com.android.calendar/$item"
        ${SHELL_CMD} content query --uri content://com.android.calendar/$item > /tmp/tempfile && result=`cat /tmp/tempfile`
        if [[ "$result" != "No result found." && -n "$result" ]]; then
            item=`echo $item | tr "/" "_"`
            echo $result > ${CONTENTPROVIDER_DIR}/calendar_$item.txt
        fi
    done

    echo "[*] QUERY CONTACTS CONTENT"
    contacts_array=(raw_contacts directories syncstate contacts groups groups_summary aggregation_exceptions settings provider_status
                    photo_dimensions deleted_contacts raw_contact_entities status_updates stream_items_limit profile stream_items data
                    "profile/syncstate" "profile/raw_contacts" "profile/raw_contact_entities" "profile/as_vcard"
                    "data/phones" "data/postals" "data/phones/filter" "data/emails/lookup" "data/emails/filter")
    for item in ${contacts_array[@]}; do
        echo "content://com.android.contacts/$item"
        ${SHELL_CMD} content query --uri content://com.android.contacts/$item > /tmp/tempfile && result=`cat /tmp/tempfile`
        if [[ "$result" != "No result found." && -n "$result" ]]; then
            item=`echo $item | tr "/" "_"`
            echo $result > ${CONTENTPROVIDER_DIR}/contacts_$item.txt
        fi
    done

    echo "[*] QUERY DOWNLOADS CONTENT"
    downloads_array=(my_downloads download)
    for item in ${downloads_array[@]}; do
        echo "content://downloads/$item"
        ${SHELL_CMD} content query --uri content://downloads/$item > /tmp/tempfile && result=`cat /tmp/tempfile`
        if [[ "$result" != "No result found." && -n "$result" ]]; then
            item=`echo $item | tr "/" "_"`
            echo $result > ${CONTENTPROVIDER_DIR}/downloads_$item.txt
        fi
    done

    echo "[*] QUERY EXTERNAL MEDIA CONTENT"
    external_array=(file "images/media" "images/thumbnails" "audio/media" "audio/genres" "audio/playlists" "audio/artists"
                    "audio/albums" "video/media" "video/thumbnails")
    for item in ${external_array[@]}; do
        echo "content://media/external/$item"
        ${SHELL_CMD} content query --uri content://media/external/$item > /tmp/tempfile && result=`cat /tmp/tempfile`
        if [[ "$result" != "No result found." && -n "$result" ]]; then
            item=`echo $item | tr "/" "_"`
            echo $result > ${CONTENTPROVIDER_DIR}/media_external_$item.txt
        fi
    done

    echo "[*] QUERY INTERNAL MEDIA CONTENT"
    internal_array=(file "images/media" "images/thumbnails" "audio/media" "audio/genres" "audio/playlists" "audio/artists"
                    "audio/albums" "video/media" "video/thumbnails")
    for item in ${internal_array[@]}; do
        echo "content://media/internal/$item"
        ${SHELL_CMD} content query --uri content://media/internal/$item > /tmp/tempfile && result=`cat /tmp/tempfile`
        if [[ "$result" != "No result found." && -n "$result" ]]; then
            item=`echo $item | tr "/" "_"`
            echo $result > ${CONTENTPROVIDER_DIR}/media_internal_$item.txt
        fi
    done

    echo "[*] QUERY SETTINGS CONTENT"
    settings_array=(system secure global bookmarks "system/ringtone" "system/alarm_alert" "system/notification_sound" "system/bluetooth_devices" "system/powersavings_appsettings")
    for item in ${settings_array[@]}; do
        echo "content://settings/$item"
        ${SHELL_CMD} content query --uri content://settings/$item > /tmp/tempfile && result=`cat /tmp/tempfile`
        if [[ "$result" != "No result found." && -n "$result" ]]; then
            item=`echo $item | tr "/" "_"`
            echo $result > ${CONTENTPROVIDER_DIR}/settings_$item.txt
        fi
    done

    echo "content://com.google.settings/partner"
    ${SHELL_CMD} content query --uri content://com.google.settings/partner > ${CONTENTPROVIDER_DIR}/google_settings_partner.txt
    echo "content://nwkinfo/nwkinfo/carriers"
    ${SHELL_CMD} content query --uri content://nwkinfo/nwkinfo/carriers > ${CONTENTPROVIDER_DIR}/nwkinfo_carriers.txt
    echo "content://com.android.settings.personalvibration.PersonalVibrationProvider"
    ${SHELL_CMD} content query --uri content://com.android.settings.personalvibration.PersonalVibrationProvider > ${CONTENTPROVIDER_DIR}/personal_vibration.txt

    echo "[*] QUERY USER DICTIONARY CONTENT"
    echo "content://user_dictionary/words"
    ${SHELL_CMD} content query --uri content://user_dictionary/words > ${CONTENTPROVIDER_DIR}/user_dictionary_words.txt

    echo "[*] QUERY BROWSER CONTENT"
    browser_array=(bookmarks searches)
    for item in ${browser_array[@]}; do
        echo "content://browser/$item"
        ${SHELL_CMD} content query --uri content://browser/$item > /tmp/tempfile && result=`cat /tmp/tempfile`
        if [[ "$result" != "No result found." && -n "$result" ]]; then
            item=`echo $item | tr "/" "_"`
            echo $result > ${CONTENTPROVIDER_DIR}/browser_$item.txt
        fi
    done

    echo "[*] QUERY ANDROID BROWSER CONTENT"
    ${SHELL_CMD} content query --uri content://com.android.browser > ${CONTENTPROVIDER_DIR}/android_browser.txt
    android_browser_array=(accounts settings syncstate images image_mappings bookmarks history searches combined
                            "accounts/account_name" "accounts/account_type" "accounts/sourceid" "bookmarks/folder" "bookmarks/search_suggest_query")
    for item in ${android_browser_array[@]}; do
        echo "content://com.android.browser/$item"
        ${SHELL_CMD} content query --uri content://com.android.browser/$item > /tmp/tempfile && result=`cat /tmp/tempfile`
        if [[ "$result" != "No result found." && -n "$result" ]]; then
            item=`echo $item | tr "/" "_"`
            echo $result > ${CONTENTPROVIDER_DIR}/android_browser_$item.txt
        fi
    done

    rm /tmp/tempfile
    time_update
    echo -e "[+]\n[+] Content Provider Acquisition completed at $NOW"
}

databases () {
    echo -e "\n[+] Extracting databases\n[+]"
    set_path
    mkdir -p "${DATABASE_DIR}/db"

    $SHELL_CMD find / -name "*.db" 2>/dev/null > ${DATABASE_DIR}/database_file.txt

    while read line; do
        local_name=$(echo ${line:1} | tr "/" "_")
        $PULL_CMD $line ${DATABASE_DIR}/db/$local_name
    done < ${DATABASE_DIR}/database_file.txt

    time_update
    echo -e "[+]\n[+] Extracting databases completed at $NOW"
}

keys () {
    echo -e "\n[+] Extracting keys\n[+]"
    set_path
    mkdir -p "${KEYS_DIR}/keys"

    $PULL_CMD /system/etc/security ${KEYS_DIR}/security
    $SHELL_CMD find / -type f -name "*.csr" -o -name "*.pub" -o -name "*.prv" -o -name "*.pem" -o -name "*.key"
                    -o -name "*.pkcs12" -o -name "*.pfx" -o -name "*.p12" -o -name "*.der" -o -name "*.cert" \
                    -o -name "*.cer" -o -name "*.crt" -o -name "*.p7b" -o -name "*.p7c" -o -name "*.keystore" \
                    -o -name "*.crl" -o -name "*.bks" -o -name "*.jks" 2>/dev/null > ${KEYS_DIR}/keys_file.txt

    while read line; do
        local_name=$(echo ${line:1} | tr "/" "_")
        $PULL_CMD $line ${KEYS_DIR}/keys/$local_name
    done < ${KEYS_DIR}/keys_file.txt

    time_update
    echo -e "[+]\n[+] Extracting keys completed at $NOW"
}

conf_files () {
    echo -e "\n[+] Extracting configure files\n[+]"
    set_path
    mkdir -p "${CONF_DIR}/files"

    $SHELL_CMD find / -type f -name "*.conf" 2>/dev/null > ${CONF_DIR}/conf_files.txt

    while read line; do
        local_name=$(echo ${line:1} | tr "/" "_")
        $PULL_CMD $line ${CONF_DIR}/files/$local_name
    done < ${CONF_DIR}/conf_files.txt

    time_update
    echo -e "[+]\n[+] Extracting configure files completed at $NOW"
}

compressed () {
    echo -e "\n[+] Extracting compressed files\n[+]"
    set_path
    mkdir -p "${COMPRESSED_DIR}/files"
    $SHELL_CMD find / -type f -name "*.zip" -o -name "*.tar.gz" 2>/dev/null > ${COMPRESSED_DIR}/compressed_files.txt

    while read line; do
        local_name=$(echo ${line:1} | tr "/" "_")
        $PULL_CMD $line ${COMPRESSED_DIR}/files/$local_name
    done < ${COMPRESSED_DIR}/compressed_files.txt

    time_update
    echo -e "[+]\n[+] Extracting compressed files completed at $NOW"
}

bin_files () {
    echo -e "\n[+] Extracting bin files\n[+]"
    set_path
    mkdir -p "${BIN_DIR}/files"
    $SHELL_CMD find / -type f -name "*.bin" 2>/dev/null > ${BIN_DIR}/bin_files.txt

    while read line; do
        local_name=$(echo ${line:1} | tr "/" "_")
        $PULL_CMD $line ${BIN_DIR}/files/$local_name
    done < ${BIN_DIR}/bin_files.txt

    time_update
    echo -e "[+]\n[+] Extracting bin files completed at $NOW"
}

adb_backup () {
    set_path
    mkdir -p "$BACKUP_DIR"

    echo -e "\n[+] Creating an Android Backup by using the command\n[+]"
    echo "[*] adb backup -all -shared -system -keyvalue -apk -obb -f backup.ab"
    $BACKUP_CMD -all -shared -system -keyvalue -apk -obb -f $BACKUP_DIR/backup.ab

    echo "[*] SHA1: "
    shasum ${BACKUP_DIR}/backup.ab >&1 | tee -a $BACKUP_DIR/backup_log.txt

    time_update
    echo -e "[+]\n[+] ADB Backup completed at $NOW"
}

all () {
    info_collect
    live_commands
    package_manager_commands
    dumpsys
    system
    sdcard
    apk
    content_provider
    databases
    keys
    conf_files
    compressed
    bin_files
    #adb_backup
}

menu () {
    echo "******************* adb-extract.sh ********************
    1. Collect basic information, init and selinux
    2. Execute live commands
    3. Execute package manager commands
    4. Execute bugreport, dumpsys and appops
    5. Acquire /system folder
    6. Acquire /sdcard folder
    7. Extract APK files
    8. Extract data from content providers
    9. Extract databases, keys and configure files
    10. Extract compressed and bin files
    11. Acquire an ADB Backup
    12. Do all of the above"

    read -p "Choose an option: " choice
    case $choice in
        1)
            info_collect
            ;;
        2)
            live_commands
            ;;
        3)
            package_manager_commands
            ;;
        4)
            dumpsys
            ;;
        5)
            system
            ;;
        6)
            sdcard
            ;;
        7)
            apk
            ;;
        8)
            content_provider
            ;;
        9)
            databases
            keys
            conf_files
            ;;
        10)
            compressed
            bin_files
            ;;
        11)
            adb_backup
            ;;
        12)
            all
            ;;
    esac
}

### adb-extract main ###
check_tools
set_var
check_device
menu
