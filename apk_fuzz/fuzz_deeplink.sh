#!/bin/bash

android_app_package_name=$(cat AndroidManifest.xml | grep -o "package=.*" | cut -d'"' -f 2)
deeplink_scheme_array[0]=$(cat AndroidManifest.xml | grep -o "android:scheme=.*" | cut -d'"' -f 2)
deeplink_host_array[0]=$(cat AndroidManifest.xml | grep -o "android:host=.*" | cut -d'"' -f 2)
deeplink_pathPattern_array[0]=$(cat AndroidManifest.xml | grep -o "android:pathPattern=.*" | cut -d'"' -f 2)
exported_activities_enum[0]=$(cat AndroidManifest.xml | grep -Ei 'exported="true"' | grep -o "android:name=.*" | cut -d'"' -f 2)
# filter_exported_activities=$(echo $exported_activities_enum | grep -o "android:name=.*" | cut -d'"' -f 2 )
exported_content_providers_enum[0]=$(cat AndroidManifest.xml | grep -o "android:authorities=.*" | cut -d'"' -f 2)

exported_activity_commands () {
    for i in "${exported_activities_enum[@]}";
    do
        for pleasework in $i;
        do
            fuzz_string=$(echo "💩" | radamsa)
            exported_activity_command="adb shell \"am start -n $android_app_package_name/$pleasework -e test '$fuzz_string'\""
            echo $exported_activity_command
            adb shell "am start -n $android_app_package_name/$pleasework -e test '$fuzz_string'"
        done
    done
}

deeplink_fuzz_function () {
for (( ; ; ))
do
    HTTPS="https"
    fuzz_string=$(echo "💩" | radamsa)
    for i in "${deeplink_scheme_array[@]//$HTTPS/}";
    do
        for pleasework in $i;
        do
            adb shell "am start -W -a android.intent.action.VIEW -d '$pleasework://$fuzz_string'"
            echo $fuzz_string
        done
    done
done
}

if [ $1 = "activities" ]
    then
    exported_activity_commands
fi

if [ $1 = "deeplinks" ]
    then
    deeplink_fuzz_function
fi
