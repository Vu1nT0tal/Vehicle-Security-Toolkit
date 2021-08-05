#!/bin/bash

echo "*************** top-activity.sh ***************"

adb shell dumpsys window | grep mCurrentFocus
