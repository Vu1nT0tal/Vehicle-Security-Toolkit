#!/system/bin/sh

echo -e "[VSOC] VSOC已启动"

sleep 1
while true
do
    if [ -f "result.txt" ]; then
        echo "\e[1;31m[VSOC] 检测到IVI系统存在异常扫描 \e[0m"
        rm result.txt
        break
    fi
done


sleep 1
while true
do
    if [ -f "/system/xbin/sh" ]; then
        echo "\e[1;31m[VSOC] 检测到IVI系统被ROOT \e[0m"
        #rm /system/xbin/sh
        break
    fi
done

flag="0"
while true
do
    sleep 1
    top -b -n 1 -o pid,%cpu | head -n 11 | tail -n 6 > cpu.txt
    
    while read line; do
        pid=$(echo $line | cut -d " " -f 1)
        cpu=$(echo $line | cut -d " " -f 2 | cut -d "." -f 1)
        #cmd=$(echo $line | cut -d " " -f 3)
        #echo $pid $cpu $cmd
        if [ $((cpu)) -gt 90 ]; then
            #echo $line
            if [ $flag = "0" ]; then
                echo -e "\e[1;31m[VSOC] 检测到IVI系统资源占用异常激增 \e[0m"
                flag="1"
            fi
            echo -e "\e[1;31m[VSOC] 正在处理异常... \e[0m"
            sleep 5
            kill $pid
            echo -e "\e[1;31m[VSOC] 异常处理完成 $pid\e[0m"
            #echo "----------------------------------------------"
            #break
        fi
    done < cpu.txt
    #echo > cpu.txt
done
