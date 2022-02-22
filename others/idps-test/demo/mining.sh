#!/system/bin/sh

endless_loop()
{
    echo -ne "i=0
    while true
    do
    i=i+100
    i=100
    done" | /system/bin/sh &
}

if [ $# != 1 ]; then
    echo "USAGE: $0 <cpus>"
    echo "cpus:" $(cat /proc/cpuinfo | grep processor | wc -l)
    exit 1;
fi

while true
do
    sleep 1
    for i in `seq $1`; do
        sleep 1
        endless_loop
        pid_array[$i]=$!;
    done

    echo "\e[1;31m正在挖矿... ${pid_array[@]} \e[0m"
    break
done
