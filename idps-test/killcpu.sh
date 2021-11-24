#!/bin/bash

endless_loop()
{
    echo -ne "i=0
    while true
    do
    i=i+100
    i=100
    done" | /bin/bash &
}

if [ $# != 1 ]; then
    echo "USAGE: $0 <cpus>"
    echo "cpus:" $(cat /proc/cpuinfo | grep processor | wc -l)
    exit 1;
fi

for i in `seq $1`; do
    endless_loop
    pid_array[$i]=$!;
done

echo 'kill' ${pid_array[@]} ';';
