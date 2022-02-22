#!/usr/bin/python3

import sys
from pathlib import Path

print('******************* can-countid.py *******************')

try:
    can_file = Path(sys.argv[1]).absolute()
except IndexError:
    print('USAGE: python3 cantool.py <logfile>\n')
    exit(1)

with open(can_file, 'r') as f:
    lines = f.readlines()

can_dict = {}
count_dict = {}
for line in lines:
    line = line.split()
    can_info = {
        'timestamp': line[0],
        'dlc': line[5],
        'data': line[6:]
    }

    try:
        can_dict[line[2]].append(can_info)
        count_dict[line[2]] += 1
    except KeyError:
        can_dict[line[2]] = [can_info]
        count_dict[line[2]] = 1

sorted_list = sorted(count_dict.items(), key=lambda x:x[1], reverse=True)
for i in sorted_list:
    print(f'{i[0]}: {i[1]}')

while True:
    try:
        canid = input('\nplease input id: ')
    except KeyboardInterrupt:
        exit(1)

    for i in can_dict[canid]:
        data = ' '.join(i['data'])
        time = i['timestamp']
        print(f'{time}:\t{data}')
