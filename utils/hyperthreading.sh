#!/bin/bash

for i in $(seq 24 47)
do
   echo $1 > /sys/devices/system/cpu/cpu$i/online
done
