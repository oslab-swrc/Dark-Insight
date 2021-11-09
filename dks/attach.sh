#!/bin/bash
# SPDX-License-Identifier: MIT
THIS_SCRIPT_PATH=$(dirname ${BASH_SOURCE[0]})
PROJECT_ROOT_PATH=$(realpath $THIS_SCRIPT_PATH/../..)

function print_usage(){
 echo "Usage : attach.sh [-d] <pid>"
 echo "-d : for debug output"
}

if [ $# -lt 1 ]; then
 print_usage
 exit 1
fi
pid=$1

#check debug option enabled
DEBUG=""
if [ $1 == "-d" ]; then
 echo "DEBUG output enabled"
 DEBUG="--debug "

 if [ $# -lt 2 ]; then
   print_usage
   exit
 fi
 pid=$2
fi

sudo rmmod kdks
sudo rmmod pci_ring_buffer
sudo modprobe kdks debug=3 run_mode=1
sudo HOME=$HOME $THIS_SCRIPT_PATH/dks ${DEBUG} --spnf $PROJECT_ROOT_PATH/spin-finder/spnfind \
	--cmd profile -p $pid
sudo rmmod kdks
sudo rmmod pci_ring_buffer
