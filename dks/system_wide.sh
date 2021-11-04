#!/bin/bash
THIS_SCRIPT_PATH=$(dirname ${BASH_SOURCE[0]})
PROJECT_ROOT_PATH=$(realpath $THIS_SCRIPT_PATH/../..)

function print_usage(){
 echo "Usage : system_wide.sh [-d]"
 echo "-d : for debug output"
}

if [ $# -gt 1 ]; then
 print_usage
 exit 1
fi

#check debug option enabled
DEBUG=""
if [ $1 == "-d" ]; then
 echo "DEBUG output enabled"
 DEBUG="--debug "

 if [ $# -gt 2 ]; then
   print_usage
   exit
 fi
fi

sudo rmmod kdks
sudo rmmod pci_ring_buffer
sudo modprobe kdks debug=0 run_mode=1
sudo HOME=$HOME $THIS_SCRIPT_PATH/dks ${DEBUG} --spnf $PROJECT_ROOT_PATH/spin-finder/spnfind \
	--cmd profile -a
sudo rmmod kdks
sudo rmmod pci_ring_buffer
