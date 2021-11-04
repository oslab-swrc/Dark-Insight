#!/bin/bash
THIS_SCRIPT_PATH=$(dirname ${BASH_SOURCE[0]})
PROJECT_ROOT_PATH=$(realpath $THIS_SCRIPT_PATH/../..)

sudo rmmod kdks
sudo rmmod pci_ring_buffer
sudo modprobe kdks debug=1
sudo HOME=$HOME $THIS_SCRIPT_PATH/dks --debug --spnf $PROJECT_ROOT_PATH/spin-finder/spnfind \
	--cmd profile $PROJECT_ROOT_PATH/build/tests/spin-ts-ping-pong/tc --nthreads 4
sudo rmmod kdks
sudo rmmod pci_ring_buffer
