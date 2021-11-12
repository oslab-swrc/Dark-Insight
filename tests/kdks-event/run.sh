#!/bin/bash

BASEDIR=/lib/modules/`uname -r`/extra

sudo rmmod kdks
sudo rmmod pci_ring_buffer
sudo insmod ${BASEDIR}/pci_ring_buffer.ko
sudo insmod ${BASEDIR}/kdks.ko
#sudo modprobe kdks debug=4095
sudo gdb ./tc -ex run
sudo rmmod kdks
sudo rmmod pci_ring_buffer
