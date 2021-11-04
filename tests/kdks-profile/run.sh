#!/bin/bash

BASEDIR=/lib/modules/`uname -r`/extra

sudo rmmod kdks
sudo rmmod pci_ring_buffer
sudo modprobe kdks debug=4095
sudo gdb ./tc -ex run
sudo rmmod kdks
sudo rmmod pci_ring_buffer
