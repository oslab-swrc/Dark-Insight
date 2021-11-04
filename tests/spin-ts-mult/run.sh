#!/bin/bash

PROJ_ROOT=../../../
DKS=${PROJ_ROOT}/build/dks/dks
SPNF=${PROJ_ROOT}/spin-finder/spnfind

sudo rmmod kdks
sudo rmmod pci_ring_buffer
sudo modprobe kdks debug=7
sudo ${DKS} --spnf ${SPNF} --cmd profile tc --spin 2 --nthreads=128
sudo rmmod kdks
sudo rmmod pci_ring_buffer
