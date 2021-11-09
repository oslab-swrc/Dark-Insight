#!/bin/bash
# SPDX-License-Identifier: MIT

ROOT=$(realpath $(dirname "$0"))
BUILD=$ROOT/build

TARGET=${1:-$BUILD/tests/spin-ts-ping-pong/tc}
TARGET=$(realpath $TARGET)

sudo rmmod kdks 2>/dev/null
sudo rmmod pci_ring_buffer 2>/dev/null

sudo insmod $BUILD/pci-ring-buffer/build_kernel/pci_ring_buffer.ko
sudo insmod $BUILD/kdks/kdks.ko debug=3

cleanup() {
  sudo chown $USER: dks_profile.data
  sudo chown $USER: dks_profile.data.old
}
trap cleanup EXIT

sudo -E $BUILD/dks/dks --debug \
     --spnf $ROOT/spin-finder/spnfind \
     --cmd profile $TARGET \
     --nthreads 4

