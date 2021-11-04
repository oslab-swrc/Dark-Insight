#!/bin/bash
THIS_SCRIPT_PATH=$(dirname ${BASH_SOURCE[0]})
PROJECT_ROOT_PATH=$(realpath $THIS_SCRIPT_PATH)

CK_SRC_PATH=$HOME/Projects/dark-insight-apps/ck/ck-0.6.0
CK_ROOT_PATH=$(realpath $CK_SRC_PATH/..)
CK_SPINLOCK=$CK_SRC_PATH/regressions/ck_spinlock/validate/ck_spinlock

THREADS=96

sudo rmmod kdks 2>/dev/null
sudo rmmod pci_ring_buffer 2>/dev/null

sudo insmod $PROJECT_ROOT_PATH/build/pci-ring-buffer/build_kernel/pci_ring_buffer.ko
# run_mode = { 1 = only spinlock, 2 = only mutex, 3 = all enabled
sudo insmod $PROJECT_ROOT_PATH/build/kdks/kdks.ko debug=0 run_mode=3

cleanup() {
  sudo chown $USER: dks_profile_ck_spinlock_$THREADS.data 2>/dev/null
  sudo chown $USER: dks_profile_ck_spinlock_$THREADS.data.old 2>/dev/null
}
trap cleanup EXIT

#clear first
sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
sudo bash -c "echo 1 > /proc/sys/vm/overcommit_memory"

echo "Thread count: $THREADS"
sudo HOME=$HOME $THIS_SCRIPT_PATH/build/dks/dks --spnf $THIS_SCRIPT_PATH/spin-finder/spnfind \
      --cmd profile --output dks_profile_ck_spinlock_$THREADS.data \
      $CK_SPINLOCK $THREADS 1;

echo "All done"
