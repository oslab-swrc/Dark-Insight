#!/bin/bash
THIS_SCRIPT_PATH=$(dirname ${BASH_SOURCE[0]})
PROJECT_ROOT_PATH=$(realpath $THIS_SCRIPT_PATH)

RAMCLOUD_PATH=$HOME/Projects/dark-insight-apps/ramcloud

sudo rmmod kdks 2>/dev/null
sudo rmmod pci_ring_buffer 2>/dev/null

sudo insmod $PROJECT_ROOT_PATH/build/pci-ring-buffer/build_kernel/pci_ring_buffer.ko
sudo insmod $PROJECT_ROOT_PATH/build/kdks/kdks.ko debug=0 run_mode=1

cleanup() {
  sudo chown $USER: dks_profile_ramcloud.data
  sudo chown $USER: dks_profile_ramcloud.data.old
}
trap cleanup EXIT

#clear first
sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
sudo bash -c "echo 1 > /proc/sys/vm/overcommit_memory"

sudo HOME=$HOME $PROJECT_ROOT_PATH/build/dks/dks --spnf $PROJECT_ROOT_PATH/spin-finder/spnfind \
	--cmd profile --output dks_profile_ramcloud.data \
	$RAMCLOUD_PATH/Root/bin/server \
	-C tcp:host=mixmaster.gtisc.gatech.edu,port=11100 -L tcp:host=mixmaster,port=1101 \
	--clusterName=__unnamed__ -f $RAMCLOUD_PATH/DB --segmentFrames 11000 \
	--maxNonVolatileBuffers 20 --detectFailures 0 --timeout 10000 -r 2 -t 1450 \
	-E 3 -x zk:mixmaster:2181 -w 1 --maxCores 4 --logCleanerThreads 2 \
	--cleanerBalancer=tombstoneRatio:0.40 --allowLocalBackup \
	--logFile $RAMCLOUD_PATH/ramcloud-ycsb/logs/server-mixmaster.log

# For linux perf.
#sudo HOME=$HOME $RAMCLOUD_PATH/Root/bin/server \
#	-C tcp:host=mixmaster.gtisc.gatech.edu,port=11100 -L tcp:host=mixmaster,port=1101 \
#	--clusterName=__unnamed__ -f $RAMCLOUD_PATH/DB --segmentFrames 11000 \
#	--maxNonVolatileBuffers 20 --detectFailures 0 --timeout 10000 -r 2 -t 1450 \
#	-E 3 -x zk:mixmaster:2181 -w 1 --maxCores 4 --logCleanerThreads 2 \
#	--cleanerBalancer=tombstoneRatio:0.40 --allowLocalBackup \
#	--logFile $RAMCLOUD_PATH/ramcloud-ycsb/logs/server-mixmaster.log

echo "All done"
