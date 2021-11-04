#!/bin/bash
THIS_SCRIPT_PATH=$(dirname ${BASH_SOURCE[0]})
PROJECT_ROOT_PATH=$(realpath $THIS_SCRIPT_PATH)

PARSEC_ROOT_PATH=$HOME/Projects/dark-insight-apps/parsec
PARSEC_SRC_PATH=$HOME/Projects/dark-insight-apps/parsec/parsec-3.0
FERRET_BIN=$PARSEC_SRC_PATH/pkgs/apps/ferret/inst/amd64-linux.gcc/bin/ferret

THREADS=15

sudo rmmod kdks 2>/dev/null
sudo rmmod pci_ring_buffer 2>/dev/null

sudo insmod $PROJECT_ROOT_PATH/build/pci-ring-buffer/build_kernel/pci_ring_buffer.ko
# run_mode = { 1 = only spinlock, 2 = only mutex, 3 = all enabled
sudo insmod $PROJECT_ROOT_PATH/build/kdks/kdks.ko debug=0 run_mode=3

cleanup() {
    sudo chown $USER: dks_profile_parsec_ferret_$THREADS.data 2>/dev/null
    sudo chown $USER: dks_profile_parsec_ferret_$THREADS.data.old 2>/dev/null
}
trap cleanup EXIT

#clear first
sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
sudo bash -c "echo 1 > /proc/sys/vm/overcommit_memory"

echo "Thread count: $THREADS"
START=$(date +%s)
# ferret <database> <table> <query dir> <top K> <depth> <n> <out>
sudo HOME=$HOME $THIS_SCRIPT_PATH/build/dks/dks --spnf $THIS_SCRIPT_PATH/spin-finder/spnfind \
    --cmd profile \
    $FERRET_BIN $PARSEC_SRC_PATH/pkgs/apps/ferret/run/corel \
    lsh \
    $PARSEC_SRC_PATH/pkgs/apps/ferret/run/queries \
    50 20 $THREADS \
    parsec_ferret_output.txt &

# For linux perf
#sudo HOME=$HOME $FERRET_BIN $PARSEC_SRC_PATH/pkgs/apps/ferret/run/corel \
#    lsh \
#    $PARSEC_SRC_PATH/pkgs/apps/ferret/run/queries \
#    50 20 $THREADS \
#    parsec_ferret_output.txt &

FERRET_PID=$(pgrep ferret)
while [ -z $FERRET_PID ]; do
    FERRET_PID=$(pgrep ferret)
done

echo "ferret pid: $FERRET_PID"
python3 ./utils/cpu_usage.py $FERRET_PID &
CPU_UTIL=$!
echo "cpu util: $CPU_UTIL"
wait $CPU_UTIL
END=$(date +%s)
echo "elabsed time: $(($END - $START)) seconds."

echo "All done"
