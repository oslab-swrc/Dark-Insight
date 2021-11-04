#!/bin/bash
THIS_SCRIPT_PATH=$(dirname ${BASH_SOURCE[0]})
PROJECT_ROOT_PATH=$(realpath $THIS_SCRIPT_PATH)

ROCKSDB_SRC_PATH=/home/changseok/Projects/dark-insight-apps/rocksdb/rocksdb-5.1.fb

ROCKSDB_ROOT_PATH=$(realpath $ROCKSDB_SRC_PATH/..)
ROCKSDB_DATA_PATH=$ROCKSDB_ROOT_PATH/ramdisk/rdb
DB_BENCH=$ROCKSDB_SRC_PATH/db_bench

BENCH_TYPE="multireadrandom"
# Maximum of thread count is 4 due to the limitation of the number of HW counters.
THREADS=96

sudo rmmod kdks 2>/dev/null
sudo rmmod pci_ring_buffer 2>/dev/null

sudo insmod $PROJECT_ROOT_PATH/build/pci-ring-buffer/build_kernel/pci_ring_buffer.ko
# run_mode = { 1 = only spinlock, 2 = only mutex, 3 = all enabled
sudo insmod $PROJECT_ROOT_PATH/build/kdks/kdks.ko debug=0 run_mode=2

cleanup() {
  sudo chown $USER: dks_profile_rocksdb_$THREADS.data 2>/dev/null
  sudo chown $USER: dks_profile_rocksdb_$THREADS.data.old 2>/dev/null
}
trap cleanup EXIT

#clear first
sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
sudo bash -c "echo 1 > /proc/sys/vm/overcommit_memory"

echo "Warm up 5min"
sudo $DB_BENCH --batch_size=1 \
      --db=${ROCKSDB_DATA_PATH} \
      --use_existing_db=1 --num=100000 \
      --benchmarks=readseq \
      --threads=1;

echo "Thread count: $THREADS"
sudo HOME=$HOME $THIS_SCRIPT_PATH/build/dks/dks --spnf $THIS_SCRIPT_PATH/spin-finder/spnfind \
      --cmd profile --output dks_profile_rocksdb_$THREADS.data \
      $DB_BENCH --batch_size=1 \
      --db=${ROCKSDB_DATA_PATH} \
      --use_existing_db=1 \
      --num=100000000 \
      --reads=$(( 50000 * $THREADS * 8 )) \
      --duration=100 \
      --benchmarks=$BENCH_TYPE \
      --threads=$THREADS;

echo "All done"
