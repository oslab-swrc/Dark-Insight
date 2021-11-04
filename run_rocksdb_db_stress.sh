#!/bin/bash
THIS_SCRIPT_PATH=$(dirname ${BASH_SOURCE[0]})
PROJECT_ROOT_PATH=$(realpath $THIS_SCRIPT_PATH)
RAW_RESULT_FILENAME=raw_results.txt

ROCKSDB_SRC_PATH=/home/changseok/Projects/dark-insight-apps/rocksdb/rocksdb-5.1.fb

ROCKSDB_ROOT_PATH=$(realpath $ROCKSDB_SRC_PATH/..)
ROCKSDB_DATA_PATH=$ROCKSDB_ROOT_PATH/ramdisk/rdb
DB_STRESS=$ROCKSDB_SRC_PATH/db_stress

BENCH_TYPE="multireadrandom"
# Maximum of thread count is 4 due to the limitation of the number of HW counters.
THREADS=48

sudo rmmod kdks 2>/dev/null
sudo rmmod pci_ring_buffer 2>/dev/null

sudo insmod $PROJECT_ROOT_PATH/build/pci-ring-buffer/build_kernel/pci_ring_buffer.ko
# run_mode = { 1 = only spinlock, 2 = only mutex, 3 = all enabled
sudo insmod $PROJECT_ROOT_PATH/build/kdks/kdks.ko debug=0 run_mode=2

cleanup() {
  sudo chown $USER: dks_profile_rocksdb_db_stress_$THREADS.data 2>/dev/null
  sudo chown $USER: dks_profile_rocksdb_db_stress_$THREADS.data.old 2>/dev/null
}
trap cleanup EXIT

#clear first
sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
sudo bash -c "echo 1 > /proc/sys/vm/overcommit_memory"

echo "Thread count: $THREADS"
START=$(date +%s)
#sudo HOME=$HOME $THIS_SCRIPT_PATH/build/dks/dks --spnf $THIS_SCRIPT_PATH/spin-finder/spnfind \
#      --cmd profile --output dks_profile_rocksdb_db_stress_$THREADS.data \
#      $DB_STRESS \
#      --max_background_compactions=20 \
#      --use_merge=0 \
#      --max_write_buffer_number=3 \
#      --sync=0 \
#      --reopen=1 \
#      --write_buffer_size=4194304 \
#      --delpercent=5 \
#      --log2_keys_per_lock=10 \
#      --block_size=16384 \
#      --allow_concurrent_memtable_write=0 \
#      --target_file_size_multiplier=2 \
#      --max_bytes_for_level_base=10485760 \
#      --use_full_merge_v1=1 \
#      --progress_reports=0 \
#      --mmap_read=0 \
#      --writepercent=35 \
#      --disable_data_sync=0 \
#      --readpercent=45 \
#      --subcompactions=1 \
#      --memtablerep=prefix_hash \
#      --prefix_size=7 \
#      --test_batches_snapshots=1 \
#      --db=/tmp/rocksdb_crashtest_whitebox_dks \
#      --threads=$THREADS \
#      --disable_wal=0 \
#      --open_files=500000 \
#      --destroy_db_initially=0 \
#      --target_file_size_base=2097152 \
#      --nooverwritepercent=1 \
#      --iterpercent=10 \
#      --max_key=100000000 \
#      --prefixpercent=5 \
#      --ops_per_thread=100000 \
#      --use_clock_cache=false \
#      --cache_size=1048576 \
#      --compaction_style=1 \
#      --verify_checksum=1 &

for i in $(seq 1 $THREADS)
do
sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
sudo HOME=$HOME $DB_STRESS \
      --max_background_compactions=20 \
      --use_merge=0 \
      --max_write_buffer_number=3 \
      --sync=0 \
      --reopen=1 \
      --write_buffer_size=4194304 \
      --delpercent=5 \
      --log2_keys_per_lock=10 \
      --block_size=16384 \
      --allow_concurrent_memtable_write=0 \
      --target_file_size_multiplier=2 \
      --max_bytes_for_level_base=10485760 \
      --use_full_merge_v1=1 \
      --progress_reports=0 \
      --mmap_read=0 \
      --writepercent=35 \
      --disable_data_sync=0 \
      --readpercent=45 \
      --subcompactions=1 \
      --memtablerep=prefix_hash \
      --prefix_size=7 \
      --test_batches_snapshots=1 \
      --db=/tmp/rocksdb_crashtest_whitebox_dks \
      --threads=$i \
      --disable_wal=0 \
      --open_files=500000 \
      --destroy_db_initially=0 \
      --target_file_size_base=2097152 \
      --nooverwritepercent=1 \
      --iterpercent=10 \
      --max_key=100000000 \
      --prefixpercent=5 \
      --ops_per_thread=100000 \
      --use_clock_cache=false \
      --cache_size=1048576 \
      --compaction_style=1 \
      --verify_checksum=1 >> $RAW_RESULT_FILENAME &

DB_STRESS_PID=$(pgrep db_stress)
while [ -z $DB_STRESS_PID ]; do
    DB_STRESS_PID=$(pgrep db_stress)
done

#echo "db_stress pid: $DB_STRESS_PID"
python3 ./utils/cpu_usage.py $DB_STRESS_PID $RAW_RESULT_FILENAME &
CPU_UTIL=$!
#echo "cpu util: $CPU_UTIL"
wait $CPU_UTIL
END=$(date +%s)
echo -e "elabsed time: $(($END - $START)) seconds.\n" >> $RAW_RESULT_FILENAME
sleep 1
done

echo "All done"
