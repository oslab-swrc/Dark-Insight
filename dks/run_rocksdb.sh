#!/bin/bash

#related to dks
THIS_SCRIPT_PATH=$(dirname ${BASH_SOURCE[0]})
PROJECT_ROOT_PATH=$(realpath $THIS_SCRIPT_PATH/../..)

#rocksdb
ROCKSDB_ROOT=/home/woonhak/workspace/dark-insight-apps/rocksdb/rocksdb-5.1.fb
ROCKSDB_DATA_PATH=$ROCKSDB_ROOT/rdb
DB_BENCH=$ROCKSDB_ROOT/db_bench
BENCH_TYPE="multireadrandom"

load_kdks_modules(){
    sudo rmmod kdks
    sudo rmmod pci_ring_buffer
#run_mode 2--> blocking sync-mutex/conditional variable
    sudo modprobe kdks debug=0 run_mode=2
}

unload_kdks_modules(){
    sudo rmmod kdks
    sudo rmmod pci_ring_buffer
}

run_bench(){
  for t in 1 2 4 8 16 32 64 ; 
  do 
    #clear first
    sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"

    echo "warm up 5min"
    sudo $DB_BENCH --batch_size=1 --db=${ROCKSDB_DATA_PATH} --use_existing_db=1 --num=100000000 \
              --benchmarks=readseq \
              --threads=1 ; 

    #load modules
    load_kdks_modules
	  echo "load kdks modules done"

    echo $t; 
    sudo HOME=$HOME $THIS_SCRIPT_PATH/dks --spnf $PROJECT_ROOT_PATH/spin-finder/spnfind \
              --cmd profile \
              $DB_BENCH --batch_size=1 --db=${ROCKSDB_DATA_PATH} --use_existing_db=1 --num=100000000 \
              --reads=$(( 50000 * $t * 8 )) \
              --duration=100 \
              --benchmarks=$BENCH_TYPE \
              --threads=$t >& $BENCH_TYPE.$t; 

    unload_kdks_modules
	  echo "unload kdks modules"
  done
}

run_bench

echo "all done"
