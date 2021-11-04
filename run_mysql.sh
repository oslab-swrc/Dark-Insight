#!/bin/bash
THIS_SCRIPT_PATH=$(dirname ${BASH_SOURCE[0]})
PROJECT_ROOT_PATH=$(realpath $THIS_SCRIPT_PATH)

MYSQL_ROOT_PATH=$HOME/Projects/dark-insight-apps/mysql-5.6
MYSQLD=$MYSQL_ROOT_PATH/mysql/bin/mysqld
MYSQLADMIN=$MYSQL_ROOT_PATH/mysql/bin/mysqladmin

THREADS=96

sudo rmmod kdks 2>/dev/null
sudo rmmod pci_ring_buffer 2>/dev/null

sudo insmod $PROJECT_ROOT_PATH/build/pci-ring-buffer/build_kernel/pci_ring_buffer.ko
# run_mode = { 1 = only spinlock, 2 = only mutex, 3 = all enabled
sudo insmod $PROJECT_ROOT_PATH/build/kdks/kdks.ko debug=0 run_mode=3

cleanup() {
    sudo chown $USER: dks_profile_mysql_sysbench_$THREADS.data 2>/dev/null
    sudo chown $USER: dks_profile_mysql_sysbench_$THREADS.data.old 2>/dev/null
    sudo $MYSQLADMIN --defaults-file=$MYSQL_ROOT_PATH/my.cnf \
	-uroot \
	-S $MYSQL_ROOT_PATH/ramdisk/mysql-data/mysql.sock \
	shutdown;
}
trap cleanup EXIT

#clear first
sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
sudo bash -c "echo 1 > /proc/sys/vm/overcommit_memory"

echo "Thread count: $THREADS"
sudo HOME=$HOME $THIS_SCRIPT_PATH/build/dks/dks --spnf $THIS_SCRIPT_PATH/spin-finder/spnfind \
    --cmd profile --output dks_profile_mysql_sysbench_$THREADS.data \
    $MYSQLD --defaults-file=$MYSQL_ROOT_PATH/my.cnf \
    --basedir=$MYSQL_ROOT_PATH/mysql/ \
    --datadir=$MYSQL_ROOT_PATH/ramdisk/mysql-data \
    --plugin-dir=$MYSQL_ROOT_PATH/mysql/lib/plugin \
    --log-error=$MYSQL_ROOT_PATH/ramdisk/mysql-data/mysql_error.log \
    --pid-file=$MYSQL_ROOT_PATH/ramdisk/mysql-data/mysql.pid \
    --socket=mysql.sock \
    --port=3308;

echo "All done"
