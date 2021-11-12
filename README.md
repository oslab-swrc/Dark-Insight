# Dark Insight

Dark Insight is a tool to profile the idle state of the system to search the scalability bottleneck. Profiling involves the kernel and user applications, has minimal overhead and does not require source code modifications.

We developed kernel modules (KDKS) and a user library (DKS). All developed files are provided under the terms of MIT license, and some Linux header files are imported.

# Envorinment

* Linux 4.13.9
* Required packages
  + Fedora
    - elfutils-devel binutils-devel libunwind-devel ncurses-devel graphviz libbsd-devel sqlite-devel kernel-devel json-c-devel
  + Ubuntu
   -
    - Corresponding packages to those of fedora.

# How to build and install

* In the project root, trigger make. And then sudo make install after building.
* You can selectively build a sub-module in each relevant directory under src.

# How to profile

* To run dark-insight, two kernel modules (pci_ring_buffer.ko and kdks.ko)
  should be installed ahead.
* When installing the kernel module, we can give two options: debug and run_mode.
  The debug controls how fine debug messages are printed out via linux tracing
  infrastructure (scale: 0-3). And run_mode controls what synchronization primitive
  dark-insight profiles. (1: spin only, 2: futex only, 3: all). For detailed info,
  you can check kdks/kdks_i.h
* Once the kernel modules are install, we can start profiling with following command
  `$ ./build/dks/dks --spnf ./spin-finder/spnfind --cmd profile [TARGET_APP] [TARGET_APP_OPTIONS]`
  See run.sh in the project root directory.
* Stop profiling whenever you want with ctrl + c.

# How to analyze

* Dark insight exports a data file in the project root. It is usually dks_profile.data
* To see the result in the console, load the file by using a following command
  `./build/dks/dks --cmd analyze ./dks_profile.data`. Or you can simply use analyze.sh
  in the project root.
* To see the result in firefox, we need to export the data into json format. Append
  -e (or --export) option after the analyze command. The json file will be exported in
  ./build/vis/dks_profile.json. You can check the file with `firefox ./external-lib/vis/dks.html`

# Trouble shooting

* When dark-insight shows nothing about callchain.
  + `# echo 1 > /proc/sys/vm/overcommit_memory`
  + Due to overcommit memory restriction implemented in fork() of glibc,
    popen() can fail because of huge memory usage of the parents.
  + https://stackoverflow.com/questions/46574798/enomem-from-popen-for-system-while-there-is-enough-memory

* When browser shows nothing about callchain because of CORS policy.
  + Run other web server ( ex. python -m http.server ) 
  + Edit dks.html
        LoadJSON("dks_profile.json" .... ) -> LoadJSON("http://localhost:8000/dks_profile.json" ....) 
