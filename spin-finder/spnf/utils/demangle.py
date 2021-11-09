#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
demangling C++ names
"""
import sys
import os
import subprocess
import logging
log = logging.getLogger(__name__)

def demangle(func_names):
    """Demangle C++ function name"""
    # Check function names
    run_cppfilt = False
    func_names2 = []
    for func_name in func_names:
        # All mangled functions start with _Z
        # See https://en.wikipedia.org/wiki/Name_mangling
        if func_name.startswith("_Z"):
            run_cppfilt = True
        # 'eglCreateSync@@Base' -> 'eglCreateSync'
        # 'sched_yield@plt'     -> 'sched_yield'
        pos = func_name.find("@")
        if pos == -1:
            func_names2.append(func_name)
        else:
            func_names2.append(func_name[:pos])
    func_names = func_names2
    if not run_cppfilt:
        return func_names

    # Demangling using c++flit
    args = ['c++filt']
    args.extend(func_names)
    p = subprocess.Popen(args, close_fds=True, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, _ = p.communicate()

    # Parsing output of c++filt
    demangled_names = []
    for line in stdout.decode("utf-8").split("\n"):
        line = line.strip()
        if line:
            demangled_names.append(line)
    return demangled_names

if  __name__ == "__main__":
    names = demangle(sys.argv[1:])
    for name in names:
        print(name)
