#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
recursive ldd (shared object dependencies)
"""
import sys
import os
import subprocess
import logging
log = logging.getLogger(__name__)

def ldd(bin_file):
    """Run ldd for a bin_file"""
    dep_list = []
    p = subprocess.Popen("ldd %s" % bin_file, shell=True, close_fds=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    for l in p.stdout.readlines():
        line = l.decode("utf-8").strip()
        for tok in line.split():
            if tok[0] == "/":
                path = os.path.realpath(tok)
                dep_list.append(path)
    return dep_list

def _rldd(bin_file, dep_set):
    """Recursive ldd for a bin file"""
    bin_file = os.path.realpath(bin_file)
    if bin_file not in dep_set:
        dep_set.add(bin_file)
        for dep_file in ldd(bin_file):
            _rldd(dep_file, dep_set)

def rldd(bin_file):
    """Recursive ldd for a bin file"""
    dep_set = set()
    _rldd(bin_file, dep_set)
    return dep_set

def readelf_header(bin_file):
    """Read elf header and return dictionary"""
    p = subprocess.Popen("readelf -h %s" % bin_file, shell=True, close_fds=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    attr_map = {}
    for l in p.stdout.readlines():
        line = l.decode("utf-8").strip()
        toks = line.split(":")
        if len(toks) is not 2:
            continue
        key = toks[0].strip()
        val = toks[1].strip()
        attr_map[key] = val
    return attr_map
