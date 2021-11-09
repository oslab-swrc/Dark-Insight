#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Utility functions for disassemble
"""
import os
import sys
import platform
import errno
import tempfile
import argparse
import logging
log = logging.getLogger(__name__)

CUR_DIR = os.path.abspath(os.path.dirname(__file__))

def disassemble_bin(bin_fname, asm_fname):
    """Disassemble a binary file"""
    cmd = "objdump -d --no-show-raw-insn"
    return os.system("%s %s > %s" % (cmd, bin_fname, asm_fname))

def disassemble_kernel(asm_fname):
    """Disassemble the current running kernel image"""
    # load kernel symbol map
    sm_fname = get_kernel_system_map()
    if not sm_fname:
        return -errno.ENOENT
    addr_func_map = load_kernel_func_map(sm_fname)
    # get a kernel image
    k_fname, compressed = get_kernel_image()
    if not k_fname:
        return -errno.ENOENT
    # decompress if it is compressed
    if compressed:
        tmpfile = get_tmpfile_name()
        ret = decompress_vmlinuz(k_fname, tmpfile)
        if ret:
            os.unlink(tmpfile)
            return ret
        k_fname = tmpfile
    # disassemble vmlinux
    asm_tmpfile = get_tmpfile_name()
    ret = disassemble_bin(k_fname, asm_tmpfile)
    if compressed:
        os.unlink(k_fname)
    # merge function entires into the disassembled file
    put_func_entries(asm_fname, asm_tmpfile, addr_func_map)
    os.unlink(asm_tmpfile)
    return ret

def get_kernel_image():
    """Get the path name of current running kernel image"""
    # vmlinux
    k_fname = "/boot/vmlinux-%s" % platform.release()
    if os.path.isfile(k_fname):
        return k_fname, False
    # vmlinuz
    k_fname = "/boot/vmlinuz-%s" % platform.release()
    if os.path.isfile(k_fname):
        return k_fname, True
    # no kernel image
    return None, False

def get_kernel_system_map():
    """Get the path name of current running kernel image"""
    # vmlinux
    sm_fname = "/boot/System.map-%s" % platform.release()
    if os.path.isfile(sm_fname):
        return sm_fname
    return None

def load_kernel_func_map(sm_fname):
    """Load kernel system map"""
    with open(sm_fname) as fd:
        addr_func_map = {}
        for line in fd:
            toks = line.split()
            sym_type = toks[1]
            if sym_type != "T" and sym_type != "t":
                continue
            addr = toks[0]
            func = toks[2]
            addr_func_map[addr + ":"] = func
        return addr_func_map

def put_func_entries(out_asm_fname, in_asm_fname, addr_func_map):
    """put function entires into the assembly file"""
    with open(in_asm_fname) as in_fd:
        with open(out_asm_fname, "w") as out_fd:
            for line in in_fd:
                toks = line.split()
                if len(toks) > 0:
                    addr = toks[0]
                    func = addr_func_map.get(addr, None)
                    if func:
                        out_fd.write("\n%s <%s>:\n" % (addr[:-1], func))
                out_fd.write(line)

def decompress_vmlinuz(vmlinuz_fname, vmlinux_fname):
    """Extract a vmlinuz file"""
    cmd = os.path.join(CUR_DIR, "extract-vmlinux")
    return os.system("%s %s > %s" % (cmd, vmlinuz_fname, vmlinux_fname))

def get_tmpfile_name():
    """Get a new temporary file name"""
    tmp_dir = tempfile._get_default_tempdir()
    tmp_file = next(tempfile._get_candidate_names())
    return os.path.join(tmp_dir, tmp_file)

def main():
    # arg parser
    parser = argparse.ArgumentParser()
    parser.add_argument('--kernel', '-k', action='store_true', default=False,
                        help="current running kernel binary")
    parser.add_argument('--binfile', '-b', default=None, help="binary file")
    parser.add_argument('--asmfile', '-a', default=None, help="assembly file")

    # parse args
    args = parser.parse_args()
    if not args.asmfile or (args.kernel == False and args.binfile == None):
        parser.print_help()
        exit(1)

    # disassemble
    if args.kernel:
        disassemble_kernel(args.asmfile)
    else:
        disassemble_bin(args.binfile, args.asmfile)

if  __name__ == "__main__":
    main()
