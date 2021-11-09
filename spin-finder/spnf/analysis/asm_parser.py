#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
assembly parser
: parsing assembly to create functions
"""
import os
import string
from spnf.arch.arch import *
from spnf.analysis.cfg import *
from spnf.analysis.loop import *
import logging
log = logging.getLogger(__name__)

_DEFAULT_ARCH_STR = "elf64-x86-64"

class AsmParser:
    def __init__(self, fd):
        self.fd = fd
        self.arch = create_arch(_DEFAULT_ARCH_STR)
        self.func = None

    def parse_func(self):
        prev_inst = None
        for line in self._get_asm_lines():
            (is_func, obj) = self._factory(line)
            # start of a new function
            if is_func:
                if self.func and len(self.func.insts) > 0:
                    yield self.func
                self.func = obj
                continue
            # instruction
            inst = obj
            if inst.itype == InstKind.meta:
                # meta instruction
                for sb_asm in inst.sub_asm_lines():
                    sb_line = sb_asm.split()
                    (_, sb_inst) = self._factory(sb_line)
                    self.func.append_inst(sb_inst)
                    if prev_inst:
                        prev_inst.set_next_inst(sb_inst)
                    prev_inst = sb_inst
            else:
                # non-meta instruction
                self.func.append_inst(inst)
                if prev_inst:
                    prev_inst.set_next_inst(inst)
                prev_inst = inst
        # yield the last function
        if self.func:
            yield self.func
            self.func = None

    @staticmethod
    def is_constant(tok):
        """Test if a tok is constant"""
        try:
            # $0x64
            if tok[0] == "$":
                return True
            # 0x64 -> 64
            if tok[:2] == "0x":
                tok = tok[2:]
            # is 64 hex?
            int(tok, 16)
            return True
        except:
            return False

    @staticmethod
    def is_thread_local_memory(arch, tok):
        """Test if a tok is a register"""
        # memory:   %fs:0x333 or %fs:(...)
        for tl_reg in arch.thread_local_regs:
            tl_reg_str = tl_reg + ":"
            if tok.startswith(tl_reg_str):
                rest = tok[len(tl_reg_str):]
                return rest[0] == "(" or AsmParser._is_hex(rest)
        return False

    @staticmethod
    def is_segmented_memory(tok):
        """Test if a tok is a register"""
        # memory:   %fs:0x333 or %fs:(...)
        try:
            if tok[0] == "%":
                reg_end = tok.find(":")
                if reg_end != -1 and tok[1:reg_end].isalnum():
                    return tok[reg_end+1] == "(" or AsmParser._is_hex(tok[reg_end+1:])
                return False
        except:
                return False

    @staticmethod
    def is_register(tok):
        """Test if a tok is a register"""
        try:
            # register: %eax
            # memory:   %fs:0x333 or %fs:(...)
            if tok[0] == "%":
                return not AsmParser.is_segmented_memory(tok)
            return False
        except:
            return False

    @staticmethod
    def is_memory(tok):
        """Test if a tok is memory"""
        # memory;   (a, b, c, d)
        if tok.find("(") != -1 and tok.find(")") != -1:
            return True
        # memory:   %fs:0x333 or %fs:(...)
        return AsmParser.is_segmented_memory(tok)

    @staticmethod
    def _is_hex(s):
        """Test if a string is hexadecimal or not"""
        if s[-1] == ":":
            s = s[:-1]
        if s[:2] == "0x":
            s = s[2:]
        return all(c in string.hexdigits for c in s)

    def _factory(self, toks):
        """Create a function or an instruction from a list of tokens"""
        if self._is_func(toks):
            return (True, Func(self.arch, toks))
        elif self.arch:
            return (False, self.arch.create_inst(toks))

    def _get_asm_lines(self):
        """Get an assembly line"""
        for line in self.fd:
            toks = line.split()
            # skip an empty or comment line
            if not toks or toks[0][0] == "#" or toks[0][0] == ";":
                continue
            # a regular assembly line
            if Arch.is_code_addr(toks[0]):
                yield toks
            # otherwise, seek description on architecture
            if not self.arch:
                arch_str = self._get_arch_str(toks)
                if not self.arch and arch_str:
                    self.arch = create_arch(arch_str)
                    if not self.arch:
                        raise Exception("Unknown architecture")

    def _is_func(self, toks):
        """Test if a string is a function entry or not"""
        return toks[0][-1] != ":" and len(toks) == 2

    def _get_arch_str(self, toks):
        try:
            if toks[-3] == "file" and toks[-2] == "format":
                return toks[-1]
        except IndexError:
            return None
