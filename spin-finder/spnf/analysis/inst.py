#!/usr/bin/env python3
"""
instruction definition
"""
from spnf.arch.arch import *
from enum import IntEnum
import logging
log = logging.getLogger(__name__)

class InstKind(IntEnum):
    fcall      = 0
    freturn    = 1
    ujump      = 2
    cjump      = 3
    simple_mov = 4
    other      = 5
    meta       = 6
    unknown    = 7

class InstInfo(IntEnum):
    itype      = 0    # instruction type
    rd_set     = 1    # read set
    wrt_set    = 2    # write set
    sub_insts  = 3    # sub_instructions

class RegInfo(IntEnum):
    cname      = 0    # canonical name of the register
    offset     = 1    # offset in bits
    size       = 2    # size in bits

class TargetKind(IntEnum):
    fixed_addr = 0
    stack_addr = 1
    unknown    = 2

class Inst(object):
    COMMENTS = set(["#", ";"])

    """Base class of all instructions"""
    def __init__(self, kind, arch, addr, info, prefix, op, rest):
        self.itype  = kind  # major type
        self.arch   = arch
        self.addr   = addr
        self._addr_str = None
        self.info   = info
        self.prefix = prefix
        self.op     = op
        self._opd   = None  # will be lazily evaluated
        self._rest  = rest  # rest of args including COMMENTS if any
        self._next_inst  = None     # next real/micro instruction
        self._next_real_inst = None # next real instruction
        self._rdset = None  # will be lazily evaluated
        self._wrtset = None  # will be lazily evaluated

    def __repr__(self):
        return "%s %s%s%s %s" % (
            self.addr_str,
            " ".join(self.prefix) if self.prefix else "",
            " " if self.prefix else "",
            self.op,
            " ".join(self._opd) if self._opd != None else " ".join(self._rest))

    @property
    def addr_str(self):
        """Address in string"""
        if self._addr_str == None:
            self._addr_str = self._code_addr_to_str(self.addr)
        return self._addr_str

    def is_terminator(self):
        """Test if this instruction is one of terminator instructions (e.g., jmp)"""
        TERMINATORS = {InstKind.cjump: True,
                       InstKind.ujump: True,
                       InstKind.freturn: True}
        return TERMINATORS.get(self.itype, False)

    def _init2_(self):
        """Fully initialize instruction"""
        # Tokenize further
        new_opd = []
        if self._rest:
            for tok in self._rest:
                (term, subtoks) = self._subtokenize(tok)
                new_opd.extend(subtoks)
                if term:
                    break
        self._opd = new_opd
        self._rest = None
        # Perform architecture dependent evaluation of an instruction
        self.arch.eval_inst(self)

    def set_next_inst(self, next_inst):
        """Set the next instruction"""
        self._next_inst = next_inst

    def _code_addr_to_str(self, addr):
        addr_list = ["%016x" % addr[0]]
        for sb_addr in addr[1:]:
            addr_list.append("%x" % sb_addr)
        str = "^".join(addr_list)
        return str

    @property
    def opd(self):
        """Evaluate rest and create operands"""
        if self._opd == None:
            self._init2_()
        return self._opd

    @property
    def next_addr(self):
        """Get the address of the next instruction"""
        return self._next_inst.addr if self._next_inst else None

    @property
    def next_real_addr(self):
        """Get the address of the next real instruction"""
        if self._next_real_inst == None:
            t_inst = self._next_inst
            while True:
                if t_inst == None or len(t_inst.addr) == 1:
                    break
                t_inst = t_inst._next_inst
            self._next_real_inst = t_inst
        return self._next_real_inst.addr

    @property
    def read_set(self):
        """Read set of this instruction"""
        # get cached one
        if self._rdset:
            return self._rdset
        # parse info
        self._rdset = set()
        if self.info:
            for rd in self.info[InstInfo.rd_set]:
                # resolve operand (e.g., #0, #1)
                if rd[0] == "#":
                    rd = self._resolve_opd(rd)
                self._rdset.add(rd)
        return self._rdset

    @property
    def write_set(self):
        """Write set of this instruction"""
        if self._wrtset:
            return self._wrtset
        # parse info
        self._wrtset = set()
        if self.info:
            # - write set
            for wrt in self.info[InstInfo.wrt_set]:
                # resolve operand (e.g., #0, #1)
                if wrt[0] == "#":
                    wrt = self._resolve_opd(wrt)
                self._wrtset.add(wrt)
        return self._wrtset

    def expand_reg_expr(self, expr):
        """Expand register expression"""
        return self.arch.expand_reg_expr(expr)

    def shrink_reg_expr(self, expr):
        """Shrink register expression"""
        return self.arch.shrink_reg_expr(expr)

    def _resolve_opd(self, opd_str):
        """Evaluate '#n' operand"""
        if opd_str[0] != "#":
            return None
        try:
            n_opd = int(opd_str[1:])
        except ValueError:
            return opd_str
        return self.opd[n_opd]

    def _subtokenize(self, tok):
        """Tokenize a token into subtokens"""
        # filter out COMMENTS
        if tok[0] in self.COMMENTS:
            return (True, [])
        # subtokenize a token
        (s, e, stoks) = (0, None, [])
        for (i, c) in enumerate(tok):
            # check a matching end marker
            if e:
                if e == c:
                    e = None
                continue
            # if it is an opening brace, find a matching one
            if c == "(":
                e = ")"
            # tokenize at ,
            if c == ",":
                stoks.append(tok[s:i])
                s = i + 1
        stoks.append(tok[s:])
        return (False, stoks)

class FCallInst(Inst):
    """FCall instruction"""
    def __init__(self, arch, addr, info, prefix, op, rest):
        super().__init__(InstKind.fcall, arch, addr, info, prefix, op, rest)
        # fully initialize to potentially specialize this for functions
        self._init2_()

class FReturnInst(Inst):
    """FReturn instruction"""
    def __init__(self, arch, addr, info, prefix, op, rest):
        super().__init__(InstKind.freturn, arch, addr, info, prefix, op, rest)
        self._target_addr = None

    @property
    def target_addr(self):
        """Get return target address"""
        if self._target_addr == None:
            self._target_addr = self.arch.freturn_target_addr(self)
        return self._target_addr

class UJumpInst(Inst):
    """Unconditional jump instruction"""
    def __init__(self, arch, addr, info, prefix, op, rest):
        super().__init__(InstKind.ujump, arch, addr, info, prefix, op, rest)
        self._target_addr = None

    @property
    def target_addr(self):
        """Get jump target address"""
        if self._target_addr == None:
            self._target_addr = self.arch.ujump_target_addr(self)
        return self._target_addr

class CJumpInst(Inst):
    """Conditional jump instruction"""
    def __init__(self, arch, addr, info, prefix, op, rest):
        super().__init__(InstKind.cjump, arch, addr, info, prefix, op, rest)
        self._target_addr = None

    @property
    def target_addr(self):
        """Get jump target address"""
        if self._target_addr == None:
            self._target_addr = self.arch.cjump_target_addr(self)
        return self._target_addr

class SimpleMoveInst(Inst):
    """Simple move instruction"""
    def __init__(self, arch, addr, info, prefix, op, rest):
        super().__init__(InstKind.simple_mov, arch, addr, info, prefix, op, rest)
        self._redefs = None

    @property
    def redef_list(self):
        """A list of redefinition tuples, [(old, new), ...]"""
        if self._redefs == None:
            self._redefs = self.arch.redef_list(self)
        return self._redefs

    @property
    def opd(self):
        """Evaluate rest and create operands"""
        # It is already evaluated
        if self._opd != None:
            return self._opd
        # Call super.opd
        opd = super().opd
        # Evaluating operands of simple move
        self.arch.eval_simple_mov_opd(self)
        return self._opd

class OtherInst(Inst):
    """Other instruction"""
    def __init__(self, arch, addr, info, prefix, op, rest):
        super().__init__(InstKind.other, arch, addr, info, prefix, op, rest)

class MetaInst(Inst):
    """Meta instruction"""
    def __init__(self, arch, addr, info, prefix, op, rest):
        super().__init__(InstKind.meta, arch, addr, info, prefix, op, rest)

    def sub_asm_lines(self):
        """Get sub-assembly lines"""
        # build up an operand list
        opdl = []
        for (i, opd) in enumerate(self.opd):
            opdl.append(("#%d" % i, opd))
        # yield sub-assembly lines
        addr_str = self.addr_str + "^"
        for asm_line in self.info[InstInfo.sub_insts]:
            asm_line = asm_line.replace("^", addr_str).replace("^ ", " ")
            for mopd, ropd in opdl:
                asm_line = asm_line.replace(mopd, ropd)
                # --0x60(%rax) -> 0x60(%rax)
                asm_line = asm_line.replace("--", "")
                # -$0x5 -> $-0x5
                asm_line = asm_line.replace("-$", "$")
            yield(asm_line)

class UnknownInst(Inst):
    """Unknown instruction"""
    def __init__(self, arch, addr, info, prefix, op, rest):
        super().__init__(InstKind.unknown, arch, addr, info, prefix, op, rest)
