#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
analsys of assembly
"""
from spnf.arch.arch import *
from spnf.utils.graph import *
from spnf.utils.demangle import *
from spnf.analysis.inst import *
import logging
log = logging.getLogger(__name__)

class Func(object):
    """Function class for analysis"""
    def __init__(self, arch, toks):
        """ Create a Func object from an assembly line"""
        self.arch = arch
        self.name = toks[1][1:-2] # <function_name>:
        if self.name[-2:] == "()":
            self.name = self.name[:-2] # <function_name()>:
        self._demangled_name = None
        self.saddr = Arch.parse_code_addr(toks[0]) # start address
        self.eaddr = self.saddr # end address
        self.insts = [] # stream of instructions
        self._inst_dict = {} # {addr:list_idx, ...}
        self._ip = None # current IP
        self._num_inst = None

    def __repr__(self):
        str_list = [str(self)]
        for inst in self.insts:
            str_list.append(str(inst))
        str_list.append("")
        return "\n".join(str_list)

    def __str__(self):
        return "%s[%s,%s]" % (self.name,
                              Arch.code_addr_to_str(self.saddr),
                              Arch.code_addr_to_str(self.eaddr))

    @property
    def demangled_name(self):
        """Demangled function name"""
        if not self._demangled_name:
            self._demangled_name = demangle([self.name])[0]
        return self._demangled_name

    @property
    def num_inst(self):
        """Number of instructions"""
        if not self._num_inst:
            self._num_inst = len(self.insts)
        return self._num_inst

    def append_inst(self, inst):
        """Append an instruction to this function"""
        self.eaddr = inst.addr
        if self._ip:
            self._ip.ninst = inst
        self._inst_dict[inst.addr] = len(self.insts)
        self.insts.append(inst)
        self._ip = inst

    def _get_insts_idx(self, addr):
        """Get an index in the instruction list for the specified address"""
        return self._inst_dict.get(addr, -1)

    def _get_inst(self, addr):
        """Get an instruction of the specified address"""
        idx = self._get_insts_idx(addr)
        return self.insts[idx] if idx >=0 else None

    def _is_valid_inst_addr(self, addr):
        """Test if it is a valid instruction address"""
        if not addr or addr[0] < self.saddr[0] or self.eaddr[0] < addr[0]:
            return False
        try:
            _ = self._inst_dict[addr]
        except KeyError:
            # TODO: Is it incorrect results of objdump?
            # There are such cases that jump targets are
            # in the middle of an instruction
            # (e.g., lock cmpxchg ...)
            return False
        return True

class CFG(Graph):
    """Control flow graph of a function"""
    def __init__(self, func):
        super().__init__()
        self.func = func   # associated function
        self._start_bb = None

    def __str__(self):
        str_list = []
        for bb in sorted(self.vertex_dict.values()):
            str_list.append(str(bb))
        return "\n".join(str_list)

    def __repr__(self):
        repr_list = []
        for bb in sorted(self.vertex_dict.values()):
            repr_list.append(repr(bb))
        return "\n".join(repr_list)

    @property
    def start_bb(self):
        """Start basic block of CFG"""
        if not self._start_bb:
            self._start_bb = self.vertex_dict[self.func.saddr]
        return self._start_bb

    def reconstruct(self):
        """Reconstruct a control flow graph from assembly of a function"""
        self._create_basic_blocks()
        self._link_basic_blocks()
        self._clean_up_nop_basic_blocks()

    def _create_basic_blocks(self):
        """Create basic blocks"""
        bb_entries = self._find_start_bb_entries()
        for entry in bb_entries:
            inst = self.func._get_inst(entry)
            if inst:
                self.vertex_dict[inst.addr] = BasicBlock(self, inst)

    def _link_basic_blocks(self):
        """Link control flow of basic blocks"""
        # for each basic block
        for source_bb in self.vertex_dict.values():
            # create ins and out links while appending instructions
            s = self.func._get_insts_idx(source_bb.saddr)
            if s < 0:
                continue
            for inst in self.func.insts[s:]:
                # Append an instruction
                source_bb._append_inst(inst)
                # This instruction is a branch
                if inst.is_terminator():
                    taddrs = inst.target_addr
                    for (kind, addr) in taddrs:
                        if self._is_valid_target_addr(kind, addr):
                            target_bb = self.vertex_dict[addr]
                            source_bb.add_edge(target_bb)
                        else:
                            source_bb.has_unknown_target = True
                    break
                # Next instruction is an entry of another basic block
                elif self._end_of_bb(inst):
                    addr = inst.next_addr
                    target_bb = self.vertex_dict[addr]
                    source_bb.add_edge(target_bb)
                    break

    def _clean_up_nop_basic_blocks(self):
        """Clean up unnecessary nop basic blocks"""
        nop_addr_bb = []
        for (addr, bb) in self.vertex_dict.items():
            # among starting basic blocks
            if addr != self.func.saddr and not bb.ins:
                # find basick blocks having only one instruction, which is 'nop'
                if len(bb.insts) == 1 and bb.insts[0].op.startswith("nop"):
                    nop_addr_bb.append((addr, bb))
        for addr, bb in nop_addr_bb:
            # remove 'bb' from its successors' ins
            for succ in bb.outs:
                succ.ins.remove(bb)
            # remove 'bb' from the CFG
            del self.vertex_dict[addr]

    def _find_start_bb_entries(self):
        """Find known all jump targets in ascending order"""
        # add the first instruction
        bb_entries = [self.func.insts[0].addr]
        # sweep following instructions
        for inst in self.func.insts:
            # get target addresses for return or jump
            if inst.is_terminator():
                # jump target is a start of BB
                taddrs = inst.target_addr
                for (kind, addr) in taddrs:
                    if self._is_valid_target_addr(kind, addr):
                        bb_entries.append(addr)
                # the next of jump is a start of BB
                next_addr = inst.next_addr
                if self.func._is_valid_inst_addr(next_addr):
                    bb_entries.append(next_addr)
        # sort and remove duplicates
        return sorted(set(bb_entries))

    def _end_of_bb(self, i):
        """Test if this instruction is the end of basic block or not"""
        return self.vertex_dict.get(i.next_addr, None)

    def _is_valid_target_addr(self, kind, addr):
        """Test if it is a valid target address"""
        if kind != TargetKind.fixed_addr:
            return False
        return self.func._is_valid_inst_addr(addr)

class BasicBlock(Vertex):
    """Basic block class for analysis"""
    def __init__(self, cfg, inst):
        super().__init__()
        self.cfg   = cfg
        self.saddr = inst.addr
        self.eaddr = inst.addr
        self.insts = [inst]
        self.has_unknown_target = False
        self._unlikely = None
        self._likely = None
        self.__make_recursive_def_defunct = False
        self.__constant_folding = False

    def __lt__(self, other):
        return self.saddr[0] < other.saddr[0]

    def __repr__(self):
        # BB name
        str_list = [str(self)]
        # ins
        if self.ins:
            str_list.append(" INS:")
            for ibb in self.ins:
                str_list.append("  " + str(ibb))
        # outs
        if self.outs:
            str_list.append(" OUTS:")
            for obb in self.outs:
                str_list.append("  " + str(obb))
        # INSTS
        str_list.append(" INSTS:")
        for inst in self.insts:
            str_list.append("  " + str(inst))
        str_list.append("")
        str_list.append("")
        return "\n".join(str_list)

    def __str__(self):
        return "BB[%s,%s]" % (Arch.code_addr_to_str(self.saddr),
                              Arch.code_addr_to_str(self.eaddr))

    def repr_html(self):
        """Write a label for graphviz"""
        str_list = []
        str_list.append('<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">')
        for inst in self.insts:
            inst_str = repr(inst).replace("<", "# ").replace(">", " #")
            str_list.append('<TR><TD ALIGN="LEFT"> %s </TD></TR>' % inst_str.replace("&", "&amp;"))
        str_list.append('</TABLE>>')
        return '\n'.join(str_list)

    @property
    def likely(self):
        """Likely to execute"""
        if self._likely == None:
            prefix_list = self.insts[-1].prefix
            if len(prefix_list) == 0:
                self._likely = False
                return False
            if prefix_list[-1].find(".likely") == -1:
                self._likely = False
                return False
            prefix_list = self.insts[0].prefix
            if len(prefix_list) == 0:
                self._likely = False
                return False
            if prefix_list[-1].find(".likely") == -1:
                self._likely = False
                return False
            self._likely = True
        return self._likely

    @property
    def unlikely(self):
        """Unlikely to execute"""
        if self._unlikely == None:
            prefix_list = self.insts[-1].prefix
            if len(prefix_list) == 0:
                self._unlikely = False
                return False
            if prefix_list[-1].find(".unlikely") == -1:
                self._unlikely = False
                return False
            prefix_list = self.insts[0].prefix
            if len(prefix_list) == 0:
                self._unlikely = False
                return False
            if prefix_list[-1].find(".unlikely") == -1:
                self._unlikely = False
                return False
            self._unlikely = True
        return self._unlikely

    @property
    def addr_range(self):
        # (start address, end address, next of end address)
        return (self.saddr, self.eaddr, self.insts[-1].next_addr)

    def _append_inst(self, inst):
        """Append an instruction to this basic block"""
        if inst.addr != self.eaddr:
            self.eaddr = inst.addr
            self.insts.append(inst)

    def make_recursive_def_defunct(self):
        """Make a recursive definition defunct"""
        if self.__make_recursive_def_defunct:
            return
        self.__make_recursive_def_defunct = True

        for inst in self.insts:
            # mov (%rdx), %rdx --> mov #ur, %rdx
            if inst.itype == InstKind.simple_mov and \
               len(inst.opd) > 1:
                src, tgt = inst.opd[0], inst.opd[1]
                if src != tgt and src.find(tgt) != -1:
                    inst.opd[0] = "#ur"

    def constant_folding(self):
        """
        Simple constant folding
        -  mov -0x88(%rbp)      %rax
           lea   0x8<%rax>      %rax
        -> mov 0x8<-0x88(%rbp)> %rax
        """
        if self.__constant_folding:
            return
        self.__constant_folding = True

        del_insts = []
        prev_inst = self.insts[0]
        for inst in self.insts[1:]:
            if prev_inst.itype != InstKind.simple_mov or \
               inst.itype != InstKind.simple_mov:
                prev_inst = inst
                continue
            if not prev_inst.op.startswith("mov") or \
               not inst.op.startswith("lea"):
                prev_inst = inst
                continue
            if prev_inst.opd[1] != inst.opd[1]:
                prev_inst = inst
                continue
            const_str = inst.opd[0].replace("<" + inst.opd[1] + ">", "")
            # rewrite the first operand of 'mov'
            prev_inst.opd[0] = const_str + "<" + prev_inst.opd[0] + ">"
            # add 'lea' to the delete list
            del_insts.append(inst)
        # delete folded instructions
        for inst in del_insts:
            self.insts.remove(inst)
