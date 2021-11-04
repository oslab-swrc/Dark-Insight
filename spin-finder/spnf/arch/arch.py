#!/usr/bin/env python3
"""
architecture definition
"""
import string
from spnf.analysis.inst import *
import spnf.arch.arch_x86_64 as x86_64

import logging
log = logging.getLogger(__name__)

class Arch(object):
    """Base class of all machine architectures"""
    def __init__(self, s, prefix_set, inst_info, inst_vopd_set,
                 reg_info, ip_regs, thread_local_regs,
                 status_flag_regs, reg_rename_tbl):
        self.arch_str = s
        self.prefix_set = prefix_set
        self.inst_info = inst_info
        self.inst_vopd_set = inst_vopd_set
        self.reg_info = reg_info
        self.ip_regs = ip_regs
        self.thread_local_regs = thread_local_regs
        self.status_flag_regs = status_flag_regs
        self.reg_rename_tbl = reg_rename_tbl
        self.reg_info_reverse = self._create_reverse_reg_info(reg_info)

    def _create_reverse_reg_info(self, reg_info):
        """Create a reverse register information from reg_info"""
        reg_info_reverse = {}
        for (reg, creg) in reg_info.items():
            reg_info_reverse[creg] = reg
        return reg_info_reverse

    def create_inst(self, toks):
        """Create an instruction from a tokenized line of assembly"""
        addr = Arch.parse_code_addr(toks[0])
        (info, ty, prefix, op, rest) = self._tokenize_asm_line(toks[1:])
        inst = self._cnstr(ty)(self, addr, info, prefix, op, rest)
        # for an unknown instruction, retry after evaluating its opd
        if ty == InstKind.unknown and inst.opd:
            ty = inst.itype
            info = inst.info
            op = inst.op
            inst = self._cnstr(ty)(self, addr, info, prefix, op, rest)
        return inst

    def _tokenize_asm_line(self, toks):
        """Tokenize an assembly line into prefix, op, and rest"""
        prefix = []
        for (i, tok) in enumerate(toks):
            if tok in self.prefix_set:
                prefix.append(tok)
            else:
                toks = toks[i:]
                break
        op   = toks[0]
        rest = toks[1:]
        info = self.inst_info.get(op, None)
        ty   = info[InstInfo.itype] if info else InstKind.unknown
        return (info, ty, prefix, op, rest)

    @staticmethod
    def parse_code_addr(s):
        """Test if a string is code address or not"""
        # TODO: refactor to utility class?
        # 1234, 0x1234, 0x1234:, 0x1234^0, 0x1234^0:
        if s[-1] == ":":
            s = s[:-1]
        addr_list = []
        for sb_str in s.split("^"):
            if sb_str[:2] == "0x":
                sb_str = sb_str[2:]
            addr_list.append(int(sb_str, 16))
        return tuple(addr_list)

    @staticmethod
    def is_code_addr(s):
        """Test if a string is code address or not"""
        # TODO: refactor to utility class?
        if s[-1] == ":":
            s = s[:-1]
        for sb_str in s.split("^"):
            if s[:2] == "0x":
                s = s[2:]
            if not all(c in string.hexdigits for c in s):
                return False
        return True

    @staticmethod
    def code_addr_to_str(addr):
        # TODO: refactor to utility class?
        addr_list = ["%016x" % addr[0]]
        for sb_addr in addr[1:]:
            addr_list.append("%x" % sb_addr)
        return "^".join(addr_list)

    @staticmethod
    def add_code_addr(x, y):
        """Add two code addresses"""
        # TODO: refactor to utility class?
        new_list = []
        for sb_x, sb_y in zip(x, y):
            new_list.append(sb_x + sb_y)
        return tuple(new_list)

    def _cnstr(self, ty):
        """Get constructor of an instruction for the specified type"""
        type_dict = {InstKind.fcall: FCallInst,
                     InstKind.freturn: FReturnInst,
                     InstKind.ujump: UJumpInst,
                     InstKind.cjump: CJumpInst,
                     InstKind.simple_mov: SimpleMoveInst,
                     InstKind.other: OtherInst,
                     InstKind.meta: MetaInst,
        }
        return type_dict.get(ty, UnknownInst)

    def freturn_target_addr(self, inst):
        """Get freturn target"""
        return [(TargetKind.stack_addr, None)]

    def ujump_target_addr(self, inst):
        """Get possible ujump targets"""
        # jump target address
        try:
            kind = TargetKind.fixed_addr
            addr = Arch.parse_code_addr(inst.opd[0])
        except ValueError:
            kind = TargetKind.unknown
            addr = None
        return [(kind, addr)]

    def cjump_target_addr(self, inst):
        """Get possible cjump targets"""
        # jump target address
        ka_list = self.ujump_target_addr(inst)
        # fall through address of conditional jump
        if inst.itype == InstKind.cjump:
            if inst.next_addr:
                ka = (TargetKind.fixed_addr, inst.next_addr)
            else:
                # TODO: Need to consider following cases
                # Compiler can generate code such that
                # two functions share one body for optimization
                ka = (TargetKind.unknown, None)
            ka_list.append(ka)
        return ka_list

    def redef_list(self, smov_inst):
        """Get redefinition tuples for a simple-move instruction"""
        # Evaluate opdrands first
        self.eval_simple_mov_opd(smov_inst)
        # Then, get a redef list
        src, tgt = smov_inst.opd[0], smov_inst.opd[1]
        return [(src, tgt)]

    def eval_simple_mov_opd(self, smov_inst):
        """
        Architecture specific evaluation of operands
        of simple_mov instructions
        """
        pass

    def eval_inst(self, inst):
        """Architecture specific evaluation of instructions"""
        self.eval_inst_specialize_fcall(inst)
        self.eval_inst_instantiate_opd(inst)
        self.eval_inst_variable_opd(inst)

    def eval_inst_specialize_fcall(self, inst):
        """Specializing fcall to specific functions"""
        if inst.itype == InstKind.fcall:
            if len(inst._opd) > 1:
                # get a target function name
                func_name = inst._opd[1]
                inst._opd = inst._opd[:1]
                if func_name[0] == "<":
                    # '<sched_yield@plt>' --> 'sched_yield@plt'
                    func_name = func_name[1:-1]
                sp_op = "".join([inst.op, "#", func_name])
                # try to specialize
                sp_inst_info = self.inst_info.get(sp_op, None)
                if sp_inst_info:
                    inst.op = sp_op
                    inst.info = sp_inst_info

    def eval_inst_instantiate_opd(self, inst):
        """Instantiate inst.opd"""
        new_opd = []
        for opd in inst._opd:
            # normalize a register name if there is conflict
            if opd.find("%") != -1:
                for (o_reg, re_reg) in self.reg_rename_tbl.items():
                    opd = opd.replace(o_reg, re_reg)
            # instantiate %rip
            for ip in self.ip_regs:
                if opd.find(ip) != -1:
                    unlinked_ip = "0x0(" + ip + ")"
                    if opd.find(unlinked_ip) != -1:
                        opd = "" # unlinked -> unknown
                    else:
                        opd = self._instantiate_ip_opd(inst, ip, opd)
                    break
            # normalize addressing expr: (%rsp) -> 0x(%rsp)
            if opd[0] == "(":
                opd = "0x0" + opd
            new_opd.append(opd)
        inst._opd = new_opd

    def eval_inst_variable_opd(self, inst):
        """Instructions with variable operands"""
        if not inst.info:
            for inst_vopd in self.inst_vopd_set:
                if inst.op.startswith(inst_vopd):
                    inst.op = "".join([inst_vopd, str(len(inst.opd)), inst.op[len(inst_vopd):]])
                    inst.info = self.inst_info.get(inst.op, None)
                    inst.itype = inst.info[InstInfo.itype] if inst.info else InstKind.unknown
                    break

    def _instantiate_ip_opd(self, inst, ip, opd):
        """Instantiate IP in operand"""
        # A next instruction is not bound yet
        if not inst.next_addr:
            return opd
        next_addr_str = Arch.code_addr_to_str(inst.next_real_addr)
        opd = opd.replace(ip, next_addr_str)
        # Test if evaluating an address is possible
        if opd.find("(") == -1 or opd.find("%") != -1:
            return opd
        # GAS: displacement(base register, offset register, multiplier)
        # --> *(base register + (offset register * multiplier) + displacement)
        try:
            org_opd = opd
            opd = opd[:-1] if opd[-1] == ")" else opd
            _displacement_rest = opd.split("(")
            displacement = int(_displacement_rest[0], 16)
            _br_or_mul = [int(x.strip(), 16) for x in _displacement_rest[1].split(",")]
            if len(_br_or_mul) == 3:
                base_register = _br_or_mul[0]
                offset_register = _br_or_mul[1]
                multiplier = _br_or_mul[2]
            elif len(_br_or_mul) == 2:
                base_register = _br_or_mul[0]
                offset_register = _br_or_mul[1]
                multiplier = 1
            elif len(_br_or_mul) == 1:
                base_register = _br_or_mul[0]
                offset_register = 0
                multiplier = 1
            else:
                raise ValueError
            new_addr = base_register + (offset_register * multiplier) + displacement
            return "(" + str(hex(new_addr)) + ")"
        except ValueError:
            return org_opd

    def expand_reg_expr(self, expr):
        """Expand register expressions"""
        # find a register
        s = expr.find("%")
        if s == -1:
            return expr
        pre_str = expr[:s]
        expr = expr[s:]
        # get a register name
        regname = None
        for (i, char) in enumerate(expr[1:]):
            if not char.isalnum():
                regname = expr[:i+1]
                expr = expr[i+1:]
                break
        if regname == None:
            regname = expr
            expr = None
        # expand the register name
        cregname = self.reg_info.get(regname, regname)
        str_list = [pre_str, cregname]
        if expr:
            post_str = self.expand_reg_expr(expr)
            str_list.append(post_str)
        return "".join(str_list)

    def shrink_reg_expr(self, expr):
        """shrink register expressions"""
        # is it expanded?
        e = expr.find("[")
        if e == -1:
            return expr
        # find a register
        s = expr.rfind("%", 0, e)
        if s == -1:
            return expr
        pre_str = expr[:s]
        expr = expr[s:]
        # get a register name
        range_chars = {"[", ":", "]"}
        regname = None
        for (i, char) in enumerate(expr[1:]):
            if not char.isalnum() and not char in range_chars:
                regname = expr[:i+1]
                expr = expr[i+1:]
                break
        if regname == None:
            regname = expr
            expr = None
        # expand the register name
        dregname = self.reg_info_reverse.get(regname, regname)
        str_list = [pre_str, dregname]
        if expr:
            post_str = self.shrink_reg_expr(expr)
            str_list.append(post_str)
        return "".join(str_list)

class Arch_x86_64(Arch):
    """Intel x86-64 architecture definition"""
    def __init__(self):
        super().__init__(x86_64.ARCH_STR,  x86_64.PREFIX_SET,
                         x86_64.INST_INFO, x86_64.INST_VOPD_SET,
                         x86_64.REG_INFO,  x86_64.IP_REGS,
                         x86_64.THREAD_LOCAL_REGS, x86_64.STATUS_FLAG_REGS,
                         x86_64.REG_RENAME_TBL)

    def _pc_rel_target_addr(self, inst):
        """Get possible PC-relative targets"""
        # pc-relative jump target address
        try:
            kind = TargetKind.fixed_addr
            opd_addr = Arch.parse_code_addr(inst.opd[0])
            addr = Arch.add_code_addr(inst.addr, opd_addr)
        except ValueError:
            kind = TargetKind.unknown
            addr = None
        ka_list = [(kind, addr)]
        # fall through address of conditional jump
        if inst.itype == InstKind.cjump:
            if inst.next_addr:
                ka = (TargetKind.fixed_addr, inst.next_addr)
            else:
                # TODO: Need to consider following cases
                # Compiler can generate code such that
                # two functions share one body for optimization
                ka = (TargetKind.unknown, None)
            ka_list.append(ka)
        return ka_list

    def cjump_target_addr(self, inst):
        """Get possible cjump targets for x86"""
        if inst.op[0:4] == "loop" or inst.op[0:6] == "xbegin":
            return self._pc_rel_target_addr(inst)
        return super().cjump_target_addr(inst)

    def ujump_target_addr(self, inst):
        """Get possible ujump targets"""
        if inst.op[0:6] == "xabort":
            return [(TargetKind.unknown, None)]
        return super().ujump_target_addr(inst)

    def redef_list(self, inst):
        """Get redefinition tuples for a simple-move instruction"""
        if inst.op.startswith("set"):
            set_list = []
            read_set = inst.read_set
            write_set = inst.write_set
            for rd in read_set:
                for wrt in write_set:
                    set_list.append((rd, wrt))
            return set_list
        if inst.op.startswith("xchg"):
            src, tgt = inst.opd[0], inst.opd[1]
            return [(src, tgt), (tgt, src)]
        if inst.op.startswith("cmpxchg"):
            src, tgt = inst.opd[0], inst.opd[1]
            cmpxchg_list = [(src, tgt)]
            suffix = inst.op[7:]
            if suffix == '':
                cmpxchg_list.extend([(tgt, "%al"), (tgt, "%ax"),
                                     (tgt, "%eax"), (tgt, "%rax")])
                return cmpxchg_list
            if suffix == 'b':
                cmpxchg_list.append((tgt, "%al"))
                return cmpxchg_list
            if suffix == 'w':
                cmpxchg_list.append((tgt, "%ax"))
                return cmpxchg_list
            if suffix == 'l':
                cmpxchg_list.append((tgt, "%eax"))
                return cmpxchg_list
            if suffix == 'q':
                cmpxchg_list.append((tgt, "%rax"))
                return cmpxchg_list
        return super().redef_list(inst)

    def eval_simple_mov_opd(self, inst):
        """
        Architecture specific evaluation of operands
        of simple_mov instructions
        """
        if inst.op.startswith("lea"):
            # lea 0x8(%rax) %rax -> lea 0x8<%rax> %rax
            src = inst.opd[0]
            inst.opd[0] = src.replace("(", "<").replace(")",">")
        super().eval_simple_mov_opd(inst)

def create_arch(arch_str):
    """A factory method of architecture classes"""
    if arch_str == "elf64-x86-64" or arch_str == "elf32-i386":
        return Arch_x86_64()
    else:
        # Unsupported architecture
        return None
