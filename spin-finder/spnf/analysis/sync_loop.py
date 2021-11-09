#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
loop analysis
"""
from spnf.utils.graph import *
from spnf.analysis.asm_parser import *
from spnf.analysis.cfg import *
from spnf.analysis.loop import *
import logging
log = logging.getLogger(__name__)

class SyncLoopInfo(object):
    """Sync Loop information"""
    def __init__(self, loop, loop_id):
        self.loop = loop             # loop
        self.loop_id = loop_id       # loop_id
        if len(loop.backedges) == 1:
            # non-combined loop
            # a header and a backedge are dominated by the header
            backedges = [ x for x in iter(loop.backedges) ]
            hd_dom_insts = set(loop.header.insts + backedges[0].insts)
        else:
            # multiple backedges for a compinbed loop
            # only a header is dominated by itself
            hd_dom_insts = set(loop.header.insts)
        self.loop_hd_dom_insts = hd_dom_insts
        self.arch = loop.header.insts[0].arch
        self.is_sync_loop = False    # is it a synchronization loop?
        self.var_dict = LoopVariables() # loop variable dictionary
        self.bbs = loop.bbs          # all basic blocks
        self.xbb_infos = []          # exit basic blocks
        self.rd_wrt_list = []
        self.c_r_wrt_set = set()     # write set in a canonical form, which is recursively defined
        self._wrt_set = None
        self._rd_set = None
        self._rd_wrt_set = None
        self._addr_ranges = None

    def __repr__(self):
        str_list = [self.loop.__repr__()]
        str_list.append("FUNC_NAME: " + str(self.func_name))
        str_list.append("DEMANGLED_FUNC_NAME: " + str(self.demangled_func_name))
        str_list.append("LOOP_ID: " + self.loop_id)
        str_list.append("SYNC_LOOP: " + str(self.is_sync_loop) +
                        " " + str(self.loop.num_bb) +
                        " " + str(self.loop.num_inst))
        str_list.append("EXIT_BLOCKS:")
        for xbb_info in sorted(self.xbb_infos):
            xbb = xbb_info.bb
            str_list.append("  " + str(xbb))
        str_list.append("RD_WRT_LIST: " + str(self.rd_wrt_list))
        str_list.append("C_R_WRT_SET: " + str(self.c_r_wrt_set))
        str_list.append("WRT_SET: " + str(self.wrt_set))
        str_list.append("LOOP_VARS: " + str(sorted(self.loop_vars)))
        str_list.append("SYNC_VARS: " + str(sorted(self.sync_vars)))

        return "\n".join(str_list)

    def __str__(self):
        # format
        # function_name, start_addr, end_addr, expr1, expr2, ... # demangled name
        # -------------              --------
        #   \                         \
        #    +-- optional              +-- inclusive
        func_name = self.func_name
        demangled_func_name = " # %s" % self.demangled_func_name
        ranges_str_list = []
        for addr_range in self.addr_ranges:
            saddr = "0x%x" % addr_range[0]
            eaddr = "0x%x" % addr_range[1]
            str_list = [func_name, saddr, eaddr]
            str_list.extend(sorted(self.sync_vars))
            ranges_str_list.append(",".join(str_list) + demangled_func_name)
        return "\n".join(ranges_str_list)

    def _revert_encoded_reg_name(self, vdef):
        """Revert encoded register names back"""
        if vdef.find("%") != -1:
            for (o_reg, re_reg) in self.arch.reg_rename_tbl.items():
                vdef = vdef.replace(re_reg, o_reg)
        return vdef

    @property
    def loop_vars(self):
        return self.var_dict.loop_vars

    @property
    def sync_vars(self):
        sync_var_names = set()
        for vdef in self.var_dict.sync_vars:
            vdef = self._revert_encoded_reg_name(vdef)
            sync_var_names.add(vdef.replace("$", "")) # $0x30<0x1(0x0(%rdi))> -> 0x30<0x1(0x0(%rdi))>
        return sync_var_names

    @property
    def variant_vars(self):
        return self.var_dict.variant_vars

    @property
    def addr_ranges(self):
        if self._addr_ranges != None:
            return self._addr_ranges

        _ranges = list(map(lambda bb: list(bb.addr_range), self.bbs))
        _ranges = sorted(_ranges, key=lambda x: x[0])
        c = _ranges[0]
        ranges = []
        for r in _ranges[1:]:
            if c[2] == r[0]:
                c[1], c[2] = r[1], r[2]
            else:
                ranges.append(c)
                c = r
        ranges.append(c)
        self._addr_ranges = ranges
        return self._addr_ranges

    @property
    def func_name(self):
        return self.loop.header.cfg.func.name

    @property
    def demangled_func_name(self):
        return self.loop.header.cfg.func.demangled_name

    @property
    def wrt_set(self):
        if self._wrt_set == None:
            if self.rd_wrt_list:
                self._wrt_set  = set(list(zip(*self.rd_wrt_list))[1])
                self._wrt_set -= set([""]) # ignore unknown
            else:
                self._wrt_set  = set()
        return self._wrt_set

    @property
    def rd_set(self):
        if self._rd_set == None:
            if self.rd_wrt_list:
                self._rd_set  = set(list(zip(*self.rd_wrt_list))[0])
                self._rd_set -= set([""]) # ignore unknown
            else:
                self._rd_set  = set()
        return self._rd_set

    @property
    def rd_wrt_set(self):
        if self._rd_wrt_set == None:
            self._rd_wrt_set = self.rd_set | self.wrt_set
        return self._rd_wrt_set


class LoopVariables(object):
    """Loop variables"""
    UNKNOWN_VAR   = 0
    VARIANT_VAR   = 1
    INVARIANT_VAR = 2
    SYNC_VAR      = 3

    def __init__(self):
        self.loop_var_map = {}

    def add_loop_var(self, vdef):
        """Add a loop variable"""
        loop_var = self.loop_var_map.get(vdef, None)
        if loop_var == None:
            loop_var = (0, LoopVariables.UNKNOWN_VAR)
            self.loop_var_map[vdef] = loop_var
        cnt, status = loop_var
        self.loop_var_map[vdef] = (cnt + 1, status)
        return (cnt + 1, status)

    def del_loop_var(self, vdef):
        """Delete a loop variable"""
        loop_var = self.loop_var_map.get(vdef, None)
        if loop_var == None:
            return
        cnt, status = loop_var
        cnt = cnt - 1
        if cnt > 0:
            self.loop_var_map[vdef] = (cnt, status)
        else:
            del self.loop_var_map[vdef]

    def get_status(self, vdef):
        """Get status of a loop variable"""
        _, status = self.loop_var_map[vdef]
        return status

    def set_staus(self, vdef, status):
        """Set status of a loop variable"""
        cnt, _ = self.loop_var_map[vdef]
        self.loop_var_map[vdef] = (cnt, status)

    @property
    def loop_vars(self):
        """Get loop variables"""
        return set(list(self.loop_var_map.values()))

    def _get_vars(self, _s):
        """Get sync variables"""
        var_set = set()
        for (var, cnt_status) in self.loop_var_map.items():
            cnt, status = cnt_status
            # sanity check
            if cnt <= 0:
                continue
            # check status
            if status == _s:
                var_set.add(var)
        return var_set

    @property
    def sync_vars(self):
        """Get sync variables"""
        return self._get_vars(LoopVariables.SYNC_VAR)

    @property
    def variant_vars(self):
        """Get variant variables"""
        return self._get_vars(LoopVariables.VARIANT_VAR)

class ExitBlockInfo(object):
    """Exit basic block information"""
    def __init__(self, _xbb, _non_loop_bb):
        self.bb = _xbb # exit basic block
        self.non_loop_bb = _non_loop_bb # non-loop basic block
        self.defs = set() # loop variables

    def __repr__(self):
        str_list = []
        str_list.append("EXIT_BASIC_BLOCK: %s" + str(self.bb))
        str_list.append("NON_LOOP_BB: %s" + str(self.non_loop_bb))
        str_list.append("DEFS: " + str(self.defs))
        return "\n".join(str_list)

    def __lt__(self, other):
        return self.bb < other.bb

class BBReadWriteList(object):
    """Read/wrtie set for a basic block"""
    def __init__(self, analyzer, bb, *pred_rws):
        self.analyzer = analyzer
        self.bb = bb           # owner basic block
        self.all_rw_list = []  # [(rN, wN), ..., (r0, "")] + [all preds]
        pred_rw_list = []
        for pred_rw in pred_rws:
            pred_rw_list.extend(pred_rw.rw_list)
        self.pred_len = len(pred_rw_list)
        self.all_rw_list = pred_rw_list

    def __repr__(self):
        str_list = ["BB: " + str(self.bb)]
        str_list.append("RWL: " + str(self.rw_list))
        return "\n".join(str_list)

    @property
    def rw_list(self):
        """Get unique rw list for this basic block"""
        if self.pred_len > 0:
            return self.all_rw_list[:-self.pred_len]
        else:
            return self.all_rw_list

    def add_rw(self, rd, wrt, inst):
        """Add a rw tuple"""
        re_rd  = self._rewrite_rd(rd)
        re_wrt = self._rewrite_wrt(wrt)
        if re_rd != "" or re_wrt != "":
            self.all_rw_list.insert(0, (re_rd, re_wrt, inst))
            log.debug("ADD_RW: [%s] /%s:%s/->/%s:%s/" \
                      % (inst, re_rd, rd, re_wrt, wrt))

    def _rewrite_rd(self, var):
        """Rewrite a read variable"""
        if var == "":
            return ""
        cvar = None
        for pred_rd, pred_wrt, inst in self.all_rw_list:
            if pred_wrt == "":
                continue
            # exact matching
            if var.find(pred_wrt) != -1:
                var = var.replace(pred_wrt, pred_rd)
                break
            # range matching
            if AsmParser.is_register(pred_wrt):
                # E.g., %al <- %eax
                if cvar == None:
                    cvar = inst.expand_reg_expr(var)
                cpred_wrt = inst.expand_reg_expr(pred_wrt)
                re_wrt = self.analyzer._overlap_cvars(cpred_wrt, cvar)
                if re_wrt != None:
                    cvar_new = cvar.replace(re_wrt, pred_rd)
                    var = inst.arch.shrink_reg_expr(cvar_new)
                    break
                cvar = None
        return var

    def _rewrite_wrt(self, var):
        """Rewrite a write variable"""
        if var == "":
            return ""
        for pred_rd, pred_wrt, inst in reversed(self.all_rw_list):
            if pred_wrt == "" or var == pred_wrt:
                continue
            # exact matching
            if var.find(pred_wrt) != -1:
                var = var.replace(pred_wrt, pred_rd)
                break
        return var

class SyncLoopAnalyzer(object):
    """Analyze sync. loop"""
    def __init__(self, loop, loop_id, anal_inst_max = 1000):
        self.syncinfo = SyncLoopInfo(loop, loop_id)
        self.arch = loop.header.insts[0].arch
        self.anal_inst_max = anal_inst_max
        self.bbs_to_header_paths = {}
        self.bb_rwl = {}
        self.hd_cwrtset = set() # write set of header path
        self.nhd_rwset = set() # read-write set of non-header path
        self.exit_only_bbs = set()
        # preprocessing the loop
        self._preproc_loop()

    def _preproc_loop(self):
        """Preprocessing a loop"""
        self._constant_folding()
        self._make_recursive_def_defunct()

    def _constant_folding(self):
        """Constant folding"""
        loop = self.syncinfo.loop
        bb = loop.header
        bb.constant_folding()
        for bb in loop.body:
            bb.constant_folding()

    def _make_recursive_def_defunct(self):
        """Make recursive definition defunct"""
        loop = self.syncinfo.loop
        bb = loop.header
        bb.make_recursive_def_defunct()
        for bb in loop.body:
            bb.make_recursive_def_defunct()

    def find_sync_loop(self):
        """Check if a loop is a sync loop or not"""
        self._find_xbb_infos()
        self._find_exit_only_bbs()
        if not self._build_rd_wrt_list():
            return False, None
        self._find_sync_loop_vars()
        return self.syncinfo.is_sync_loop, self.syncinfo

    def _find_exit_only_bbs(self):
        """Find exit only basic blocks"""
        self.exit_only_bbs = set()
        for xbb_info in self.syncinfo.xbb_infos:
            xbb = xbb_info.bb
            for xo_bb in self._find_exit_only_bbs_x86(xbb):
                self.exit_only_bbs.add(xo_bb)
        log.debug("FOUND_EXIT_ONLY_BB: %s" % self.exit_only_bbs)

    def _find_exit_only_bbs_x86(self, xbb):
        """
        Find exit only basic blocks for x86 using simple heuristic.

        * TODO NOTE
          This is not complete. For completeness, we should use symbolic
          execution to check such blocks, which are executed only exit paths.
        """
        # Exit block
        #   000000000109218e^5 lock.atomic nop
        #   0000000001092193   jne 109217e # exit address
        if len(xbb.insts) != 2 or len(xbb.ins) != 2:
            return
        nop = xbb.insts[0]
        if nop.op != "nop" or len(nop.prefix) == 0:
            return
        if nop.prefix[0] != "lock.atomic":
            return
        jne = xbb.insts[1]
        if jne.op != "jne":
            return

        # Exit-only block from cmpxchg
        #   000000000109218e^2 lock.atomic.je.unlikely mov %rdx,0x0(%rbx)
        #   000000000109218e^3 lock.atomic.je.unlikely jmp 000000000109218e^5
        for xo_bb in xbb.ins:
            for inst in xo_bb.insts:
                if len(inst.prefix) == 0:
                    xo_bb = None
                    break
                if inst.prefix[0] != "lock.atomic.je.unlikely":
                    xo_bb = None
                    break
            if xo_bb != None:
                yield xo_bb

    def _build_rd_wrt_list(self):
        """Build read-write set"""
        # build per-bb read-write list
        self.bb_rwl = {}
        # for each bb
        for bb in self.syncinfo.bbs:
            # do not build rwlist for exit-only basic blocks
            if bb in self.exit_only_bbs:
                log.debug("======= SKIP_EXIT_ONLY_BB: %s =========" % str(bb))
                continue
            log.debug("======= BB: %s =========" % str(bb))
            nh_pred_bb_rwls = []
            nh_pred_bbs = self._bbs_to_header(bb) # node to head
            # give up to analyze too large loop
            num_insts = 0
            for bb in nh_pred_bbs:
                num_insts += len(bb.insts)
            if num_insts > self.anal_inst_max:
                return False
            # from head to me
            for pred_bb in reversed(nh_pred_bbs):
                preb_bb_rwl = self.bb_rwl.get(pred_bb, None)
                # if there is no rwl for a bb, create one
                if not preb_bb_rwl:
                    preb_bb_rwl = self._create_rwl(pred_bb, nh_pred_bb_rwls)
                    self.bb_rwl[pred_bb] = preb_bb_rwl
                nh_pred_bb_rwls.insert(0, preb_bb_rwl)
        # merge all
        rd_wrt_list = []
        for rwl in self.bb_rwl.values():
            rd_wrt_list.extend(rwl.rw_list)
        self.syncinfo.rd_wrt_list = rd_wrt_list
        # create a write set in a canonical form, which is recursively defined
        for (rd, wrt, _) in self.syncinfo.rd_wrt_list:
            if rd == "#ur" and wrt != "":
                cwrt = self.arch.expand_reg_expr(wrt)
                self.syncinfo.c_r_wrt_set.add(cwrt)
        return True

    def _create_rwl(self, bb, pred_bb_rwls):
        """Create a read-write list for a basic block"""
        rwl = BBReadWriteList(self, bb, *pred_bb_rwls)
        for inst in bb.insts:
            # get read & write sets of an instruction
            ird_set = inst.read_set.copy()
            iwrt_set = inst.write_set.copy()
            # data flow for simple movement instructions
            if inst.itype == InstKind.simple_mov:
                # add rw for simple move instructions
                for rd, wrt in inst.redef_list:
                    rwl.add_rw(rd, wrt, inst)
                # remove redef ones from the the read/write set
                redef_rd_wrt_list = list(zip(*inst.redef_list))
                ird_set -= set(redef_rd_wrt_list[0])
                iwrt_set -= set(redef_rd_wrt_list[1])
            # add ird_set and iwrt_set to the rwl
            for rd in ird_set:
                rwl.add_rw(rd, "", inst)
            for wrt in iwrt_set:
                rwl.add_rw("#u", wrt, inst)
        return rwl

    def _find_xbb_infos(self):
        """Find loop exit basic blocks"""
        log.debug("LOOP: %s" % str(self.syncinfo.loop))
        for bb in self.syncinfo.bbs:
            non_loop_bbs = bb.outs - self.syncinfo.bbs
            if non_loop_bbs:
                assert(len(non_loop_bbs) == 1)
                non_loop_bbs = [x for x in non_loop_bbs]
                xbb_info = ExitBlockInfo(bb, non_loop_bbs[0])
                self.syncinfo.xbb_infos.append(xbb_info)
                log.debug("EXIT_BB: %s" % str(bb))

    def _find_sync_loop_vars(self):
        """Find synchronization variables from loop variables"""
        have_variant_vars = False
        have_sync_vars = False
        # Find loop variables
        for xbb_info in self.syncinfo.xbb_infos:
            xbb = xbb_info.bb
            if self._is_stack_cannery_check_bb(xbb):
                continue
            rinsts = self._reversed_insts_to_header(xbb)
            defs = self._find_loop_var_defs(xbb, rinsts)
            # set defs for the xbb
            xbb_info.defs = defs
            # add it to the var_dict
            for vdef in xbb_info.defs:
                _, status = self.syncinfo.var_dict.add_loop_var(vdef)
                if status == LoopVariables.UNKNOWN_VAR:
                    if self._is_unknown(vdef):
                        log.debug("UNKNOWN-VDEF: %s" % vdef)
                        self.syncinfo.var_dict.set_staus(vdef, LoopVariables.VARIANT_VAR)
                        have_variant_vars = True
                        continue
                    if self._is_loop_invariant(vdef):
                        if self._is_sync_var(vdef):
                            log.debug("SYNC-VDEF: %s" % vdef)
                            self.syncinfo.var_dict.set_staus(vdef, LoopVariables.SYNC_VAR)
                            have_sync_vars = True
                        else:
                            log.debug("INVARIANT-VDEF: %s" % vdef)
                            self.syncinfo.var_dict.set_staus(vdef, LoopVariables.INVARIANT_VAR)
                    else:
                        log.debug("VARIANT-VDEF: %s" % vdef)
                        self.syncinfo.var_dict.set_staus(vdef, LoopVariables.VARIANT_VAR)
                        have_variant_vars = True
                        continue
        # Decide if it is a sync loop or not
        self.syncinfo.is_sync_loop = (
            have_variant_vars == False and have_sync_vars == True)

    def _is_stack_cannery_check_bb(self, xbb):
        """Check if this exit basic block is for stack cannery"""
        return self._is_stack_cannery_check_bb_x86(xbb)

    def _is_stack_cannery_check_bb_x86(self, xbb):
        """Stack cannery detection for x86-gcc"""
        # XXX TODO NOTE: seperate out arch-dependent code!!!

        # <exit block>
        #   ...
        #   mov 0x*(%rsp), %REG
        #   xor %fs:0x*,   %REG
        #   jne *
        # check instruction sequence
        if len(xbb.insts) < 3:
            return False
        mov_inst = xbb.insts[-3]
        xor_inst = xbb.insts[-2]
        jne_inst = xbb.insts[-1]
        if not mov_inst.op.startswith("mov") or \
           not xor_inst.op.startswith("xor") or \
           not jne_inst.op.startswith("jne"):
            return False
        # one of outs should be a return
        have_ret = False
        for out_bb in xbb.outs:
            if out_bb.insts[-1].op.startswith("ret"):
                have_ret = True
                break
        if not have_ret:
            return False
        # check mov
        if mov_inst.opd[0].find("(%rsp)") == -1 or \
           not mov_inst.opd[0].startswith("0x") or \
           not mov_inst.opd[1].startswith("%"):
            return False
        tmp_reg = mov_inst.opd[1]
        # check xor
        if xor_inst.opd[1] == tmp_reg:
            thread_local_mem = xor_inst.opd[0]
        elif xor_inst.opd[0] == tmp_reg:
            thread_local_mem = xor_inst.opd[1]
        else:
            return False
        if not thread_local_mem.startswith("%fs:0x"):
            return False
        return True

    def _is_loop_invariant(self, var):
        """Test if a variable is loop-invariant or not"""
        # does it rely on unknown source?
        if var.find("#u") != -1:
            return False
        # constant
        if AsmParser.is_constant(var):
            return True
        # get an update set for a variable
        update_set = self._get_update_set(var)
        log.debug("  UPDATE_SET: %s" % update_set)
        # if nothing is changed, it is loop-invariant
        if not update_set:
            return True
        # if the same value is updated, it is loop-invariant
        return self._update_same(update_set)

    def _is_unknown(self, var):
        """Is a variable unknown?"""
        return var.find("#u") != -1

    def _get_update_set(self, var):
        """Get update set of a variable"""
        update_set = set()
        cvar = self.arch.expand_reg_expr(var)
        for wrt in self.syncinfo.wrt_set:
            if var.find(wrt) != -1:
                # not in write set: comparison in a lexical form
                update_set.add(wrt)
            elif AsmParser.is_register(wrt):
                # not in write set: comparison in a normalized form
                cwrt = self.arch.expand_reg_expr(wrt)
                if self._overlap_cvars(cvar, cwrt) != None:
                    update_set.add(wrt)
        return update_set

    def _is_updated(self, var):
        """Check if a variable is update or not"""
        # unknown
        if var.find("#u") != -1:
            return True
        # constant
        if AsmParser.is_constant(var):
            return False
        cvar = self.arch.expand_reg_expr(var)
        for wrt in self.syncinfo.wrt_set:
            # If the var is updated with the lexicographically same value,
            # then we consider that the var is not updated.
            if var == wrt:
                continue
            # Otherwise, check it is updated.
            if var.find(wrt) != -1:
                # not in write set: comparison in a lexical form
                return True
            elif AsmParser.is_register(wrt):
                # not in write set: comparison in a normalized form
                cwrt = self.arch.expand_reg_expr(wrt)
                if self._overlap_cvars(cvar, cwrt) != None:
                    return True
        return False

    def _update_same(self, update_set):
        """Check if it update the same value or not"""
        for upd in update_set:
            cupd = None
            for rd, wrt, inst in self.syncinfo.rd_wrt_list:
                log.debug("    UPD0-CHK: %s - RD: %s - WRT: %s [%s]" \
                          % (upd ,rd, wrt, inst))
                if wrt == "":
                    continue
                if upd == wrt:
                    if self._is_updated(rd):
                        log.debug("    UPD0-FAIL: %s - RD: %s - WRT: %s [%s]"\
                                  % (upd ,rd, wrt, inst))
                        return False
                elif AsmParser.is_register(wrt):
                    cupd = self.arch.expand_reg_expr(upd) if not cupd else cupd
                    cwrt = self.arch.expand_reg_expr(wrt)
                    if self._overlap_cvars(cupd, cwrt) != None:
                        if self._is_updated(rd):
                            log.debug("    UPD1: %s - RD: %s - WRT: %s [%s]" \
                                      % (upd ,rd, wrt, inst))
                            return False
        return True

    def _overlap_cvars(self, cwrt, cvdef):
        """ Check if cvdef and cwrt are overlapped in a normalized form"""
        (creg, cran, clen) = self._parse_reg_range(cwrt)
        s = cvdef.find(creg)
        if s != -1:
            (cvreg, cvran, cvlen) = self._parse_reg_range(cvdef[s:])
            if self._range_overapped(cran, cvran):
                return cvdef[s:s+cvlen]
        return None

    def _is_sync_var(self, vdef):
        """Find synchornization variables among loop variables"""
        # Pick memory variables among invaraint-loop variables
        if AsmParser.is_memory(vdef):
            # Thread local variable (e.g., %fs:0x28) cannot
            # be a sync. variable
            if AsmParser.is_thread_local_memory(self.arch, vdef):
                return False

            # Pick variables, which are written in a lexical form
            # This is needed since we will read the synchronization
            # variables in runtime.
            for rd_wrt in self.syncinfo.rd_wrt_set:
                if vdef.find(rd_wrt) != -1:
                    return True
        return False

    def _find_loop_var_defs(self, bb, rinsts):
        """Find definitions of loop exit variables for all basic blocks"""
        # Set context
        self._set_context(bb)
        # Start from the read set of the terminator of an exit block
        log.debug("INST: %s" % rinsts[0])
        log.debug("    VDEFS: %s" % rinsts[0].read_set)
        vdefs = self._find_var_defs(rinsts[0].read_set, rinsts[1:])
        return vdefs

    def _set_context(self, bb):
        """Set context for finding loop variables"""
        # Set write set in a path to header
        hd_bbs = set(self._bbs_to_header(bb))
        hd_wrtl = []
        for bb in hd_bbs:
            bb_rwl = self.bb_rwl.get(bb, None)
            if bb_rwl != None:
                for (rd, wrt, _) in bb_rwl.rw_list:
                    cwrt = self.arch.expand_reg_expr(wrt)
                    hd_wrtl.append(cwrt)
        self.hd_cwrtset = set(hd_wrtl) - set([''])

        # Set non-header path read-write list
        nhd_bbs = self.syncinfo.bbs - hd_bbs
        nhd_rwl = []
        for bb in nhd_bbs:
            bb_rwl = self.bb_rwl.get(bb, None)
            if bb_rwl != None:
                for (rd, wrt, _) in bb_rwl.rw_list:
                    nhd_rwl.append((rd, wrt))
        self.nhd_rwset = set(nhd_rwl)

    def _find_var_defs(self, vdefs, rinsts):
        """Find definitions of a variable"""
        for inst in rinsts:
            log.debug("INST: %s" % inst)
            # If vdefs are modified by inst.write_set,
            # rewrite defs with this inst.read_set.
            new_vdefs = set()
            for vdef in vdefs:
                vdef_set = self._try_rewrite_vdef(vdef, inst)
                if vdef_set:
                    new_vdefs |= vdef_set
                else:
                    new_vdefs.add(vdef)
            vdefs = new_vdefs
            log.debug("    VDEFS: %s" % vdefs)
        return vdefs

    def _try_rewrite_vdef(self, vdef, inst):
        """Rewrite variable definition"""
        cvdef = self.arch.expand_reg_expr(vdef)
        new_vdef_set = set()
        for wrt in inst.write_set:
            # Test if an instruction redefines the vdef
            re_vdef, re_vdef = None, None
            if vdef.find(wrt) != -1:
                # E.g., %rax <- %rax, 0x0(%rbp) <- %rbp
                re_wrt, re_vdef  = wrt, vdef
            elif AsmParser.is_register(wrt):
                # E.g., %al <- %eax
                cwrt = self.arch.expand_reg_expr(wrt)
                re_wrt = self._overlap_cvars(cwrt, cvdef)
                if re_wrt != None:
                    re_vdef  = cvdef
            # Replace the wrt in vdef to read set
            if re_vdef:
                if re_vdef in self.arch.status_flag_regs:
                    # rewrite definition
                    for rd in inst.read_set:
                        new_cvdef = re_vdef.replace(re_wrt, rd)
                        new_dvdef = self.arch.shrink_reg_expr(new_cvdef)
                        new_vdef_set.add(new_dvdef)
                elif inst.itype == InstKind.simple_mov:
                    for rd in inst.read_set:
                        if self._is_unknown_in_nhd_bbs(inst, re_vdef, re_wrt):
                            # unknown
                            log.debug("UKN INST: %s" % inst)
                            log.debug("UKN INST_READ_SET: %s" % inst.read_set)
                            log.debug("UKN RE_VDEF: %s" % re_vdef)
                            log.debug("UKN RE_WRT:  %s" % re_wrt)
                            log.debug("UKN RD:  %s" % rd)
                            new_cvdef = re_vdef.replace(re_wrt, "#u")
                            new_dvdef = self.arch.shrink_reg_expr(new_cvdef)
                            new_vdef_set.add(new_dvdef)
                            break
                        else:
                            # rewrite definition
                            new_cvdef = re_vdef.replace(re_wrt, rd)
                            new_dvdef = self.arch.shrink_reg_expr(new_cvdef)
                            new_vdef_set.add(new_dvdef)
                else:
                    # unknown
                    new_cvdef = re_vdef.replace(re_wrt, "#u")
                    new_dvdef = self.arch.shrink_reg_expr(new_cvdef)
                    new_vdef_set.add(new_dvdef)
        return new_vdef_set

    def _is_unknown_in_nhd_bbs(self, inst, expr, sb_expr):
        """Test if re_wrt is unknown in non-header-path bbs"""
        # NOTE: expr is not a flag register

        # If an instruction is in a header block,
        # defer testing after full rewriting
        if inst in self.syncinfo.loop_hd_dom_insts:
            log.debug("UKN HEADER_DOM_INST: %s" % inst)
            return False

        # If not canonicalized, canonicalize register first
        c_sb_expr = sb_expr
        if sb_expr.find("[") == -1:
            c_sb_expr = self.arch.expand_reg_expr(sb_expr)

        # If there is an unknown due to recursion, it is always unknown.
        # : e.g., mov (%rdx), %rdx
        # TODO: register range matching
        if c_sb_expr in self.syncinfo.c_r_wrt_set:
            log.debug("UKN C_SB_EXPR: %s" % c_sb_expr)
            log.debug("UKN C_R_WRT_SET: %s" % self.syncinfo.c_r_wrt_set)
            return True

        # If sb_expr is redefined in a path to header,
        # defer testing after full rewriting.
        # This is a simplified liveness analysis, which simply
        # checks the liveness of an expression either in path-to-header
        # or path-to-non-header.
        # TODO: register range matching
        if c_sb_expr in self.hd_cwrtset:
            return False

        # Match with a non-cannonical form
        for (rd, wrt) in self.nhd_rwset:
            if rd.find("#u") != -1 and wrt != "" and expr.find(wrt) != -1:
                return True

        # Match with a cannonical form
        cexpr = self.arch.expand_reg_expr(expr)
        if cexpr == expr:
            return False
        for (rd, wrt) in self.nhd_rwset:
            if rd.find("#u") == -1 or wrt == "":
                continue
            cwrt = self.arch.expand_reg_expr(wrt)
            (creg, cran, clen) = self._parse_reg_range(cwrt)
            s = cexpr.find(creg)
            if s != -1:
                (cvreg, cvran, cvlen) = self._parse_reg_range(cexpr[s:])
                if self._range_overapped(cran, cvran):
                    return True
        return False

    def _parse_reg_range(self, reg_ran_x):
        """Decompose '%eax[1:2]xxx' into (%eax, (1, 2), len(%eax[1:2]))"""
        s = reg_ran_x.find("[")
        e = reg_ran_x.find("]")
        # unknown register
        if s == -1 or e == -1:
            return (reg_ran_x, [], len(reg_ran_x))
        # known register
        reg = reg_ran_x[:s]
        ran = [int(x) for x in reg_ran_x[s+1:e].split(":")]
        length  = e + 1
        return (reg, ran, length)

    def _range_overapped(self, x, y):
        """Test if there range x and y are overlapped"""
        xs = set( range(x[0], x[1]))
        ys = set( range(y[0], y[1]))
        return xs.intersection(ys)

    def _reversed_insts_to_header(self, bb):
        """Get reversed instructions to the loop header"""
        rinsts = []
        for bb in self._bbs_to_header(bb):
            rinsts.extend(reversed(bb.insts))
        return rinsts

    def _bbs_to_header(self, bb):
        """Get basic blocks to the loop header"""
        if self.bbs_to_header_paths.get(bb, None) == None:
            bb_trace = []
            # DFS - do not visit exit-only basic blocks
            bb_discovered = self.exit_only_bbs.copy()
            self._bbs_to_header_dfs(bb, bb_trace, bb_discovered)
            bb_trace.insert(0, bb)
        else:
            bb_trace = bbs_to_header_paths[bb]
        return bb_trace.copy()

    def _bbs_to_header_dfs(self, bb, bb_trace, bb_discovered):
        """Get basic blocks to the loop header"""
        if bb == self.syncinfo.loop.header:
            return True

        bb_discovered.add(bb)
        for bb_next in bb.ins:
            # Don't follow non-loop, unlikely, or already-visited basic blocks
            if not bb_next in self.syncinfo.bbs or \
               bb_next.unlikely or \
               bb_next in bb_discovered:
                continue
            # Follow bb_next
            ret = self._bbs_to_header_dfs(bb_next, bb_trace,
                                          bb_discovered)
            if ret:
                bb_trace.insert(0, bb_next)
                return True
        return False

class NonSyncLoopMerger(object):
    """Try to merge non-sync loops"""
    def __init__(self, header, loop_infos):
        self.header = header
        self.loop_infos = loop_infos
        self._mergable = None

    def merge_and_find_sync_loops(self):
        """Merge and fine sync loops"""
        # Sanity check if it is mergable
        if self.loop_infos == None or len(self.loop_infos) <= 1:
            log.debug("It is not mergable")
            return []
        # NxN merge
        loop_mg_infos = []
        all_merged = True
        for loop_i in self.loop_infos:
            for loop_j in self.loop_infos:
                if loop_i == loop_j:
                    continue
                loop_mg = self._try_merge_loops(loop_i, loop_j)
                if loop_mg:
                    loop_mg_infos.append(loop_mg)
                else:
                    all_merged = False
        # If there is one or more loops that cannot be merged,
        # the common loop header should not be included,
        # where is shared by other non-sync loops.
        if not all_merged:
            for loop_mg in loop_mg_infos:
                loop_mg.bbs.remove(self.header)
        return loop_mg_infos

    def _try_merge_loops(self, loop_tgt, loop_src):
        """Try merge two loop info: loop_tgt += loop_src"""
        # Check if there is mathcing boundary exit block
        boundary_xbbs = self._find_boundary_xbb(loop_tgt, loop_src)
        if not boundary_xbbs:
            return None
        log.debug("== Two loops (%s, %s) have common boundary blocks."
                  % (loop_tgt.loop_id, loop_src.loop_id))

        # Check if two loops have the same variables after merging
        var_match = self._match_variables_after_merge(
            loop_tgt, loop_src, boundary_xbbs)
        if not var_match:
            return None
        log.debug("  -- Two loops (%s, %s) have the same variables after merging."
                  % (loop_tgt.loop_id, loop_src.loop_id))

        # Merge: loop_mg = loop_tgt + loop_src
        loop_mg = self._merge_loops(loop_tgt, loop_src, boundary_xbbs)
        log.debug("  -- Merged loop: %s" % str(loop_mg))
        log.debug("  -- Merged loop variant vars: %s" % loop_mg.variant_vars)
        return loop_mg

    def _find_boundary_xbb(self, loop_info0, loop_info1):
        """Find boundary exit blocks of two loops"""
        loop0_bbs = loop_info0.loop.bbs
        loop1_bbs = loop_info1.loop.bbs
        boundary_xbbs = []
        # Search NxN
        for xbb_info0 in loop_info0.xbb_infos:
            for xbb_info1 in loop_info1.xbb_infos:
                # Does the boundary bb point each other?
                if xbb_info0.bb == xbb_info1.bb and \
                   xbb_info0.non_loop_bb in loop1_bbs and \
                   xbb_info1.non_loop_bb in loop0_bbs:
                    pair = (xbb_info0, xbb_info1)
                    boundary_xbbs.append(pair)
                    break
        return boundary_xbbs

    def _match_variables_after_merge(self, _loop0, _loop1, boundary_xbbs):
        """Check if two loops have the same variables after merging"""
        # Delete variables defined by exit blocks
        loop0 = self._clone_sync_loop_info(_loop0)
        loop1 = self._clone_sync_loop_info(_loop1)
        for (info0, info1) in boundary_xbbs:
            for vdef in info0.defs:
                loop0.var_dict.del_loop_var(vdef)
            for vdef in info1.defs:
                loop1.var_dict.del_loop_var(vdef)
        # Check if sync variables are the same and not empty
        if not loop0.sync_vars or loop0.sync_vars != loop1.sync_vars:
            return False
        # Check if variant variables don't exist
        if loop0.variant_vars or loop1.variant_vars:
            return False
        return True

    def _merge_loops(self, loop_tgt, loop_src, boundary_xbbs):
        """Merge two loops"""
        loop_mg = self._clone_sync_loop_info(loop_tgt)
        loop_mg.loop_id = loop_tgt.loop_id + "+=" + loop_src.loop_id
        #  - Merge basic blocks of two loops
        loop_mg.bbs = loop_tgt.bbs.union(loop_src.bbs)
        #  - Delete boundary exit blocks and their variant variables
        for (info_tgt, info_src) in boundary_xbbs:
            # Delete variant variables defined at the boundary_xbb
            for vdef in info_tgt.defs:
                status = loop_mg.var_dict.get_status(vdef)
                if status == LoopVariables.VARIANT_VAR:
                    loop_mg.var_dict.del_loop_var(vdef)
            # Remove tgt_info in the loop_tgt
            loop_mg.xbb_infos.remove(info_tgt)
        return loop_mg

    def _clone_sync_loop_info(self, loop_info):
        """Clone a sync loop info for loop merge opration"""
        import copy
        clone = copy.copy(loop_info)
        clone.var_dict = copy.deepcopy(loop_info.var_dict)
        clone.bbs = copy.copy(loop_info.bbs)
        clone.xbb_infos = copy.copy(loop_info.xbb_infos)
        clone._addr_ranges = None
        return clone

class SyncLoopRange(object):
    """Sync loop addreange and sync varaibles"""
    def __init__(self, func, saddr, eaddr, sync_vars):
        self.func      = func
        self.saddr     = saddr
        self.eaddr     = eaddr
        self.sync_vars = sync_vars.copy()

    def __lt__(self, other):
        """self < other"""
        return self.saddr < other.saddr

    def try_combine(self, other):
        """combine self and other if possible"""
        if self.saddr <= other.saddr and other.eaddr <= self.eaddr:
            self.sync_vars |= other.sync_vars
            return True
        return False

    def __str__(self):
        return self.str_demangle_opt(True)

    def str_demangle_opt(self, demangle_opt):
        # format
        # function_name, start_addr, end_addr, expr1, expr2, ... # demangled name
        # -------------              --------
        #   \                         \
        #    +-- optional              +-- inclusive
        func_name = self.func.name
        saddr = "0x%x" % self.saddr
        eaddr = "0x%x" % self.eaddr
        str_list = [func_name, saddr, eaddr]
        str_list.extend(sorted(self.sync_vars))
        out_str = ",".join(str_list)
        if demangle_opt:
            out_str = out_str + " # %s" % self.func.demangled_name
        return out_str

def find_sync_loops(func,
                    func_inst_max = 100000,
                    loop_body_max = 200,
                    loop_anal_inst_max = 2000,
                    debug_vis=False):
    """Find synchronization loops from a function"""
    # give up analyzing a too large function
    if func.num_inst > func_inst_max:
        return []
    # reconstruct CFG
    cfg = CFG(func)
    cfg.reconstruct()
    if debug_vis:
        dbg_fcn = str(func)[:str(func).find("[")]
        cfg.visualize("debug-%s.pdf" % dbg_fcn, fmt="pdf")
    # find loops
    analyzer = LoopAnalyzer(cfg)
    loops = analyzer.find_natural_loops()
    # find sync loops
    non_sync_infos = {}
    sync_infos = []
    for (i, loop) in enumerate(sorted(loops)):
        log.debug("LOOP ==== %d ====" % i)
        if debug_vis:
            loop.visualize("debug-%s-loop-%d.pdf" % (dbg_fcn, i),
                           fmt="pdf")
        if loop.num_bb > loop_body_max:
            continue
        analyzer = SyncLoopAnalyzer(loop, str(i), loop_anal_inst_max)
        is_sync_loop, sync_info = analyzer.find_sync_loop()
        if is_sync_loop:
            log.debug(repr(sync_info))
            sync_infos.append(sync_info)
        else:
            header = sync_info.loop.header
            loops = non_sync_infos.get(header, [])
            loops.append(sync_info)
            non_sync_infos[header] = loops
    # try to merge non-sync loops
    for (header, loop_infos) in non_sync_infos.items():
        log.debug("TRY NON-SYNC LOOP MERGE ==== %s : %d" % \
                  (header, len(loop_infos)))
        merger = NonSyncLoopMerger(header, loop_infos)
        loop_mg_infos = merger.merge_and_find_sync_loops()
        for sync_info in loop_mg_infos:
            log.debug(repr(sync_info))
        sync_infos += loop_mg_infos
    return sync_infos

def find_sync_loop_ranges(func,
                          func_inst_max = 100000,
                          loop_body_max = 200,
                          loop_anal_inst_max = 2000,
                          debug_vis=False):
    """Find synchronization loop ranges from a function"""
    sync_infos = find_sync_loops(func, func_inst_max, loop_body_max,
                                 loop_anal_inst_max, debug_vis)
    sync_loop_ranges = merge_sync_loop_ranges(func, sync_infos)
    return sync_loop_ranges

def merge_sync_loop_ranges(func, sync_infos):
    """Merge sync loop ranges"""
    # sanity check
    if sync_infos == None:
        return None
    if sync_infos == []:
        return []
    # convert to sync loop ranges
    sync_loop_ranges = []
    for sync_info in sync_infos:
        sync_vars = sync_info.sync_vars
        for addr_range in sync_info.addr_ranges:
            saddr = addr_range[0]
            eaddr = addr_range[1]
            sync_loop_range = SyncLoopRange(func, saddr, eaddr, sync_vars)
            sync_loop_ranges.append(sync_loop_range)
    sync_loop_ranges = sorted(sync_loop_ranges)
    # merge ranges
    merged_sync_loop_ranges = []
    merge_base = sync_loop_ranges[0]
    for sync_loop_range in sync_loop_ranges[1:]:
        if not merge_base.try_combine(sync_loop_range):
            merged_sync_loop_ranges.append(merge_base)
            merge_base = sync_loop_range
    merged_sync_loop_ranges.append(merge_base)
    # ok, done
    return merged_sync_loop_ranges
