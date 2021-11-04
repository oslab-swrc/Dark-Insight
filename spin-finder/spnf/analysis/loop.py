#!/usr/bin/env python3
"""
loop analysis
"""
from spnf.utils.graph import *
from spnf.analysis.cfg import *
import logging
log = logging.getLogger(__name__)

class Loop(object):
    """Loop information"""
    def __init__(self, h, n, body):
        self.header = h           # loop header
        self.backedges = set([n]) # back edges
        self.body = body          # basic block of a loop excluding a header
        self._num_bb = None
        self._num_inst = None
        self._bbs = None

    def __repr__(self):
        str_list = []
        str_list.append("HEADER: " + str(self.header))
        str_list.append("BACKENDGES:")
        for bb in sorted(self.backedges):
            str_list.append("  " + str(bb))
        bbs = self.body - set([self.header]) - self.backedges
        if bbs:
            str_list.append("BODY:")
            for bb in sorted(bbs):
                str_list.append("  " + str(bb))
        return "\n".join(str_list)

    def __lt__(self, other):
        """self < other"""
        return self.header < other.header

    def _combine(self, other):
        self.backedges |= other.backedges
        self.body |= other.body

    def visualize(self, fn_out, fmt="pdf"):
        """Visualize a graph"""
        gp = GraphPrinter(self, nodes = self.bbs)
        gp.write(fn_out, fmt = fmt)

    @property
    def bbs(self):
        """Set of basic blocks"""
        if self._bbs == None:
            self._bbs = self.body | set([self.header])
        return self._bbs

    @property
    def num_bb(self):
        """Number of basic blocks"""
        if not self._num_bb:
            self._num_bb = 1 + len(self.body)
        return self._num_bb

    @property
    def num_inst(self):
        """Number of instructions"""
        if not self._num_inst:
            self._num_inst = len(self.header.insts)
            for bb in self.body:
                self._num_inst += len(self.body)
        return self._num_inst

class LoopAnalyzer(object):
    """Analyse loop in a CFG"""
    def __init__(self, cfg):
        self._cfg = cfg
        self._domtree = None
        self._reachable_set = None
        self._body_validity_cache = {}

    def find_natural_loops(self):
        """Find all natural loops in a CFG"""
        # There are two or more basic blocks
        if len(self._cfg.vertex_dict) < 2:
            return []
        # Find loops for each sub-graph
        # This is needed because an incomplte CFG may have
        # multiple basic blocks without incoming edges. So
        # CFG may consist of multiple sub-graphs.
        visited = set()
        loops = []
        for start_bb in self._start_bbs():
            # Build a dominance tree
            self._compute_dominance(start_bb)
            # For each node h in dominator tree
            not_visited_reachable_set = self._reachable_set - visited
            for h in not_visited_reachable_set:
                # Backedge: edge n->h such that h dominates n
                for n in h.ins:
                    if not self._is_valid_loop_body(h, n):
                        continue
                    if self._domtree.dominates(h, n):
                        body = self._find_loop_body(h, n)
                        if body:
                            loop = Loop(h, n, body)
                            loops.append(loop)
            # Update visited set
            visited |= self._reachable_set
        # Combine loops such that two loops share the same
        # loop header but are not nested each other
        return self._combine_loops(loops)

    def _compute_dominance(self, start_bb):
        """Compute dominance for start_bb"""
        self._domtree = DomTree(self._cfg, start_bb)
        self._domtree.compute_dominance()
        self._reachable_set = self._domtree.reachable_set
        self._body_validity_cache = {}

    def _is_valid_loop_body(self, header, body):
        """
        All incoming edges should be from a reachable set.
        It is required for dominace tree analaysis in multiheaded CFG.
        """
        valid = self._body_validity_cache.get(body, None)
        if valid == None:
            if header == body:
                valid = True
            else:
                valid = not (body.ins - self._reachable_set)
            self._body_validity_cache[body] = valid
        return valid

    def _start_bbs(self):
        """Find all starting basic blocks that have outs"""
        start_bbs = [self._cfg.start_bb]
        for n in self._cfg.vertex_dict.values():
            if not n.ins and n.outs and n != self._cfg.start_bb:
                start_bbs.append(n)
        return start_bbs

    def _find_loop_body(self, header, backedge):
        """
        Find a loop body excluding a loop header.
        If three is an unknown target address,
        it conservatively returns None.
        """
        # http://pages.cs.wisc.edu/~fischer/cs701.f14/finding.loops.html
        body = [header]
        stack = [backedge]
        while len(stack) > 0:
            d = stack.pop()
            if d not in body:
                if not self._is_valid_loop_body(header, d):
                    return None
                body.append(d)
                reachable_d_ins = self._reachable_set & d.ins
                for pred in reachable_d_ins:
                    stack.append(pred)
        return set(body)

    def _combine_loops(self, loops):
        """
        Combine loops such that two loops have the same
        header and none is nested in the other
        """
        # quick check
        if len(loops) < 2:
            return loops
        # build a header-loops dictionary
        hd_loops = {}
        for loop in loops:
            loop_list = hd_loops.get(loop.header, [])
            loop_list.append(loop)
            hd_loops[loop.header] = loop_list
        # combine loops
        for (header, loop_list) in hd_loops.items():
            while True:
                ccnt = 0
                if len(loop_list) >= 2:
                    cloops = []
                    for (x, loop_x) in enumerate(loop_list):
                        for (y, loop_y) in enumerate(loop_list[x+1:]):
                            if self._is_combinable(loop_x, loop_y):
                                loop_x._combine(loop_y)
                                loop_list.remove(loop_y)
                                ccnt += 1
                                break
                        cloops.append(loop_x)
                    loop_list = cloops
                if ccnt == 0:
                    break
            hd_loops[header] = loop_list
        # flaten hd_loops
        cloops = [item for sublist in hd_loops.values() for item in sublist]
        return sorted(cloops)

    def _is_combinable(self, m, n):
        """Test if two loops are combinable"""
        if m.header != n.header:
            return False
        if not m.body.intersection(n.body):
            return True
        return False
