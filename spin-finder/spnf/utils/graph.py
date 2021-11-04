#!/usr/bin/env python3
"""
base class of graph
"""
import os
import sys
import subprocess
import tempfile
import logging
log = logging.getLogger(__name__)

class GraphPrinter(object):
    """Graph printer"""
    @staticmethod
    def _check_dot_installed():
        """Check is graphviz is installed or not"""
        p = subprocess.Popen("which dot", shell=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()
        l = p.stdout.readline()
        line = l.decode("utf-8").strip()
        if line.find("no dot in (") == -1:
            return True
        return False

    def __init__(self, graph, nodes = None):
        if not GraphPrinter._check_dot_installed():
            raise Exception("GraphVis is not installed")
        self.graph = graph
        self.nodes = nodes if nodes else set(self.graph.vertex_dict.values())

    def write(self, fn_out, fmt="pdf"):
        """Print graph to the fn_out in a SVG format"""
        # set up variables
        # create a temporarly graphviz file
        with tempfile.NamedTemporaryFile(mode='w') as tmp:
            self._write_graph_viz(tmp)
            tmp.flush()
            os.system("dot %s -T %s > %s" % (tmp.name, fmt, fn_out))

    def _write_graph_viz(self, fd):
        """Write a graph viz to an fd"""
        # header
        fd.write('digraph structs {\n')
        fd.write('    node [shape=plaintext]\n')
        # define vertex
        for vertex in sorted(self.nodes):
            fd.write('    %s [label=%s];\n' %
                     (vertex.uid, vertex.repr_html()))
        # connectivity
        for vertex in sorted(self.nodes):
            outs = sorted(vertex.outs & self.nodes)
            for out in outs:
                fd.write('    %s -> %s;\n' %
                         (vertex.uid, out.uid))
        # footer
        fd.write('}\n')

class Graph(object):
    """A graph composed of vertexes and edges"""
    def __init__(self):
        """Create a graph"""
        self.vertex_dict = {}  # dictionary of vertex

    def __repr__(self):
        str_list = []
        for vertex in sorted(self.vertex_dict.values()):
            str_list.append(repr(vertex))
        return "".join(str_list)

    def __str__(self):
        str_list = []
        for vertex in sorted(self.vertex_dict.values()):
            str_list.append(str(vertex))
        return "".join(str_list)

    def visualize(self, fn_out, nodes = None, fmt="pdf"):
        """Visualize a graph"""
        gp = GraphPrinter(self, nodes = nodes)
        gp.write(fn_out, fmt = fmt)

class Vertex(object):
    """A vertex"""
    def __init__(self):
        """Create a vertex of a graph"""
        self.ins  = set()  # incoming edges
        self.outs = set()  # outgoing edges
        self._uid = None   # unique vertex id

    def add_edge(self, target_vertex):
        """Add an edge from this vertex to a specified target vertex"""
        self.outs.add(target_vertex)
        target_vertex.ins.add(self)

    def repr_html(self):
        """Write a label for graphviz"""
        str_list = []
        str_list.append('<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">')
        str_list.append('<TR><TD ALIGN="LEFT"> %s </TD></TR>' % repr(self).replace("&", "&amp;"))
        str_list.append('</TABLE>')
        return '\n'.join(str_list)

    @property
    def uid(self):
        """Get an unique vertex id"""
        if not self._uid:
            self._uid = "vtx" + hex(id(self))
        return self._uid

class DomTree(object):
    """Dominator tree of a graph starting with a vertex"""
    def __init__(self, graph, n0):
        self._graph = graph
        self._n0 = n0
        self._dom_dict = {} # {vertex: set(dominators), ...}
        self._rs = set()

    def __repr__(self):
        str_list = []
        for (vertex, dominators) in sorted(self._dom_dict.items()):
            dom_list = []
            for d in sorted(dominators):
                dom_list.append(str(d))
            str_list.append(str(vertex) + ": " + ",".join(dom_list))
        return "\n".join(str_list)

    @property
    def reachable_set(self):
        """Reachable set of a graph from n0"""
        return self._rs

    def dominator(self, n):
        """Get dominators of n"""
        return self._dom_dict[n]

    def dominates(self, d, n):
        """Test if d dominates n"""
        dom_dict = self._dom_dict.get(n, None)
        if dom_dict:
            return d in self._dom_dict[n]
        else:
            return False

    def compute_dominance(self):
        """
        Compute dominance relations of a graph
        - https://en.wikipedia.org/wiki/Dominator_(_graph_theory)
        """
        # compute reachable set
        self._rs = self._compute_reachable_set(self._n0)

        # Dominator of the start node is the start itself
        dom_n0 = set([self._n0])
        self._dom_dict[self._n0] = dom_n0

        # For all reachable nodes, set all nodes as the dominators
        N = self._rs
        N2 = N - dom_n0
        for n in N2:
            self._dom_dict[n] = N.copy()

        # Iteratively eliminate nodes that are not dominators
        changed = True
        while changed:
            changed = False
            for n in N2:
                # {n} union with
                # intersection over Dom(p) for all p in pred(n)
                reachable_ins = N & n.ins
                if len(reachable_ins) > 0:
                    ins_sets = map(lambda p: self._dom_dict[p], reachable_ins)
                    dom_n = set.intersection(*ins_sets)
                    dom_n.add(n)
                else:
                    dom_n = set([n])
                # Update _dom_dict(n) if changed
                if dom_n != self._dom_dict[n]:
                    self._dom_dict[n] = dom_n
                    changed = True

    def _compute_reachable_set(self, n0):
        """Compute a reachable set of nodes from n0"""
        visited_nodes = set()
        work_queue = set([n0])

        while work_queue:
            node = work_queue.pop()
            # Is node already visited?
            if node in visited_nodes:
                continue
            # Visit the node
            visited_nodes.add(node)
            # Put successors into the work queue
            work_queue = work_queue.union(node.outs)
        return visited_nodes

class ReachableSet(object):
    """
    Warshall's algorithm
    http://www.cs.princeton.edu/courses/archive/spr03/cs226/lectures/digraph.4up.pdf
    """
    def __init__(self, graph):
        self._graph = graph
        self._tc = {}
        self._do_warshall()

    def reachable(self, v, w):
        """Return reachability from v to w"""
        return self._tc.get((v, w), False)

    def _do_warshall(self):
        """WARNING: O(n^3) -> too slow for large graph"""
        for n in self._graph.vertex_dict.values():
            self._tc[(n, n)] = True
            for out in n.outs:
                self._tc[(n, out)] = True
        for i in self._graph.vertex_dict.values():
            for v in self._graph.vertex_dict.values():
                for w in self._graph.vertex_dict.values():
                    if self._tc.get((v, i), False) and self._tc.get((i, w), False):
                        self._tc[(v, w)] = True
