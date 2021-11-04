#!/usr/bin/env python3
import os
import fnmatch
from spnf.utils.colors import *

import logging
log = logging.getLogger(__name__)

class Testcase(object):
    """Unit test case"""

    def __init__(self, fn):
        self.fn = fn          # test case file name
        self.tc_outs   = None # expected output of test case
        self.rm_outs   = None # removed outputs
        self.add_outs  = None # added outputs
        self.diff_outs = None # diff outputs
        self._load_tc_out()

    @property
    def filename(self):
        """An absolute path name of a test case"""
        return self.fn

    def check(self, outs):
        """Check if outputs are the same out not"""
        self.rm_outs = self._find_removed_outs(outs)
        self.add_outs = self._find_added_outs(outs)
        self.diff_outs = sorted( \
            list(map(lambda x: (x, False), self.rm_outs)) + \
            list(map(lambda x: (x, True),  self.add_outs)))
        return self._is_passed()

    def print_result(self):
        """Print test result"""
        PASS_COLOR = Color.bold + Color.fg.blue
        FAIL_COLOR = Color.bold + Color.fg.red
        RM_COLOR   = Color.fg.red
        ADD_COLOR  = Color.fg.green
        ENDC       = Color.reset

        # file name
        if self._is_passed():
            print("%s[PASS] %s%s" % (PASS_COLOR, self.fn, ENDC))
        else:
            print("%s[FAIL] %s%s" % (FAIL_COLOR, self.fn, ENDC))
        # diff outputs
        for out, added in self.diff_outs:
            if added:
                print("%s+  %s%s" % (ADD_COLOR, out, ENDC))
            else:
                print("%s-  %s%s" % (RM_COLOR,  out, ENDC))

    def _is_passed(self):
        """Check if a testcase is passed"""
        return True if self.rm_outs == [] and self.add_outs == [] else False

    def _find_removed_outs(self, outs):
        """Find removed outputs"""
        rm_outs = []
        for tc_out in self.tc_outs:
            found = False
            for out in outs:
                if out == tc_out:
                    found = True
                    break
            if not found:
                rm_outs.append(tc_out)
        return rm_outs

    def _find_added_outs(self, outs):
        """Find added outputs"""
        add_outs = []
        for out in outs:
            found = False
            for tc_out in self.tc_outs:
                if out == tc_out:
                    found = True
                    break
            if not found:
                add_outs.append(out)
        return add_outs

    def _load_tc_out(self):
        """Load tc outputs"""
        tc_outs = []
        with open(self.fn) as fd:
            for line in fd:
                # // TC_OUT RAMCloud::SpinLock::lock,0x495e86,0x4960c7,0x0($0x8<-0x88(%rbp)>)
                toks = line.split()
                if len(toks) < 3 or toks[0] != '//' or toks[1] != 'TC_OUT':
                    continue
                tc_outs.append(toks[2])
        tc_outs.sort()
        self.tc_outs = tc_outs

class Testsuite(object):
    """A collection of test cases"""

    def __init__(self):
        self._tc_list = [] # test case file names

    def load_tc_file(self, fn):
        """Load a test case"""
        # Sanity check
        fn = os.path.abspath(fn)
        if not os.path.isfile(fn):
            log.warning("%s is not a file" % fn)
            return
        # Create a Testcase
        tc = Testcase(fn)
        # Add to the test case list
        self._tc_list.append(tc)

    def load_tc_dir(self, dn, tc_filter = '*.S'):
        """Load test cases from a directory"""
        # Sanity check
        if not os.path.isdir(dn):
            log.warning("%s is not a directory" % dn)
            return
        # Get a list of test case files
        tc_files = []
        for root, dirnames, filenames in os.walk(dn):
            for filename in fnmatch.filter(filenames, tc_filter):
                tc_file = os.path.abspath(os.path.join(root, filename))
                tc_files.append(tc_file)
        tc_files.sort()
        # Load test cases for the files
        for fn in tc_files:
            self.load_tc_file(fn)

    def load_tc_path(self, path):
        """Load test case(s) from a path"""
        # file
        if os.path.isfile(path):
            self.load_tc_file(path)
            return
        # directory
        if os.path.isdir(path):
            self.load_tc_dir(path)
            return
        # directory with a filter
        ps = path.split('/')
        dn = '/'.join(ps[:-1])
        tc_filter = ps[-1]
        if not os.path.isdir(dn):
            log.warning("%s does not exist" % path)
            return
        self.load_tc_dir(dn, tc_filter)

    @property
    def testcases(self):
        return self._tc_list
