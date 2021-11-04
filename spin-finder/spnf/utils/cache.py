#!/usr/bin/env python3
"""
base class of graph
"""
import os
import pickle
import logging
log = logging.getLogger(__name__)

class Entry:
    def __init__(self, st_size, st_mtime, value):
        self.st_size = st_size
        self.st_mtime  = st_mtime
        self.value = value

class Cache(object):
    """file name based cache"""
    def __init__(self, cachefile, miss_handler = None, miss_handler_ctx = None):
        self.cachefile = cachefile
        self.cdict = {}
        self.cleanup = False
        self.miss_handler = miss_handler
        if not self.miss_handler:
            self.miss_handler = Cache.dummy_miss_handler
        self.miss_handler_ctx = miss_handler_ctx
        self._load_cache()

    def get(self, file_bin):
        """Get a cached entry"""
        key = self._get_key(file_bin)
        entry = self.cdict.get(key, None)
        if entry:
            if not self._is_valid(file_bin, entry):
                del self.cdict[key]
            else:
                # hit and valid
                return entry.value
        # miss
        self.miss_handler(self, self.miss_handler_ctx, file_bin)
        entry = self.cdict.get(key, None)
        return entry.value if entry else None

    def put(self, file_bin, value):
        """Put a cache entry"""
        binstat = os.stat(file_bin)
        entry = Entry(binstat.st_size, binstat.st_mtime, value)
        key = self._get_key(file_bin)
        self.cdict[key] = entry
        self._save_cache()

    def remove(self, file_bin):
        """Delete a cache entry"""
        key = self._get_key(file_bin)
        del self.cdict[key]
        self._save_cache()

    def invalidate(self):
        """Invalidate cache"""
        os.unlink(self.cachefile)
        self.cdict = {}

    def _load_cache(self):
        """Load cache file"""
        try:
            with open(self.cachefile, "rb") as fd:
                self.cdict = pickle.load(fd)
        except (EOFError, FileNotFoundError) as e:
            # ignore error if there is no cache file or
            # no entry in the file
            pass

    def _save_cache(self):
        """Save cache file"""
        # clean up once
        if not self.cleanup:
            for (key, entry) in list(self.cdict.items()):
                if not self._is_valid(key, entry):
                    del self.cdict[key]
            self.cleanup = True
        # save the cache
        with open(self.cachefile, "wb") as fd:
            pickle.dump(self.cdict, fd)

    def _is_valid(self, file_bin, entry):
        """Load an cache entry from disk"""
        # no file_bin
        if not os.path.isfile(file_bin):
            return False
        # check timestamp and size between cfilef
        binstat = os.stat(file_bin)
        if entry.st_mtime != binstat.st_mtime \
           or entry.st_size != binstat.st_size:
            return False
        return True

    def _get_key(self, file_bin):
        """Get a key of cache from a file name"""
        return os.path.abspath(file_bin)

    @staticmethod
    def dummy_miss_handler(cache, file_bin):
        """Dummy cache miss handler"""
        # do nothing :)
        pass

