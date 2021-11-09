SRC_DIRS  = external-lib
SRC_DIRS += kdks dks
NJOB := ${shell nproc}

# verbose flag
BUILD_VERBOSE = $(V)
ifeq ($(BUILD_VERBOSE),1)
  Q =
else
  Q = @
endif
export Q

# targets
all:
	$(Q)for d in $(SRC_DIRS); \
		do ( echo; \
			echo '\033[0;32m==================================================='; \
			echo '[*] BUILD '$$d; \
			echo '\033[0m'; \
			cd $$d; $(MAKE) -j${NJOB}; \
		); \
	done

install:
	$(Q)for d in $(SRC_DIRS); \
		do ( echo; \
			echo '\033[0;34m==================================================='; \
			echo '[*] INSTALL '$$d; \
			echo '\033[0m'; \
			cd $$d; $(MAKE) install; \
		); \
	done

clean:
	$(Q)for d in $(SRC_DIRS); \
		do ( echo; \
			echo '\033[0;35m==================================================='; \
			echo '[*] CLEAN '$$d; \
			echo '\033[0m'; \
			cd $$d; $(MAKE) clean; \
		); \
	done

distclean: clean
	$(Q) rm -f TAGS cscope.*

cscope:
	$(Q) rm -f cscope.*
	$(Q) find ${CURDIR}  -name '*.cc'	\
		-or -name '*.cpp' 		\
		-or -name '*.c'			\
		-or -name '*.ic'		\
		-or -name '*.h' -exec realpath {} \; > cscope.files
	$(Q) cscope -b -q -R && echo '[*] Done - create cscope';

tags:
	$(Q) etags `find . -type f -name '*.cc' -or -name '*.cpp'  -or -name '*.c' -or -name '*.h' -or -name '*.ic' -exec realpath {} \\;`

.PHONY: all install clean distclean cscope tags 
