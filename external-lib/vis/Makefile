CUR_PATH = $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
VIS_SRC_NAME = vis-4.20.1
VIS_SRC = $(CUR_PATH)/$(VIS_SRC_NAME)
VIS_INSTALL_PATH = $(realpath $(CUR_PATH)/../..)/build/vis

ifeq ($(V),1)
	Q =
else
	Q = @
endif
export Q

NPROCS = 1
OS = $(shell uname -s)
ifeq ($(OS),Linux)
	NPROCS = $(shell grep -c ^processor /proc/cpuinfo)
endif

.PHONY: build install clean distclean

default: all
all : build

build: $(VIS_SRC)
	@echo [ $@ ];

$(VIS_SRC): $(VIS_SRC_NAME).tar.gz
	$(Q)if [ ! -d "$(VIS_SRC)" ]; then \
		tar xf $(VIS_SRC_NAME).tar.gz -C ./; \
	fi

$(VIS_SRC_NAME).tar.gz:
	wget https://github.com/almende/vis/archive/v4.20.1.tar.gz -O vis-4.20.1.tar.gz

install:
	$(Q)if [ ! -d $(VIS_INSTALL_PATH) ]; then \
		mkdir $(VIS_INSTALL_PATH); \
	fi
	$(Q)cp -f $(CUR_PATH)/dks.html $(VIS_INSTALL_PATH)/
	$(Q)cp -rf $(VIS_SRC)/dist $(VIS_INSTALL_PATH)/

clean:
	$(Q)rm -rf $(VIS_SRC)

distclean:
	$(Q)rm -rf $(CUR_PATH)/$(VIS_SRC_NAME).tar.gz $(VIS_SRC)
