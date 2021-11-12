# verbose flag
BUILD_VERBOSE = $(V)
ifeq ($(BUILD_VERBOSE),1)
	Q =
else
	Q = @
endif

# build directory
tcpath0 := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
tcpath1 := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
TCNAME  := $(subst $(tcpath0)/,,$(tcpath1))

BUILD_ROOT ?= $(abspath $(CURDIR)/../../build/)
BDIR    ?= $(BUILD_ROOT)/tests/$(TCNAME)
DEPDIR  ?= $(CURDIR)/.deps

tc_bin  := $(BDIR)/tc
tc_objs += $(patsubst $(CURDIR)/%.c, $(BDIR)/%.o, \
	      $(wildcard $(CURDIR)/*.c))

# conpiler flags
CFLAGS += -Wall -D_GNU_SOURCE
CFLAGS += -g -O0 -DDEBUG -fno-omit-frame-pointer
CFLAGS += -MMD -MF $(DEPDIR)/$*.d -MP  # dependency generation
CFLAGS += -DHAVE_PERF_REGS_SUPPORT \
	  -DHAVE_ARCH_X86_64_SUPPORT \
	  -DHAVE_PERF_REGS_SUPPORT \
	  -DHAVE_LIBUNWIND_SUPPORT \
	  -DHAVE_LIBELF_SUPPORT \
	  -DHAVE_ELF_GETPHDRNUM_SUPPORT \
	  -DHAVE_LIBBFD_SUPPORT

CFLAGS += -I$(CURDIR)/../../include \
	  -I$(CURDIR)/../../lib/include \
	  -I$(CURDIR)/../../include/arch/x86/include \
	  -I$(CURDIR)/../../dks	\
	  -I$(CURDIR)/../../external-lib/pci-ring-buffer/include
LDFLAGS += -L$(CURDIR)/../../build/pci-ring-buffer/build_user
LDFLAGS += -L$(CURDIR)/../../build/dks/
LDFLAGS += -ldks -lpthread -lrt -lm -lprb -lelf -ldw -lunwind -lbfd -ljson-c

all: $(BUILD_ROOT)/dks/libdks.a $(BDIR) $(DEPDIR) $(tc_bin)

$(BUILD_ROOT)/dks/libdks.a:
	$(Q)$(MAKE) -C $(BUILD_ROOT)/../dks/ $@

$(tc_bin): $(tc_objs) $(BUILD_ROOT)/dks/libdks.a
	@echo "CC	$@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BDIR)/%.o: %.c
	@echo "CC	$@"
	$(Q)$(CC) $(CFLAGS) -o $@ -c $<

$(BDIR):
	$(Q) mkdir -p $(BDIR)

$(DEPDIR):
	$(Q) mkdir -p $(DEPDIR)

install:
	@echo "Copying scripts to $(BDIR)"
	$(Q) cp -f $(CURDIR)/*.sh $(BDIR) 2> /dev/null || \
	     cp -f $(CURDIR)/*.py $(BDIR) 2> /dev/null || \
	     echo > /dev/null

clean:
	@echo "CLEAN"
	$(Q) rm -rf $(BDIR)/*
	$(Q) rm -rf $(DEPDIR)/*

.PHONY: all install clean
