SHELL = bash
# verbose flag
BUILD_VERBOSE = $(V)
ifeq ($(BUILD_VERBOSE),1)
	Q =
else
	Q = @
endif

# build directory
BDIR       ?= $(CURDIR)/../build/dks
BDIRLIB    ?= $(CURDIR)/../build/lib
BDIRUTIL   ?= $(CURDIR)/../build/dks/util
DEPDIR     ?= $(CURDIR)/.deps
DEPDIRLIB  ?= $(CURDIR)/.deps/lib
DEPDIRUTIL ?= $(CURDIR)/.deps/util

dks_bin  = $(BDIR)/dks
dks_objs += $(patsubst $(CURDIR)/%.c, $(BDIR)/%.o, \
	      $(wildcard $(CURDIR)/*.c))
libobjs += $(patsubst $(CURDIR)/../lib/%.c, $(BDIRLIB)/%.o, \
	      $(wildcard $(CURDIR)/../lib/*.c))
libperf_objs += $(patsubst $(CURDIR)/util/%.c, $(BDIRUTIL)/%.o, \
	      $(wildcard $(CURDIR)/util/*.c))

dks_objs := $(filter-out $(BDIR)/dks.o, $(dks_objs))
#filter-out flex,bison	      
#libperf_objs := $(filter-out %-flex.o, $(dks_util_objs))
#libperf_objs := $(filter-out %-bison.o, $(dks_util_objs))

# compiler flags
CFLAGS += -Wall -O0 -fPIC -D_GNU_SOURCE 
CFLAGS += -Wno-sizeof-pointer-div
CFLAGS += -g -DDEBUG
CFLAGS += -MMD -MF $(DEPDIR)/$*.d -MP  # dependency generation
CFLAGS += -DRING_BUFFER_CONF_NO_MMAP \
	  -DRING_BUFFER_CONF_NO_DOUBLE_MMAP

#TODO this should be changed with automatic lib test */
CFLAGS +=  -DHAVE_DWARF_UNWIND_SUPPORT \
	   -DHAVE_ARCH_X86_64_SUPPORT \
	   -DHAVE_PERF_REGS_SUPPORT \
	  -DHAVE_LIBUNWIND_SUPPORT \
	  -DHAVE_LIBELF_SUPPORT \
	  -DHAVE_LIBELF_MMAP_SUPPORT \
	  -DHAVE_ELF_GETPHDRNUM_SUPPORT \
	  -DHAVE_LIBBFD_SUPPORT

CFLAGS += -I$(CURDIR)/include \
	  -I$(CURDIR)/util/include \
	  -I$(CURDIR)/../lib/include \
	  -I$(CURDIR)/../include/arch/x86/include/ \
	  -I$(CURDIR)/../include \
	  -I$(CURDIR)/../external-lib/pci-ring-buffer/include

LDFLAGS += -L$(CURDIR)/../build/pci-ring-buffer/build_user
LDFLAGS += -L$(BDIR)
LIBS += -ldks #for libdks
LIBS +=-lpthread -lrt -lprb -lm -lelf -lsqlite3 -ldw -lunwind -lbfd -ljson-c

all: dirs $(BDIR)/libdks.a $(dks_bin)

$(dks_bin): $(BDIR)/dks.o $(BDIR)/libdks.a
	@echo "CC	$@"
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

$(BDIR)/libdks.a:$(libperf_objs) $(libobjs) $(dks_objs)
	$(AR) rcs $@ $^

$(BDIR)/%.o: %.c
	@echo "CC	$@"
	$(Q)$(CC) $(CFLAGS) -o $@ -c $<

$(BDIRUTIL)/%.o: %.c
	@echo "CC	$@"
	$(Q)$(CC) $(CFLAGS) -o $@ -c $<

$(BDIRLIB)/%.o: $(CURDIR)/../lib/%.c
	@echo "CC	$@"
	$(Q)$(CC) $(CFLAGS) -o $@ -c $<

dirs:
	$(Q)mkdir -p $(BDIR) $(DEPDIR) $(BDIRLIB) $(DEPDIRLIB) $(BDIRUTIL) $(DEPDIRUTIL)

install: 
	$(Q)cp *.sh $(BDIR)/
	@echo "$@ done"

clean:
	@echo "CLEAN"
	$(Q) rm -rf $(BDIR)/*
	$(Q) rm -rf $(DEPDIR)/*

.PHONY: all install clean libs
