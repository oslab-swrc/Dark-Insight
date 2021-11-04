# architecture-dependent configuration
target_arch=$(shell $(CC) -dumpmachine | sed 's:-.*::')
ifeq ($(target_arch),x86_64)
	CFLAFS += -DHOST -DTARGET_ARCH_X86_64
else ifeq ($(target_arch),k1om)
	CFLAFS += -DTARGET_ARCH_K1OM -mmic
	ifneq (,$(findstring icc,$(CC)))
		CFLAFS += -mmic
	endif
else
        $(error Architecture '$(target_arch)' is not supported)
endif

# common configuration
SRC_ROOT := ..
BDIR ?= $(target_arch)

CFLAGS  += -W -Wall
CFLAGS  += -O3 -march=native -mtune=native # max. optimization level
CFLAGS  += -g # include debug symbols
CFLAGS  += -I$(SRC_ROOT)/include
CFLAGS  += -I$(SRC_ROOT)/lib # expose internal headers for unit testcases
DEPSDIR := .deps
DEPCFLAGS = # -MD -MF $(DEPSDIR)/$*.d -MP
LDFLAGS += -lpthread -lrt
ifeq ($(CONFIG_PCI_RING_BUFFER_SCIF),m)
LDFLAGS += -lscif
endif

# application-dependent configuration
CFLAGS  += -DRING_BUFFER_CONF_NO_MMAP        # do not use mmap
CFLAGS  += -DRING_BUFFER_CONF_NO_DOUBLE_MMAP # for compatability with kernel


# lib objs and bins
pci_ring_buffer_objs := $(addprefix $(BDIR)/lib/, \
					ring_buffer_shm.o \
					ring_buffer.o \
				      	ring_buffer_porting.o)
ifeq ($(CONFIG_PCI_RING_BUFFER_SCIF),m)
pci_ring_buffer-objs += $(addprefix $(SRC_ROOT)/lib/, \
					ring_buffer_scif.o)
endif

# test objs and bins
pci_ring_buffer_test_objs := $(patsubst $(SRC_ROOT)/test_user/%.c,\
					$(BDIR)/test_user/%.o,\
					$(wildcard $(SRC_ROOT)/test_user/rb-*.c))
pci_ring_buffer_test_bins := $(patsubst $(SRC_ROOT)/test_user/%.c,\
					$(BDIR)/%,\
					$(wildcard $(SRC_ROOT)/test_user/rb-*.c))
ifeq ($(CONFIG_PCI_RING_BUFFER_SCIF),m)
pci_ring_buffer_test_objs += $(patsubst $(SRC_ROOT)/test_user/%.c,\
					$(BDIR)/test_user/%.o,\
					$(wildcard $(SRC_ROOT)/test_user/rbs-*.c))
pci_ring_buffer_test_bins += $(patsubst $(SRC_ROOT)/test_user/%.c,\
					$(BDIR)/%,\
					$(wildcard $(SRC_ROOT)/test_user/rbs-*.c))
endif

# build rules
all: $(BDIR)/libprb.a \
     $(pci_ring_buffer_test_bins) \
     $(pci_ring_buffer_test_bins)

$(BDIR)/lib/%.o: $(SRC_ROOT)/lib/%.c
	@mkdir -p $(BDIR)/lib/
	$(CC) $(CFLAGS) $(DEPCFLAGS) -c -o $@ $<

$(BDIR)/test_user/%.o: $(SRC_ROOT)/test_user/%.c
	@mkdir -p $(BDIR)/test_user/
	$(CC) $(CFLAGS) $(DEPCFLAGS) -c -o $@ $<

$(BDIR)/libprb.a: $(pci_ring_buffer_objs)
	@/bin/rm -f $@
	@mkdir -p $(BDIR)/
	$(AR) cru $@ $^

$(BDIR)/rb-ut: $(BDIR)/test_user/rb-ut.o $(BDIR)/libprb.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

$(BDIR)/rb-pair: $(BDIR)/test_user/rb-pair.o $(BDIR)/libprb.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

$(BDIR)/rbs-ut: $(BDIR)/test_user/rbs-ut.o $(BDIR)/libprb.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

$(BDIR)/rbs-flow: $(BDIR)/test_user/rbs-flow.o $(BDIR)/libprb.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

$(BDIR)/rbs-blocking-ut: $(BDIR)/test_user/rbs-blocking-ut.o $(BDIR)/libprb.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f $(pci_ring_buffer_objs) \
	      $(pci_ring_buffer_test_objs) \
	      $(pci_ring_buffer_test_bins) \
	      $(BDIR)/libprb.a

install:
	# do nothing
