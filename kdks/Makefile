ifneq ($(KERNELRELEASE),)
# in-tree build
include Kbuild

else
# out-of-tree build
KDIR ?= /lib/modules/`uname -r`/build
BDIR ?= $(CURDIR)/../build/kdks
BDIR_MAKEFILE ?= $(BDIR)/Makefile
UDEV_RULE ?= $(CURDIR)/81-kdks.rules
RB_MOD_SYM ?= $(CURDIR)/../build/pci-ring-buffer/build_kernel/Module.symvers

# verbose flag
BUILD_VERBOSE = $(V)
ifeq ($(BUILD_VERBOSE),1)
	Q =
else
	Q = @
endif

default: $(BDIR_MAKEFILE)
	$(Q) $(MAKE) -C $(KDIR) M=$(BDIR) src=$(CURDIR) KBUILD_EXTRA_SYMBOLS=$(RB_MOD_SYM)

$(BDIR_MAKEFILE): $(BDIR)
	$(Q) touch $(BDIR_MAKEFILE)

$(BDIR):
	$(Q) mkdir -p $(BDIR)

install: modules_install

modules_install: udev_rule_install
	$(Q) $(MAKE) -C $(KDIR) M=$(BDIR) src=$(CURDIR) modules_install
	$(Q) depmod

udev_rule_install:
	$(Q) cp -f $(UDEV_RULE) /etc/udev/rules.d

clean:
	$(Q) $(MAKE) -C $(KDIR) M=$(BDIR) src=$(CURDIR) clean

.PHONY: install modules_install clean
endif # KERNELRELEASE
