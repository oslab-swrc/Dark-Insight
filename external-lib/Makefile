# short-cut targets
all: ring_buffer_kernel ring_buffer_user vis
clean: ring_buffer_kernel_clean ring_buffer_user_clean vis_clean
install: ring_buffer_kernel_install ring_buffer_user_install vis_install

.PHONY: all clean install vis vis_clean vis_install

# ring buffer for kernel
ring_buffer_kernel:
	(cd $(CURDIR)/pci-ring-buffer/build_kernel; \
	$(MAKE) BDIR=$(CURDIR)/../build/pci-ring-buffer/build_kernel $(ARG))

ring_buffer_kernel_clean:
	(cd $(CURDIR)/pci-ring-buffer/build_kernel; \
	$(MAKE) BDIR=$(CURDIR)/../build/pci-ring-buffer/build_kernel clean $(ARG))

ring_buffer_kernel_install:
	(cd $(CURDIR)/pci-ring-buffer/build_kernel; \
	$(MAKE) BDIR=$(CURDIR)/../build/pci-ring-buffer/build_kernel install $(ARG))

# ring buffer for  user
ring_buffer_user:
	(cd $(CURDIR)/pci-ring-buffer/build_user; \
	$(MAKE) BDIR=$(CURDIR)/../build/pci-ring-buffer/build_user $(ARG))

ring_buffer_user_clean:
	(cd $(CURDIR)/pci-ring-buffer/build_user; \
	$(MAKE) BDIR=$(CURDIR)/../build/pci-ring-buffer/build_user clean $(ARG))

ring_buffer_user_install:
	(cd $(CURDIR)/pci-ring-buffer/build_kernel; \
	$(MAKE) BDIR=$(CURDIR)/../build/pci-ring-buffer/build_user install $(ARG))

vis:
	$(Q)cd $(CURDIR)/vis && $(MAKE) $(ARG)

vis_clean:
	$(Q)cd $(CURDIR)/vis && $(MAKE) clean $(ARG)

vis_install:
	$(Q)cd $(CURDIR)/vis && $(MAKE) install $(ARG)
