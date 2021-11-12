SRC_DIRS  = spin-forever spin-ping-pong spin-ts-ping-pong spin-ts-tts spin-two-cond spin-ts-mult
SRC_DIRS += pthread-spin-ping-pong libspin-ts-ping-pong
SRC_DIRS += mutex-ping-pong
SRC_DIRS += kdks-event kdks-profile
SRC_DIRS += spnf-parse

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
			cd $$d; $(MAKE); \
		); \
	done

clean:
	$(Q)for d in $(SRC_DIRS); \
		do ( echo; \
			cd $$d; $(MAKE) clean; \
		); \
	done

install:
	$(Q)for d in $(SRC_DIRS); \
		do ( echo; \
			cd $$d; $(MAKE) install; \
		); \
	done

.PHONY: all clean install
