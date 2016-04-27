#CFLAGS := -DDEBUG -DSPAWN_IN_GDB
#CFLAGS := -DDEBUG -DSPAWN_IN_XTERM
#CFLAGS := -DDEBUG
#CFLAGS := -DDEBUG -O3 -march=core2
CFLAGS := -O3 -march=core2
CFLAGS += -m32 -std=gnu99 -g -g3 -ggdb -gdwarf-4 -Wall -Wextra

SAMPLES_DIR := ../../../samples/

MULTICB_QEMU_PATH := $(CURDIR)/multicb-qemu
CFLAGS += -DMULTICB_QEMU_PATH='"$(MULTICB_QEMU_PATH)"'


all: fakeforksrv run_via_fakeforksrv


.PHONY: clean all check install
clean:
	-rm -f fakeforksrv run_via_fakeforksrv

check: all
	[ -x "$(MULTICB_QEMU_PATH)" ]
	$(CURDIR)/check-cs.sh $(SAMPLES_DIR)/examples/CADET_00003/poller/for-release $(SAMPLES_DIR)/examples/CADET_00003/bin/CADET_00003
	$(CURDIR)/check-cs.sh EAGLE_00004
	$(CURDIR)/check-cs.sh LUNGE_00005
	$(CURDIR)/check-cs.sh NRFIN_00006
	$(CURDIR)/check-cs.sh YAN01_00009
	$(CURDIR)/check-cs.sh KPRCA_00016
	$(CURDIR)/check-cs.sh KPRCA_00024
	$(CURDIR)/check-cs.sh KPRCA_00048
