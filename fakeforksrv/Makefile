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

check-cs-%: all
	[ -x "$(MULTICB_QEMU_PATH)" ]
	$(CURDIR)/check-cs.sh $*

check: \
check-cs-EAGLE_00004 \
check-cs-EAGLE_00004 \
check-cs-NRFIN_00006 \
check-cs-YAN01_00009 \
check-cs-KPRCA_00016 \
check-cs-KPRCA_00024 \
check-cs-KPRCA_00048 \
check-cs-LUNGE_00005 \
check-cs-CADET_00003
	@echo "All tests passed :)"
