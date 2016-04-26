#CFLAGS := -DDEBUG -DSPAWN_IN_GDB
#CFLAGS := -DDEBUG -DSPAWN_IN_XTERM
CFLAGS := -DDEBUG
#CFLAGS := -DDEBUG -O3 -march=core2
#CFLAGS := -O3 -march=core2
CFLAGS += -m32 -std=gnu99 -g -g3 -ggdb -gdwarf-4 -Wall -Wextra

EXAMPLES_DIR := /usr/share/cgc-challenges

MULTICB_QEMU_PATH := $(CURDIR)/multicb-qemu
CFLAGS += -DMULTICB_QEMU_PATH='"$(MULTICB_QEMU_PATH)"'


all: fakeforksrv run_via_fakeforksrv


.PHONY: clean all check install
clean:
	-rm -f fakeforksrv run_via_fakeforksrv

check: all
	[ -x "$(MULTICB_QEMU_PATH)" ]
	@echo TODO
