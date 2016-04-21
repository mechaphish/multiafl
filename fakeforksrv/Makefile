CFLAGS := -DDEBUG
#CFLAGS := -DDEBUG -O3 -march=core2
#CFLAGS := -O3 -march=core2
CFLAGS += -m32 -std=gnu99 -g -g3 -ggdb -gdwarf-4 -Wall -Wextra


QEMU_PATH := ./multi-qemu
EXAMPLES_DIR := /usr/share/cgc-challenges

CFLAGS += -DQEMU_PATH='$(QEMU_PATH)' 


all: fakeforksrv


.PHONY: clean all check install
clean:
	-rm -f fakeforksrv

check: all
	@echo TODO
