CFLAGS := -O3 -DNDEBUG
#CFLAGS := -DDEBUG
CFLAGS += -g -ggdb3 -Wall -Wextra

QEMU_PATH := /usr/local/bin/qemu-i386

all: fakesingle fakesingle_qemu

override CFLAGS += -m32 -std=gnu99
fakesingle: fakesingle.c sockets.c

fakesingle_qemu: fakesingle.c sockets.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LOADLIBES) $(LDLIBS)

.PHONY: clean all check
clean:
	rm -f fakesingle fakesingle_qemu


check: all
	@echo "Testing as wrapper on a single binary (remember to 'make install' the samples)"
	[ -f /usr/share/cgc-challenges/CADET_00003/bin/CADET_00003 ]
	! cb-test --negotiate --cb CADET_00003 --directory /usr/share/cgc-challenges/CADET_00003/bin --xml_dir /usr/share/cgc-challenges/CADET_00003/poller/for-release/ --wrapper "$(CURDIR)/fakesingle" | egrep 'failed[^0-9]+[1-9]+'
	@echo "Same but overriding CB from env variable"
	! CB_1=/usr/share/cgc-challenges/CADET_00003/bin/CADET_00003 FORCE_CB_ENV=1 cb-test --negotiate --cb LUNGE_00005_1 --directory /usr/share/cgc-challenges/LUNGE_00005/bin --xml_dir /usr/share/cgc-challenges/CADET_00003/poller/for-release/ --wrapper "$(CURDIR)/fakesingle" | egrep 'failed[^0-9]+[1-9]+'


#@echo "Trying as wrapper on each"
#! cb-test --negotiate --cb LUNGE_00005_1 LUNGE_00005_2 LUNGE_00005_3 LUNGE_00005_4 LUNGE_00005_5 LUNGE_00005_6 --directory /usr/share/cgc-challenges/LUNGE_00005/bin --xml_dir /usr/share/cgc-challenges/LUNGE_00005/poller/for-release/ --wrapper $(CURDIR)/fakesingle | egrep 'failed[^0-9]+[1-9]+'
