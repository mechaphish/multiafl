CFLAGS := -DDEBUG
CFLAGS += -m32 -g -g3 -ggdb -gdwarf-4 -Wall -Wextra

# Allow for chroot(), as cb-test wants
# Note: also reason for ./xxx paths below
#CFLAGS += -static


QEMU_PATH := ./multi-qemu
EXAMPLES_DIR := /usr/share/cgc-challenges

all: fakesingle fakesingle_qemu hardcoded_CADET_00003 hardcoded_LUNGE_00005 hardcoded_EAGLE_00004

fakesingle: fakesingle.c sockets.c signals.c utils.c resources.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)
fakesingle_qemu: fakesingle.c sockets.c signals.c utils.c resources.c
	$(CC) -DQEMU_PATH='$(QEMU_PATH)' $(CFLAGS) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)


hardcoded_CADET_00003: fakesingle.c sockets.c signals.c utils.c resources.c
	[ -x ./CADET_00003 ]
	$(CC) -DHARDCODED_CBS='"./CADET_00003"' $(CFLAGS) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)
hardcoded_LUNGE_00005: fakesingle.c sockets.c signals.c utils.c resources.c
	[ -x ./LUNGE_00005_1 ]
	$(CC) -DHARDCODED_CBS='"./LUNGE_00005_1", "./LUNGE_00005_2", "./LUNGE_00005_3", "./LUNGE_00005_4", "./LUNGE_00005_5", "./LUNGE_00005_6"' $(CFLAGS) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)
hardcoded_EAGLE_00004: fakesingle.c sockets.c signals.c utils.c resources.c
	[ -x ./EAGLE_00004_1 ]
	$(CC) -DHARDCODED_CBS='"./EAGLE_00004_1", "./EAGLE_00004_2", "./EAGLE_00004_3"' $(CFLAGS) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)


.PHONY: clean all check install
clean:
	-rm -f fakesingle fakesingle_qemu hardcoded_*

check: all
	@echo "Testing as wrapper on a single binary"
	[ -f "$(EXAMPLES_DIR)/CADET_00003/poller/for-release/GEN_00000.xml" ]
	! cb-test --negotiate --cb CADET_00003 --directory "$(CURDIR)" --xml_dir "$(EXAMPLES_DIR)/CADET_00003/poller/for-release/" --wrapper "$(CURDIR)/fakesingle" | egrep 'failed[^0-9]+[1-9]+'
	@echo "Testing with hardcoded CB names"
	! PATH=".:$$PATH" cb-test --negotiate --cb hardcoded_CADET_00003 --directory "$(CURDIR)" --xml_dir "$(EXAMPLES_DIR)/CADET_00003/poller/for-release/" --wrapper /usr/bin/env | egrep 'failed[^0-9]+[1-9]+'
	[ -f "$(EXAMPLES_DIR)/LUNGE_00005/poller/for-release/GEN_00000.xml" ]
	! PATH=".:$$PATH" cb-test --negotiate --cb hardcoded_LUNGE_00005 --directory "$(CURDIR)" --xml_dir "$(EXAMPLES_DIR)/LUNGE_00005/poller/for-release/" --wrapper /usr/bin/env | egrep 'failed[^0-9]+[1-9]+'
	[ -f "$(EXAMPLES_DIR)/EAGLE_00004/poller/for-release/POLL_00000.xml" ]
	! PATH=".:$$PATH" cb-test --negotiate --cb hardcoded_EAGLE_00004 --directory "$(CURDIR)" --xml_dir "$(EXAMPLES_DIR)/EAGLE_00004/poller/for-release/" --wrapper /usr/bin/env | egrep 'failed[^0-9]+[1-9]+'
	@echo "All tests passed :)"
