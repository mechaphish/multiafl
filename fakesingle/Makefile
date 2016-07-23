C_FILES = fakesingle.c sockets.c signals.c

#CFLAGS := -DDEBUG
#CFLAGS := -DDEBUG -O3 -march=core2
CFLAGS := -O3 -march=core2
CFLAGS += -m32 -std=gnu99 -g -g3 -ggdb -gdwarf-4 -Wall -Wextra

# Allow for chroot(), as cb-test wants
# Note: also reason for ./xxx paths below
#CFLAGS += -static


EXAMPLES_DIR := /usr/share/cgc-sample-challenges/examples
CQE_CHALLENGES_DIR := /usr/share/cgc-sample-challenges/cqe-challenges

all: fakesingle hardcoded_CADET_00003 hardcoded_LUNGE_00005 hardcoded_EAGLE_00004 hardcoded_NRFIN_00006

fakesingle: $(C_FILES)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)


hardcoded_CADET_00003: $(C_FILES)
	[ -x ./CADET_00003 ]
	$(CC) -DHARDCODED_CBS='"./CADET_00003"' $(CFLAGS) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)
hardcoded_LUNGE_00005: $(C_FILES)
	[ -x ./LUNGE_00005_1 ]
	$(CC) -DHARDCODED_CBS='"./LUNGE_00005_1", "./LUNGE_00005_2", "./LUNGE_00005_3", "./LUNGE_00005_4", "./LUNGE_00005_5", "./LUNGE_00005_6"' $(CFLAGS) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)
hardcoded_EAGLE_00004: $(C_FILES)
	[ -x ./EAGLE_00004_1 ]
	$(CC) -DHARDCODED_CBS='"./EAGLE_00004_1", "./EAGLE_00004_2", "./EAGLE_00004_3"' $(CFLAGS) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)


hardcoded_NRFIN_00006: $(C_FILES)
	[ -x ./NRFIN_00006_1 ]
	$(CC) -DHARDCODED_CBS='"./NRFIN_00006_1", "./NRFIN_00006_2", "./NRFIN_00006_3", "./NRFIN_00006_4", "./NRFIN_00006_5", "./NRFIN_00006_6"' $(CFLAGS) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)


.PHONY: clean all check install
clean:
	-rm -f fakesingle hardcoded_*

check: all
	which cb-test
	@echo "Testing as wrapper on a single binary"
	! cb-test --negotiate --cb CADET_00003 --directory "$(CURDIR)" --xml_dir "$(EXAMPLES_DIR)/CADET_00003/poller/for-release/" --wrapper "$(CURDIR)/fakesingle" | egrep 'failed[^0-9]+[1-9]+'
	@echo "Testing with hardcoded CB names"
	! PATH=".:$$PATH" cb-test --negotiate --cb hardcoded_CADET_00003 --directory "$(CURDIR)" --xml_dir "$(EXAMPLES_DIR)/CADET_00003/poller/for-release/" --wrapper /usr/bin/env | egrep 'failed[^0-9]+[1-9]+'
	! PATH=".:$$PATH" cb-test --negotiate --cb hardcoded_LUNGE_00005 --directory "$(CURDIR)" --xml_dir "$(EXAMPLES_DIR)/LUNGE_00005/poller/for-release/" --wrapper /usr/bin/env | egrep 'failed[^0-9]+[1-9]+'
	! PATH=".:$$PATH" cb-test --negotiate --cb hardcoded_EAGLE_00004 --directory "$(CURDIR)" --xml_dir "$(EXAMPLES_DIR)/EAGLE_00004/poller/for-release/" --wrapper /usr/bin/env | egrep 'failed[^0-9]+[1-9]+'
	@echo "Testing on a CQE challenge set"
	! PATH=".:$$PATH" cb-test --cb hardcoded_NRFIN_00006 --directory "$(CURDIR)" --xml_dir "$(CQE_CHALLENGES_DIR)/NRFIN_00006/poller/for-release/" --wrapper /usr/bin/env | egrep 'failed[^0-9]+[1-9]+'
	@echo "All tests passed :)"
