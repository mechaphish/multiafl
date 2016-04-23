all:
	$(MAKE) -C fakesingle
	$(MAKE) -C fakeforksrv
	$(MAKE) -C afl
	bash -c "cd '$(CURDIR)/afl/qemu_mode' && ./build_qemu_support.sh"
clean:
	$(MAKE) -C fakesingle clean
	$(MAKE) -C fakeforksrv clean
	$(MAKE) -C afl clean
check:
	$(MAKE) -C fakesingle check
	$(MAKE) -C fakeforksrv check

.PHONY: clean all check
