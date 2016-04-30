all:
	$(MAKE) -C fakeforksrv
	$(MAKE) -C afl
	bash -c "cd '$(CURDIR)/afl/qemu_mode' && ./build_qemu_support.sh"
	@echo "Skipping the test-only fakesingle."
	#$(MAKE) -C fakesingle
clean:
	$(MAKE) -C fakesingle clean
	$(MAKE) -C fakeforksrv clean
	$(MAKE) -C afl clean
	[ ! -d '$(CURDIR)/afl/qemu_mode/qemu-dev' ] || $(MAKE) -C '$(CURDIR)/afl/qemu_mode/qemu-dev' clean
check: all
	$(MAKE) -C fakeforksrv check
	@echo "If in a DARPA VM, You can also make -C fakesingle check"
	#$(MAKE) -C fakesingle check

.PHONY: clean all check
