all:
	$(MAKE) -C fakesingle
clean:
	$(MAKE) -C fakesingle clean
check:
	$(MAKE) -C fakesingle check

.PHONY: clean all check
