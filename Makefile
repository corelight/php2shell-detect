.PHONY: test zam clean format check

test:
	@$(MAKE) -C testing test

zam:
	@$(MAKE) -C testing zam

clean:
	@$(MAKE) -C testing clean

format:
	clz-format -i -r scripts
	clz-format -i -r testing/tests
	clz-format -i -r testing/Files

check:
	zeek -a ./scripts
