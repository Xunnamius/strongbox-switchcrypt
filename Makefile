.PHONY: buselfs clean check tests

buselfs:
	$(MAKE) all -C build

clean:
	$(MAKE) clean -C build

check:
	$(MAKE) check -C build

tests:
	$(MAKE) tests -C build
