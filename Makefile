.PHONY: buselfs clean check

buselfs:
	$(MAKE) all -C build

clean:
	$(MAKE) clean -C build

check:
	$(MAKE) pre -C build
	$(MAKE) check -C build
	echo "Be sure to run 'make clean' if you try to build buselfs after this!"
