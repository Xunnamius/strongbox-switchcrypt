.PHONY: strongbox clean check

strongbox:
	$(MAKE) all -C build

clean:
	$(MAKE) clean -C build

check:
	echo "WARNING: Be sure to run 'make clean' if you try to build StrongBox after this!"
	$(MAKE) pre -C build
	$(MAKE) check -C build -B
