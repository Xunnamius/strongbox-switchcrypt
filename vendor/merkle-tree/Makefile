# allows to call make Q= all and quiet will be disabled
Q=@ 

.PHONY: clean doc

all: debug

release:
	$(Q)$(MAKE) -C src/ release

debug:
	$(Q)$(MAKE) -C src/ debug

coverage:
	$(Q)$(MAKE) -C src/ coverage

clean:
	$(Q)rm -Rf doc/
	$(Q)$(MAKE) -C tests/ clean
	$(Q)$(MAKE) -C src/ clean

test:
	$(Q)$(MAKE) -C tests/ test

doc:
	$(Q)$(MAKE) -C src/ doc
