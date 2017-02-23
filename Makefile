EXENAME     := buselfs
STATIC_LIB	:= vendor/libbuse.a

CC			:= /usr/bin/gcc
LDFLAGS		:= -L./vendor -L/usr/local/lib -lbuse -lsodium -lzlog -lpthread -lm

.PHONY: all clean check tests src

all: src
	$(CC) -o bin/$(EXENAME) bin/*.o $(STATIC_LIB) $(LDFLAGS)

clean:
	rm -f bin/*

check:
	$(MAKE) check -C test

tests:
	$(MAKE) -C test

src:
	$(MAKE) -C src
