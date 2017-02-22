TARGET		:= buselfs
STATIC_LIB	:= vendor/libbuse.a

CC			:= /usr/bin/gcc
CFLAGS		:= -g -pedantic -Wall -Wextra -std=c99 -I/usr/local/include
LDFLAGS		:= -L./vendor -L/usr/local/lib -lbuse -lsodium -lm

.PHONY: all clean tests check
all: $(TARGET)

$(TARGET): %: bin/%.o $(STATIC_LIB)
	$(CC) -o bin/$@ $< $(LDFLAGS)

bin/$(TARGET:=.o): bin/%.o: src/%.c vendor/buse.h
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f bin/*

check:
	echo "run tests"

tests:
	echo "make tests"
