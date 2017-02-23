CC		:= /usr/bin/gcc
CFLAGS	:= -g -pedantic -Wall -Wextra -std=c99 -I/usr/local/include
C_FILES := $(wildcard *.c)

.PHONY: all

all: $(C_FILES:.c=)

$(C_FILES:.c=): %: %.c %.h
	$(CC) $(CFLAGS) -o ../bin/$@.o -c $<
