# BuseLFS

This is a complete rewrite of the old buselogfs code. This is a Buse + Chacha20 + Poly1305 + LFS encrypted filesystem. It uses Argon2 as its KDF.

(todo: advantages, disadvantages, tradeoffs, etc)

## Things to Address

- Byte order is assumed to be **little endian**. Might have to an implement endian conversion layer touching `io.c` and `crypto.c`, perhaps using the standard functions, if this becomes an issue.
- Merkle Tree implementation has a hard upper limit (compiled) to the number of leaves and tree node levels 

## Dependencies

- [zlog]()
- [libsodium]()
- [make]()
- [gcc]() (sorry, I'm using some GCC extensions to make life easier)
- [ruby]() (if you're going to be running the tests)
- std=c11

## Usage

You may wish to run the included unit tests first before actually utilizing buselfs. See the [Testing](#testing) section below.

First, of course, `make` buselfs:

```
make clean # if you were running tests before now
make
```

Command syntax:

```
(todo)
```

## Testing

This has only been tested on Core2 Debian 8 x64 and ARM Odroid XU3 (Debian and Ubuntu x64) systems. It's only guaranteed to work in these environments, if even that. Note: **these tests require ruby!**

Run these tests to make (about 90%) sure:

```
make pre
make check
```

## File Structure and Internal Construction

(todo)

## Makefile Breakdown

(todo) (including DEBUG) (note that DEBUG mode breaks security, leaks potentially sensitive information)
