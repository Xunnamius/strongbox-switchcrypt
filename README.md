# BuseLFS

This is a complete rewrite of the old buselogfs code. This is a Buse + Chacha20 + Poly1305 + LFS encrypted filesystem. It uses Argon2 as its KDF.

(todo: advantages, disadvantages, tradeoffs, etc)
(Use `make tests` to run all the tests)
(The ONLY test that works with BLFS_DEBUG_MONITOR_POWER=1 is test_buselfs!)

## Things to Address

- Byte order is assumed to be **little endian**. Might have to an implement endian conversion layer touching `io.c` and `crypto.c`, perhaps using the standard functions, if this becomes an issue.
- Merkle Tree implementation has a hard upper limit (2^TREE_DEPTH or 1,048,576 elements, soft limited to 524288) to the number of leaves and tree node levels 

## Dependencies

- [zlog]()
- [libsodium]()
- [make]()
- [gcc]() (sorry, I'm using some GCC extensions to make life easier)
- [ruby]() (required iff you're going to be running the tests)
- [OpenSSL]() (provides swappable algorithm base)
- std=c11

## Usage

You may wish to run the included unit tests first before actually utilizing buselfs. See the [Testing](#testing) section below.

First, of course, `make` buselfs:

```
make clean # only if you were running tests or making things before now. Important for different O/DEBUG levels!
make
```

Command syntax:

```
(todo)
```

## Testing

This has only been tested on Core2 Debian 8 x64 and ARM Odroid XU3 (Debian and Ubuntu x64) systems. It's only guaranteed to work in these environments, if even that. Note: **these tests require ruby!**

Run these tests to make (about 90%) sure:

Note that the password for all tests is always **"t"** (no quotes, of course).

```
make clean
make pre
make check
```

test_aes is used only for AES-XTS!

## File Structure and Internal Construction

(todo)

## Makefile Breakdown

(todo) (including DEBUG) (note that DEBUG mode breaks security, leaks potentially sensitive information)
