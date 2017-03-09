# BuseLFS

This is a complete rewrite of the old buselogfs code. This is a Buse + Chacha20 + Poly1305 + LFS encrypted filesystem. It uses Argon2 as its KDF.

(todo: advantages, disadvantages, tradeoffs, etc)

## Things to Address

- Byte order is assumed to be **little endian**. Might have to implement endian conversion in `io.c` using the standard functions if this becomes an issue.
- 

## Dependencies

- [zlog]()
- [libsodium]()

## Usage

You may wish to run the included unit tests first before actually utilizing buselfs. See the [Testing](#testing) section below.

First, of course, `make` buselfs:

```
make
```

Command syntax:

```
(todo)
```

## Testing

This has only been tested on Core2 Debian 8 x64 and ARM Odroid XU3 (Debian and Ubuntu x64) systems. It's only guaranteed to work in these environments, if even that. Run the tests below to be (about 90%) sure!

Run these tests to make sure:

```
make check
```

## File Structure and Internal Construction

(todo)
