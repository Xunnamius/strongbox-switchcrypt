# BuseLFS

This is a complete rewrite of the old buselogfs code. This is a Buse + Chacha20 + Poly1305 + LFS encrypted filesystem. It uses Argon2 as its KDF.

(todo: advantages, disadvantages, tradeoffs, etc)

## Installation and Dependencies

Run `make` to compile buselfs. Run `make install` to install buselfs. Together, that's:

```
make
make install
```

You may wish to run the included unit tests first before installing. See the [Testing](#Testing) section below.

Run `make uninstall` to uninstall buselfs.

## Usage

(todo)

## Testing

This has only been tested on a Debian 8 x64 system. It's only guaranteed to work there, if even that.

Run these tests to make sure:

```
make check
```

## File Structure and Internal Construction

(todo)