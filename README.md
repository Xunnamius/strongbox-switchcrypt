# BuseLFS

This is a complete rewrite of the old buselogfs code. This is a Buse + Chacha20 + Poly1305 + LFS encrypted filesystem. It uses Argon2 as its KDF.

(todo: advantages, disadvantages, tradeoffs, etc)

## Things to Address

- Byte order is assumed to be **little endian**. Might have to an implement endian conversion layer touching `io.c` and `crypto.c`, perhaps using the standard functions, if this becomes an issue.
- Merkle Tree implementation has a hard upper limit (2^TREE_DEPTH or 1,048,576 elements, soft limited to 524288) to the number of leaves and tree node levels 
- The `open` and `wipe` commands do not currently work, since their proper functioning wasn't necessary for gathering results. If they become germane to the research at some future point, they will be fixed.

## Dependencies

- [zlog]()
- [libsodium]()
- [make]()
- [gcc]() (sorry, I'm using some GCC extensions to make life easier)
- [ruby]() (if you're going to be running the tests)
- [OpenSSL]() (if you're going to be running AES-XTS emulation mode; no flake sizes less than 16 bytes!)
- std=c11
- /dev/mmcblk0rpmb (i.e. a device that offers a RPMB API)

## Usage

You may wish to run the included unit tests first before actually utilizing buselfs. See the [Testing](#testing) section below.

`sudo` and/or root privileges are required at certain points due to ioctl calls made to privileged devices (like the RPMB).

First, of course, `make` buselfs:

```
# make clean # only if you were running tests or making things before now. Important for different O/DEBUG levels!
# make
```

Command syntax:

```
# buselfs [--default-password][--backstore-size 1024][--flake-size 4096][--flakes-per-nugget 64] create nbd_device_name
# buselfs [--default-password][--allow-insecure-start] open nbd_device_name
# buselfs [--default-password][--allow-insecure-start] wipe nbd_device_name
```

Note: nbd_device must always appear last and the desired command (open, wipe, etc) second to last.

Use `# buselfs help` for more information and friendly examples.

## Testing

This has only been tested on Core2 Debian 8 x64 and ARM Odroid XU3 (Debian and Ubuntu x64) systems. It's only guaranteed to work in these environments, if even that. Note: **these tests require ruby!**

Run these tests to make (about 90%) sure:

Note that the password for all tests is always **"t"** (no quotes, of course).

```
# make clean
# make pre
# make check
```

### Available Tests

(todo) `test_aes` is used only for AES-XTS!

## File Structure and Internal Construction

(todo)

## Makefile Breakdown

(todo) (including DEBUG) (note that DEBUG mode breaks security, leaks potentially sensitive information)

## Configuration

(todo) (can configure RPMB device path to be something other than /dev/mmcblk0rpmb)
