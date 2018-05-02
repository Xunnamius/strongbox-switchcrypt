# StrongBox (internally: BuseLFS)

This is a complete rewrite of the old buselogfs code. This is a Buse + Chacha20 + Poly1305 + LFS encrypted filesystem. It uses Argon2 as its KDF. Featured in the paper `StrongBox: Confidentiality, Integrity, and Performance using Stream Ciphers for Full Drive Encryption` by Bernard Dickens III (University of Chicago), Haryadi Gunawi (University of Chicago), Ariel J Feldman (University of Chicago), and Henry Hoffmann (University of Chicago).

*Note that this is a prototype implementation of the StrongBox idea. This is not production-ready code. Do not expect to be able to use this in real life, it's only a proof-of-concept for little-endian odroid XU3s. As this is not production code, do not place it anywhere near files you consider important! You've been warned!*

(todo: flesh this README out)
(todo: advantages, disadvantages, tradeoffs, etc of this design; StrongBox is proof of concept)
(Use `make tests` to run all the tests)
(The ONLY test that works with BLFS_DEBUG_MONITOR_POWER=1 is test_buselfs!)
(tpm-id must be greater than 0 but <= LLONG_MAX)

## Things to Address

- Byte order is assumed to be **little endian**. Might have to an implement endian conversion layer touching `io.c` and `crypto.c`, perhaps using the standard functions, if this becomes an issue.
- Merkle Tree implementation has a hard upper limit (2^TREE_DEPTH or 1,048,576 elements, soft limited to 524288) to the number of leaves and tree node levels 
- The `open` and `wipe` commands do not currently work, since their proper functioning wasn't necessary for gathering results. If they become germane to the research at some future point, they will be fixed.

## Dependencies

- [zlog](https://github.com/HardySimpson/zlog)
- [libsodium](https://github.com/jedisct1/libsodium)
- [make](http://man7.org/linux/man-pages/man1/make.1.html)
- [gcc](https://gcc.gnu.org) (sorry, I'm using some GCC extensions to make life easier)
- [ruby](https://www.ruby-lang.org/en/) (required iff you're going to be running the tests)
- [OpenSSL](https://www.openssl.org) (provides swappable algorithm base)
- [energymon](https://github.com/energymon/energymon) (required iff you want energy metrics (has performance implications))
- [std=c11](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
- A device that offers or emulates an [RPMB API](https://lwn.net/Articles/682276/) is required iff you intend to test RPMB functionality. See: [BLFS_RPMB_KEY](#blfs_rpmb_key), [BLFS_RPMB_DEVICE](#blfs_rpmb_device), and [BLFS_MANUAL_GV_FALLBACK](#blfs_manual_gv_fallback).
    - *sudo access* is necessary when using RPMB functionality against an mmc device. If you're using a usersapce emulation of some sort, sudo is not necessary.

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

## Gathering Energy Metrics

Use of this feature requires [energymon](https://github.com/energymon/energymon) to be compiled—ideally with a non-dummy default implementation—and fully installed.

(todo)

## Configuration

(todo) (can configure RPMB device path to be something other than /dev/mmcblk0rpmb)

### Compile Flags

All compile flags must be specified with a `-D` prefix in [the actual Makefile](build/Makefile).

(todo)

##### `BLFS_DEBUG_MONITOR_POWER`

### Constants

These values are configurable in `src/constants.h`:

##### `BLFS_CURRENT_VERSION`
The current build version (arbitrary number).

##### `BLFS_LEAST_COMPAT_VERSION`
The absolute minimum build version of the StrongBox software whose backing store this current revision of StrongBox considers valid, e.g. backwards compatibility.

##### `BLFS_RPMB_KEY`
The key used by RPMB. In future versions of StrongBox, should they come to exist, this may not be the case (i.e. it's handled automatically/via TPM).

##### `BLFS_RPMB_DEVICE`
Valid Path string to the RPMB device, e.g. "/dev/mmcblk0rpmb". In future versions of StrongBox, should they come to exist, this may not be the case (i.e. it's found automatically).

##### `BLFS_CONFIG_ZLOG`
Path to your [zlog configuration file](https://github.com/HardySimpson/zlog/blob/master/doc/GettingStart-EN.txt).

##### `BLFS_ENERGYMON_OUTPUT_PATH`
If you've enabled [energy metrics gathering](#blfs_debug_monitor_power), this must be a valid file path string (file need not exist yet).

##### `BLFS_MANUAL_GV_FALLBACK`
(todo)



