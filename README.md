# StrongBox (internally: BuseLFS)

This is a complete rewrite of the old buselogfs code. This is a Buse + Chacha20 + Poly1305 + LFS encrypted filesystem. It uses Argon2 as its KDF. Featured in the paper `StrongBox: Confidentiality, Integrity, and Performance using Stream Ciphers for Full Drive Encryption` by Bernard Dickens III (University of Chicago), Haryadi Gunawi (University of Chicago), Ariel J Feldman (University of Chicago), and Henry Hoffmann (University of Chicago).

(todo: flesh this README out)
(todo: advantages, disadvantages, tradeoffs, etc of this design; StrongBox is proof of concept)
(Use `make tests` to run all the tests)
(The ONLY test that works with BLFS_DEBUG_MONITOR_POWER=1 is test_buselfs!)

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
- [std=c11](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
- A device that offers or emulates an [RPMB API](https://lwn.net/Articles/682276/) (see: BLFS_RPMB_KEY and BLFS_RPMB_DEVICE)
    - *sudo access* is necessary due to RPMB integration. If you're using a usersapce emulation of some sort, sudo is not necessary.

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


### Constants

These values are configurable in `src/constants.h`:

`BLFS_CURRENT_VERSION`
The current build version (arbitrary)

`BLFS_LEAST_COMPAT_VERSION`
The absolute minimum build version of the StrongBox software whose backing store this current revision of StrongBox considers valid, e.g. backwards compatibility

`BLFS_TPM_ID`
With this version of StrongBox, `BLFS_TPM_ID` is used by the RPMB API to determine the block index within the massive (4-16MB) RPMB EMMC drive space.

`BLFS_RPMB_KEY`
The key used by RPMB.

`BLFS_RPMB_DEVICE`
Path to the RPMB device, e.g. "/dev/mmcblk0rpmb"

#define BLFS_CONFIG_ZLOG "../config/zlog_conf.conf"

#define VECTOR_GROWTH_FACTOR    2
#define VECTOR_INIT_SIZE        10

/** START: energy/power metric collection */

// XXX: Must be file path
#define BLFS_ENERGYMON_OUTPUT_PATH "/home/odroid/bd3/repos/energy-AES-1/results/strongbox-metrics.results"

/** END: energy/power metric collection */

// 0 - no debugging, log writing, or any such output
// 1U - light debugging to designated log file
// 2U - ^ and some informative messages to stdout
// 3U - ^ except now it's a clusterfuck of debug messages
#ifndef BLFS_DEBUG_LEVEL
#define BLFS_DEBUG_LEVEL 0
#endif

#ifndef BLFS_DEBUG_MONITOR_POWER
#define BLFS_DEBUG_MONITOR_POWER 0
#endif

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

typedef enum stream_cipher_e {
    sc_default,
    sc_not_impl,
    sc_chacha8,
    sc_chacha12,
    sc_chacha20,
    sc_salsa8,
    sc_salsa12,
    sc_salsa20,
    sc_aes128_ctr,
    sc_aes256_ctr,
    sc_hc128,
    sc_rabbit,
    sc_sosemanuk,
} stream_cipher_e;



