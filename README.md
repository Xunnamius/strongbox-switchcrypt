# StrongBox (internally: BuseLFS)

This is a complete rewrite of the old buselogfs code. This is a Buse + Chacha20 + Poly1305 + LFS encrypted filesystem. It uses Argon2 as its KDF. Featured in the paper [StrongBox: Confidentiality, Integrity, and Performance using Stream Ciphers for Full Drive Encryption](https://dl.acm.org/citation.cfm?id=3173183) by Bernard Dickens III (University of Chicago), Haryadi Gunawi (University of Chicago), Ariel J Feldman (University of Chicago), and Henry Hoffmann (University of Chicago).

*Note that this is a prototype implementation of the StrongBox idea. This is not production-ready code. Do not expect to be able to use this in real life, it's only a proof-of-concept for little-endian odroid XU3s. As this is not production code, do not place it anywhere near files you consider important! You've been warned!*

## Dependencies

- [zlog](https://github.com/HardySimpson/zlog)
- [libsodium](https://github.com/jedisct1/libsodium)
- [make](http://man7.org/linux/man-pages/man1/make.1.html)
- [gcc](https://gcc.gnu.org) (sorry, I'm using some GCC extensions to make life easier)
- [ruby](https://www.ruby-lang.org/en/) (required iff you're going to be running the tests)
- [OpenSSL](https://www.openssl.org) (provides swappable algorithm base)
- [energymon](https://github.com/energymon/energymon) (required iff you want energy metrics [has performance implications])
- [std=c11](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
- A device that offers or emulates an [RPMB API](https://lwn.net/Articles/682276/) is required iff you intend to test RPMB functionality. See: [BLFS_RPMB_KEY](#blfs_rpmb_key), [BLFS_RPMB_DEVICE](#blfs_rpmb_device), and [BLFS_MANUAL_GV_FALLBACK](#blfs_manual_gv_fallback).
    - *sudo access* is necessary when using RPMB functionality against an mmc device. If you're doing usersapce emulation of some sort, *sudo* is not necessary.

## Usage

```
# sb [--default-password][--backstore-size 1024][--flake-size 4096][--flakes-per-nugget 64] create nbd_device_name
# sb [--default-password][--allow-insecure-start] open nbd_device_name
# sb [--default-password][--allow-insecure-start] wipe nbd_device_name
```

Observe that `nbd_device_name` must always appear last and the desired command (`open`, `wipe`, or `create`) second to last.

For more information and some friendly? examples:

```
# sb help
```

## Building StrongBox

You may wish to run the included unit tests first before actually utilizing StrongBox. See the [Testing](#testing) section below.

`sudo` and/or root privileges are required at certain points due to ioctl calls made to privileged devices (like the RPMB).

First, of course, change directory into the StrongBox directory and `make` it:

```
# make
```

If you were running tests or compiling StrongBox from source for testing purposes or what have you—especially when using different O/DEBUG levels—you need to clean the build folder between compilation attempts, like so:

```
# make clean
# make
```

Either way, a StrongBox binary will be generated at `build/sb`, where it can be run. With your current working directory as the context, the path `../config/zlog_config.conf` must exist when running StrongBox. The repo is already set up this way when the `build` directory is the current working directory when running StrongBox.

StrongBox is by default compiled with `-O3` optimization. To compile with a different optimization level, you can use the following:

```
# make clean
# make all-O3
```
```
# make clean
# make all-O2
```
```
# make clean
# make all-O0
```

## Testing StrongBox

This prototype has only been tested on two systems: ARM Odroid XU4 and ARM Odroid XU3; Debian and Ubuntu operating systems. It's only guaranteed to work in these environments, if even that. 

Run these tests to be pretty sure (note: **these tests require ruby!**):

```
# make clean
# make pre
# make check
```

The password for all tests is always **"t"** (no quotes, of course).

You can also compile every test in the suite but not have them automatically run, which might be useful; for instance, if you wanted to step through one or more tests with gdb. You can compile them all without running them by running the following:

```
# make clean
# make tests
```

These tests are compiled without optimization. To compile these tests with optimization, you can use the following:

```
# make clean
# make tests-O3
```
```
# make clean
# make tests-O2
```
```
# make clean
# make tests-O0
```

### Available Tests

- `test_aes`
    - This test is only relevant when the [BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION](#BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION) flag is in effect.
- `test_backstore`
- `test_bitmask`
- `test_strongbox`
    - Several tests in this collection are disabled when [BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION](#BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION) flag is in effect.
- `test_crypto`
- `test_io`
- `test_mmc`
    - [BLFS_MANUAL_GV_FALLBACK](#BLFS_MANUAL_GV_FALLBACK) should be set to >= 0 to use built-in RPMB emulation. Otherwise, this and other tests that touch the RPMB will fail. Check [the flag's documentation](#BLFS_MANUAL_GV_FALLBACK) for more information.
- `test_swappable`
    - Several tests in this collection are disabled when [BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION](#BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION) flag is in effect.
- `test_vector`

Note: the **ONLY** test that works with [BLFS_DEBUG_MONITOR_POWER](#BLFS_DEBUG_MONITOR_POWER) is in effect is `test_strongbox`!

## File Structure and Internal Construction

(todo) (Don't give files that aren't direct children of test/ names like `test_XXX.c` ; Don't give files that are not auto-generated unity mocks the `mock_` prefix)

## Makefile Breakdown

(todo) (including DEBUG) (note that DEBUG mode breaks security, leaks potentially sensitive information)

## Gathering Energy Metrics

Use of this feature requires [energymon](https://github.com/energymon/energymon) to be compiled—ideally with a non-dummy default implementation—and fully installed.

(todo)

## Configuration Options

(todo) (can configure RPMB device path to be something other than /dev/mmcblk0rpmb)

### Compile Flags

Note that all compile flags must be specified with a `-D` prefix in [the actual Makefile](build/Makefile).

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

## Limitations of the Prototype

- Byte order is assumed to be **little endian**. Might have to an implement endian conversion layer touching `io.c` and `crypto.c`, perhaps using the standard functions, if this becomes an issue.
- Merkle Tree implementation has a hard upper limit (2<sup>TREE_DEPTH</sup> or 1,048,576 elements, soft limited to 524288) to the number of leaves and tree node levels 
- The `open` and `wipe` commands do not currently work, since their proper functioning wasn't necessary for gathering results. If they become germane to the research at some future point, they will be fixed.
- This prototype has only been tested on the Odroid XU3 platform with Ubuntu Trusty kernel as well as the Odroid XU4 platform with Ubuntu Xenial and no energymon support. No functionality is guaranteed whatsoever on those systems, and it's hit or miss if StrongBox will even compile, let alone function properly, on non-Odroid systems.
