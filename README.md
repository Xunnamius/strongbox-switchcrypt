# StrongBox (internally: BuseLFS)

(TODO: update the documentation to reflect recent changes as of version 500)

This is a complete rewrite of the old buselogfs code. This is a Buse + Chacha20 + Poly1305 + LFS encrypted filesystem. It uses Argon2 as its KDF. Featured in the paper [StrongBox: Confidentiality, Integrity, and Performance using Stream Ciphers for Full Drive Encryption](https://dl.acm.org/citation.cfm?id=3173183) by Bernard Dickens III (University of Chicago), Haryadi Gunawi (University of Chicago), Ariel J Feldman (University of Chicago), and Henry Hoffmann (University of Chicago).

> *Note that this is a prototype implementation of the StrongBox idea. This is not production-ready code. Do not expect to be able to use this in real life, it's only a proof-of-concept for little-endian odroid XU3s. As this is not production code, do not place it anywhere near files you consider important! You've been warned!*

## Dependencies

- Some sort of [ARM](https://www.arm.com/) device, preferably an [Odroid](https://www.hardkernel.com/main/main.php)
- [ARM NEON](https://developer.arm.com/technologies/neon) CPU feature (`cat /proc/cpuinfo | grep -i neon`)
- [zlog](https://github.com/HardySimpson/zlog)
- [libsodium](https://github.com/jedisct1/libsodium)
- [make](http://man7.org/linux/man-pages/man1/make.1.html)
- libbsd-dev (provides `arc4random()` and `arc4random_uniform()`; required by [`sc_freestyle`](#usage))
- [gcc](https://gcc.gnu.org) (sorry, I'm using some GCC extensions to make life easier)
- [ruby](https://www.ruby-lang.org/en/) (required iff you're going to be running the tests)
- [OpenSSL](https://www.openssl.org) (provides swappable algorithm base)
- [energymon](https://github.com/energymon/energymon) (required iff you want energy metrics **[currently hardcode disabled]**)
- [std=c11](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
- Assumes 32-bit `int`, 64-bit `long long` (due to [`sc_chacha20_alt`](#usage))
- A device that offers or emulates an [RPMB API](https://lwn.net/Articles/682276/) is required iff you intend to test RPMB functionality. See: [BLFS_RPMB_KEY](#blfs_rpmb_key), [BLFS_RPMB_DEVICE](#blfs_rpmb_device), and [BLFS_MANUAL_GV_FALLBACK](#blfs_manual_gv_fallback).
    - *sudo access* is necessary when using RPMB functionality against an mmc device. If you're doing usersapce emulation of some sort, *sudo* is not necessary.

## Usage

> Note that, as of this version, the `open` and `wipe` commands have not yet been fully implemented, so don't try to use them.

```
# sb [--default-password][--backstore-size 1024][--flake-size 4096][--flakes-per-nugget 64][--cipher sc_default][--swap-cipher sc_default][--swap-strategy swap_default][--support-uc uc_default][--tpm-id 5] create nbd_device_name

# sb [--default-password][--allow-insecure-start] open nbd_device_name
# sb [--default-password][--allow-insecure-start] wipe nbd_device_name
```

Observe that `nbd_device_name` must always appear last and the desired command
(`open`, `wipe`, or `create`) second to last.

> Note that `16384 >= flake-size >= 512` and `256 >= flakes-per-nugget >= 8`. For best performance, both should be powers of 2. Defaults are `4096` and `64` respectively.

> Further, the following must hold: `backstore-size >= flake-size * flakes-per-nugget + A`. `A` is equal to `total-number-of-nuggets * (greatest-cipher-md-requested-bytes-per-flake + 1)` but its ultimate value depends on `flake-size` and `flakes-per-nugget`. Hence, the formula in the previous paragraph is more important.

Ciphers available for the `--cipher` and `--swap-cipher` are:

- `sc_default` (this is synonymous with `sc_chacha20`)
- `sc_chacha8`
- `sc_chacha12`
- `sc_chacha20`
- `sc_chacha20_alt`
- `sc_salsa8`
- `sc_salsa12`
- `sc_salsa20`
- `sc_aes128_ctr`
- `sc_aes256_ctr`
- `sc_hc128`
- `sc_rabbit`
- `sc_sosemanuk`
- `sc_freestyle`
- `sc_not_impl`

You can see these options defined in [constants.h](src/constants.h). Note that
`sc_chachaX_neon` are alternative ARM NEON optimized implementations of ChaCha20
by [floodyberry](https://github.com/floodyberry/chacha-opt).

Swap strategies available for `--swap-strategy` are:

- `swap_default` (this is synonymous with `swap_disabled`)
- `swap_forward`
- `swap_rolling`
- `swap_aggressive`
- `swap_immediate`
- `swap_opportunistic`
- `swap_disabled`
- `swap_not_impl`

You can see these options defined in [constants.h](src/constants.h).

Explicit support for the following experimental use cases (uc) is available:

- `uc_default` (this is synonymous with `uc_disabled`)
- `uc_secure_regions`
- `uc_secure_nuggets`
- `uc_perf_agreement`
- `uc_fixed_energy`
- `uc_opportunistic_crypt`
- `uc_disabled`
- `uc_no_impl`

You can see these options defined in [constants.h](src/constants.h). Note that these options are meaningless if the swap strategy is set to `swap_disabled`.

> (TODO: flesh this section out with explanations of use cases, swap strategies, explaining SIGHUP <=> switching, etc)

For more information and some friendly? examples:

```
# sb help
```

## Building StrongBox

You may wish to run the included unit tests first before actually utilizing StrongBox. See the [Testing](#testing-strongbox) section below.

`sudo` and/or root privileges are required at certain points due to ioctl calls made to privileged devices (like the RPMB).

First, of course, change directory into the StrongBox directory and `make` it:

```
# make
```

If you were running tests or compiling StrongBox from source for testing purposes or what have you—especially when using different O/DEBUG levels—you need to clean the `build/` directory between compilation attempts, like so:

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

Run these tests (with `build/` as cwd) to be pretty sure. Note: **these tests require ruby!**:

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
    - This test is only relevant when the [BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION](#blfs_badbadnotgood_use_aesxts_emulation) flag is in effect.
- `test_backstore`
- `test_bitmask`
- `test_strongbox`
    - *Many* tests in this collection are disabled when the [BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION](#blfs_badbadnotgood_use_aesxts_emulation) flag is in effect.
- `test_crypto`
    - Several tests in this collection are disabled when the [BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION](#blfs_badbadnotgood_use_aesxts_emulation) flag is in effect.
- `test_io`
- `test_mmc`
    - [BLFS_MANUAL_GV_FALLBACK](#blfs_manual_gv_fallback) should be set to >= 0 to use built-in RPMB emulation. Otherwise, this and other tests that touch the RPMB (i.e. most tests) will fail if you don't have an RPMB-aware and configured device. Check [the flag's documentation](#blfs_manual_gv_fallback) for more information.
- `test_swappable`
    - Several tests in this collection are disabled when the [BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION](#blfs_badbadnotgood_use_aesxts_emulation) flag is in effect.
- `test_vector`

> Note: the **ONLY** test that works with [BLFS_DEBUG_MONITOR_POWER](#blfs_debug_monitor_power) is in effect is `test_strongbox`!

## File Structure and Internal Construction

```
.
├── build
│   └── test -> ../test
├── config
├── src
├── test
└── vendor
    ├── cmock
    ├── energymon
    ├── libestream
    ├── merkle-tree
    └── unity
```

- `build/` is where all the transient results of the Makefile process will go. `make clean` will clear out this directory (excluding the `build/test/` symlink and `build/Makefile`).
- `config/` is where the Ruby mock, zlog, cexception, and unity_runner configs are placed, among others.
- `src/` is where the StrongBox source lives.
- `test/` is where the corresponding StrongBox unit tests live.
- `vendor/` is where all unmanaged third party code is placed.

Considerations:
- Don't give files that aren't direct children of `test/` names like `test_X.c`
- Don't give files that are not auto-generated unity mocks the `mock_` prefix

## Gathering Energy Metrics

StrongBox is designed to capture energy usage data (energy, power, duration) while operating, though it is disabled by default. You can enable this behavior with the [BLFS_DEBUG_MONITOR_POWER](#blfs_debug_monitor_power) flag. Use of this feature requires [energymon](https://github.com/energymon/energymon) to be compiled—ideally with a non-dummy default implementation—and fully installed.

> Note that collection of data about StrongBox's energy use likely has some performance implications.

## Important Compile Flags

These are the most interesting flags available when compiling StrongBox. All compile flags must be specified with a `-D` prefix in [the actual Makefile](build/Makefile).

#### **BLFS_DEBUG_LEVEL**

This setting determines the verbosity of StrongBox's debug output. By default, it is off (0). The highest recognized debug level is 3U. Debug files will be output to `/tmp/blfs_level_$BLFS_DEBUG_LEVEL_$DEVICE_FRAG` where `$DEVICE_FRAG` (*not a shell/env var*) is equal to some reference to [`nbd_device_name`](#usage).

`BLFS_DEBUG_LEVEL=0` => debug is off  
`BLFS_DEBUG_LEVEL=1` => light debugging to designated log file  
`BLFS_DEBUG_LEVEL=2` => `BLFS_DEBUG_LEVEL=1` and some informative messages to stdout  
`BLFS_DEBUG_LEVEL=3` => `BLFS_DEBUG_LEVEL=2` with the addition that every single function call is now logged

> **Note that BLFS_DEBUG_LEVEL > 0 breaks security and leaks potentially sensitive information!**

#### **BLFS_DEBUG_MONITOR_POWER**

`BLFS_DEBUG_MONITOR_POWER=1` enables this debug flag while `=0` disables it (default). When enabled, StrongBox will begin logging energy/power/duration data to the log. Enabling this has some performance implications.

#### **BLFS_MANUAL_GV_FALLBACK**

`BLFS_MANUAL_GV_FALLBACK` >= 0 enables this debug flag while `=-1` disables it (default). When `=-1`, StrongBox will assume it can find a suitable RPMB device at the [configured location](#blfs_rpmb_device) and will query it. When `!=-1`, StrongBox will skip any and all I/O accesses to any RPMB device and will instead short circuit and return the value of `BLFS_MANUAL_GV_FALLBACK`.

Valid return values (and thus valid values for `BLFS_MANUAL_GV_FALLBACK`) are:
- `BLFS_GLOBAL_CORRECTNESS_ALL_GOOD` (0), which indicates success
- `BLFS_GLOBAL_CORRECTNESS_POTENTIAL_CRASH` (1), which indicates a potential crash
- `BLFS_GLOBAL_CORRECTNESS_ILLEGAL_MANIP` (2), which indicates a patently illegal integrity violation

## Important Configuration Constants

While not exhaustive, these are the most important configuration constants available when compiling and executing StrongBox. Most of these values are configurable in [src/constants.h](src/constants.h):

#### **BLFS_CURRENT_VERSION**
The current build version (arbitrary number).

#### **BLFS_LEAST_COMPAT_VERSION**
The absolute minimum build version of the StrongBox software whose backing store this current revision of StrongBox considers valid, e.g. backwards compatibility.

#### **BLFS_RPMB_KEY**
The key used by RPMB. In future versions of StrongBox, should they come to exist, this may not be the case (i.e. it's handled automatically/via TPM). **Must be exactly thirty characters!**

#### **BLFS_RPMB_DEVICE**
Valid Path string to the RPMB device, e.g. "/dev/mmcblk0rpmb" (default). In future versions of StrongBox, should they come to exist, this may be deprecated in favor of automatically discovery.

#### **BLFS_CONFIG_ZLOG**
Path to your [zlog configuration file](https://github.com/HardySimpson/zlog/blob/master/doc/GettingStart-EN.txt).

#### **BLFS_ENERGYMON_OUTPUT_PATH**
If you've enabled [energy metrics gathering](#blfs_debug_monitor_power), this must be a valid file path string (file need not exist yet).

#### **VECTOR_GROWTH_FACTOR**

Controls the growth factor of internal bit vectors. Defaults to 2.

#### **VECTOR_INIT_SIZE**

Controls the initial size of internal bit vectors. Defaults to 10.

#### **BLFS_CONFIG_ZLOG**

This must be a valid file path string (file need not exist yet) to your zlog configuration file. Defaults to `../config/zlog_conf.conf`.

#### **BLFS_BACKSTORE_FILENAME**

Path to the backing store file that will be generated on run. Defaults to `./blfs-%s.bkstr`. Exactly one `%s` is necessary.

#### **BLFS_BACKSTORE_DEVICEPATH**

Path to the NBD pseudo-device that will be generated on run. Defaults to `/dev/%s`. Exactly one `%s` is necessary.

## Prototypical Limitations and Potential Pitfalls

- Byte order is assumed to be **little endian**. Might have to an implement endian conversion layer touching `io.c` and `crypto.c`, perhaps using the standard functions, if this becomes an issue.
- Merkle Tree implementation has a hard upper limit (2<sup>TREE_DEPTH</sup> or 1,048,576 elements, soft limited to 524288) to the number of leaves and tree node levels 
- The `open` and `wipe` commands do not currently work, since their proper functioning wasn't necessary for gathering results. If they become germane to the research at some future point, they will be fixed.
- This prototype has only been tested on the Odroid XU3 platform with Ubuntu Trusty kernel as well as the Odroid XU4 platform with Ubuntu Xenial and no energymon support. No functionality is guaranteed whatsoever on those systems, and it's hit or miss if StrongBox will even compile, let alone function properly, on non-odroid systems.
- If you're going to add a new cipher to the collection, be sure to update `src/ciphers.h` and add corresponding source and header files to `src/cipher/`. Also add a new enum entry in `src/constants.h` and add new connective tissue for your cipher to `src/swappable.c`. Finally, don't forget to add your cipher's unit tests to `test/test_swappable.c`.
- While the OpenSSL linkage and the other specialized cipher versions are specifically optimized for ARM NEON/ARMv6-32 CPU features, neither libsodium nor the estream profile ciphers nor freestyle are specially optimized. StrongBox is also a single-threaded application. On the other hand, dm-crypt has the benefit of ARM NEON/ARMv6-32 hardware optimizations as well as parallelization across CPUs.
- `--flake-size` must be a power greater than or equal to 64 and, for best performance, should be some power of 2.
