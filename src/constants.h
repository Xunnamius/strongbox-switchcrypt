#ifndef BLFS_CONSTANTS_H
#define BLFS_CONSTANTS_H

#include <sodium.h>

//////////////////
// Configurable //
//////////////////

#define BLFS_CURRENT_VERSION 0.1.0
#define BLFS_LEAST_COMPAT_VERSION 0.1.0

#define BLFS_CONFIG_ZLOG "../config/zlog_conf.conf"

// 0 - no debugging, log writing, or any such output
// 1U - light debugging to designated log file
// 2U - ^ and some informative messages to stdout
// 3U - ^ except now it's a clusterfuck of debug messages
#ifndef BLFS_DEBUG_LEVEL
#define BLFS_DEBUG_LEVEL 3U
#endif

///////////////////
// Useful Macros //
///////////////////

#if BLFS_DEBUG_LEVEL > 0
#define IFDEBUG(expression) expression
#else
#define IFDEBUG(expression)
#endif

#define STRINGIZE_STR_FN(X) #X
#define STRINGIZE(X) STRINGIZE_STR_FN(X)

#define TRUE 1
#define FALSE 0

////////////
// Crypto //
////////////

#define BLFS_CRYPTO_BYTES_CHACHA_BLOCK          64U // chacha outputs randomly accessible 512-bit blocks
#define BLFS_CRYPTO_BYTES_CHACHA_KEY            32U // crypto_stream_chacha20_KEYBYTES
#define BLFS_CRYPTO_BYTES_CHACHA_NONCE          8U // crypto_stream_chacha20_NONCEBYTES
#define BLFS_CRYPTO_BYTES_KDF_OUT               32U // crypto_box_SEEDBYTES
#define BLFS_CRYPTO_BYTES_KDF_SALT              16U // crypto_pwhash_SALTBYTES
#define BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT         16U // crypto_onetimeauth_poly1305_BYTES
#define BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY         32U // crypto_onetimeauth_poly1305_KEYBYTES
#define BLFS_CRYPTO_BYTES_MTRH                  32U // HASH_LENGTH ; this x8 is also an upper bound on flakes per nugget

////////////
// Header //
////////////

#define BLFS_HEAD_HEADER_TYPE_VERSION           0x01U
#define BLFS_HEAD_HEADER_TYPE_SALT              0x02U
#define BLFS_HEAD_HEADER_TYPE_MTRH              0x04U
#define BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER      0x08U
#define BLFS_HEAD_HEADER_TYPE_VERIFICATION      0x10U
#define BLFS_HEAD_HEADER_TYPE_NUMNUGGETS        0x20U
#define BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET   0x40U
#define BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES   0x80U
#define BLFS_HEAD_HEADER_TYPE_INITIALIZED       0x100U
#define BLFS_HEAD_HEADER_TYPE_REKEYING          0x200U

#define BLFS_HEAD_HEADER_BYTES_VERSION          4U  // uint32_t
#define BLFS_HEAD_HEADER_BYTES_SALT             BLFS_CRYPTO_BYTES_KDF_SALT
#define BLFS_HEAD_HEADER_BYTES_MTRH             BLFS_CRYPTO_BYTES_MTRH
#define BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER     8U  // uint64_t
#define BLFS_HEAD_HEADER_BYTES_VERIFICATION     128U
#define BLFS_HEAD_HEADER_BYTES_NUMNUGGETS       4U  // uint32_t
#define BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET  4U  // uint32_t
#define BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES  4U  // uint32_t
#define BLFS_HEAD_HEADER_BYTES_INITIALIZED      1U  // uint8_t
#define BLFS_HEAD_HEADER_BYTES_REKEYING         1U  // uint8_t

#define BLFS_HEAD_OFFSET_BEGIN                  0 // the beginning of the world!

///////////////
// Backstore //
///////////////

#define BLFS_BACKSTORE_FILENAME "./blfs-%s.bkstr"

//////////////
// Defaults //
//////////////

#define BLFS_DEFAULT_BYTES_FLAKE                4096U
#define BLFS_DEFAULT_BYTES_BACKSTORE            1073741824ULL // 1GB
#define BLFS_DEFAULT_FLAKES_PER_NUGGET          256U
#define BLFS_DEFAULT_ENABLE_STRUCT_CACHING      TRUE

///////////
// Flags //
///////////

#define BLFS_FLAG_TEST_MODE                     0x01U
#define BLFS_FLAG_FORCE_CLEAN_START             0x02U
#define BLFS_FLAG_JOURNALING_MODE_ORDERED       0x04U
#define BLFS_FLAG_JOURNALING_MODE_FULL          0x08U
#define BLFS_FLAG_CUSTOM_BYTES_FLAKE            0x10U
#define BLFS_FLAG_CUSTOM_BYTES_BACKSTORE        0x20U
#define BLFS_FLAG_CUSTOM_FLAKES_PER_NUGGET      0x40U

////////////////////////
// Exceptional Events //
////////////////////////

// See: config/cexception_configured.h
#include "cexception_configured.h"

#endif /* BLFS_CONSTANTS_H */
