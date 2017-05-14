#ifndef BLFS_CONSTANTS_H_
#define BLFS_CONSTANTS_H_

//////////////////
// Configurable //
//////////////////

#define BLFS_CURRENT_VERSION 274U
#define BLFS_LEAST_COMPAT_VERSION 274U
#define BLFS_TPM_ID 0

#define BLFS_CONFIG_ZLOG "../config/zlog_conf.conf"

// 0 - no debugging, log writing, or any such output
// 1U - light debugging to designated log file
// 2U - ^ and some informative messages to stdout
// 3U - ^ except now it's a clusterfuck of debug messages
#ifndef BLFS_DEBUG_LEVEL
#define BLFS_DEBUG_LEVEL 0
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

#include <string.h> /* strdup() */

///////////////////
// Useful Macros //
///////////////////

#if BLFS_DEBUG_LEVEL > 0
#define IFDEBUG(expression) expression
#define IFNDEBUG(expression)
#else
#define IFDEBUG(expression)
#define IFNDEBUG(expression) expression
#endif

#if BLFS_DEBUG_LEVEL > 2
#define IFDEBUG3(expression) expression
#else
#define IFDEBUG3(expression)
#endif

#define STRINGIZE_STR_FN(X) #X
#define STRINGIZE(X) STRINGIZE_STR_FN(X)

#define TRUE 1
#define FALSE 0

#define BITS_IN_A_BYTE 8
#define BYTES_IN_A_MB 1048576

#define MIN(a,b) __extension__ ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })
#define MAX(a,b) __extension__ ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })
#define CEIL(dividend,divisor) __extension__ ({ \
                                                __typeof__ (dividend) _dd = (dividend); \
                                                __typeof__ (divisor) _dr = (divisor); \
                                                _dd / _dr + (_dd % _dr > 0); \
                                             })

#define LAMBDA(return_type, function_body) \
__extension__ ({ \
                 return_type __fn__ function_body \
                 __fn__; \
               })

////////////
// Crypto //
////////////

#define BLFS_CRYPTO_BYTES_AESXTS_KEY            64U // OpenSSL AES-XTS 256-bit requires 64-bit keys (2 32-bit AES keys) 
#define BLFS_CRYPTO_BYTES_AESXTS_TWEAK          16U // OpenSSL AES-XTS 256-bit requires 16-bit IV
#define BLFS_CRYPTO_BYTES_AES_DATA_MIN          16U // XXX: OpenSSL AES-XTS 256-bit will CHOKE AND DIE!!! if passed less
#define BLFS_CRYPTO_BYTES_AES_BLOCK             16U // AES works with 16-byte blocks
#define BLFS_CRYPTO_BYTES_AES_KEY               32U // crypto_stream_aes256ctr_KEYBYTES
#define BLFS_CRYPTO_BYTES_AES_IV                16U // We use AES-256 in ECB mode with 16 byte "IV"
#define BLFS_CRYPTO_BYTES_CHACHA_BLOCK          64U // chacha outputs randomly accessible 512-bit (64-byte) blocks
#define BLFS_CRYPTO_BYTES_CHACHA_KEY            32U // crypto_stream_chacha20_KEYBYTES
#define BLFS_CRYPTO_BYTES_CHACHA_NONCE          8U  // crypto_stream_chacha20_NONCEBYTES
#define BLFS_CRYPTO_BYTES_KDF_OUT               32U // crypto_box_SEEDBYTES
#define BLFS_CRYPTO_BYTES_KDF_SALT              16U // crypto_pwhash_SALTBYTES
#define BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT         16U // crypto_onetimeauth_poly1305_BYTES
#define BLFS_CRYPTO_BYTES_TJ_HASH_OUT           16U // crypto_onetimeauth_poly1305_BYTES
#define BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY         32U // crypto_onetimeauth_poly1305_KEYBYTES; <= BLFS_CRYPTO_BYTES_KDF_OUT
#define BLFS_CRYPTO_BYTES_MTRH                  32U // HASH_LENGTH ; this x8 is also an upper bound on flakes per nugget

////////////
// Header //
////////////

// XXX: See the top of backstore.c to see the defined head section header order!
#define BLFS_HEAD_HEADER_TYPE_VERSION           0xF01U
#define BLFS_HEAD_HEADER_TYPE_SALT              0xF02U
#define BLFS_HEAD_HEADER_TYPE_MTRH              0xF04U
#define BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER      0xF08U
#define BLFS_HEAD_HEADER_TYPE_VERIFICATION      0xF10U
#define BLFS_HEAD_HEADER_TYPE_NUMNUGGETS        0xF20U
#define BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET   0xF40U
#define BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES   0xF80U
#define BLFS_HEAD_HEADER_TYPE_INITIALIZED       0xF100U
#define BLFS_HEAD_HEADER_TYPE_REKEYING          0xF200U

#define BLFS_HEAD_HEADER_BYTES_VERSION          4U  // uint32_t
#define BLFS_HEAD_HEADER_BYTES_SALT             BLFS_CRYPTO_BYTES_KDF_SALT // 16U
#define BLFS_HEAD_HEADER_BYTES_MTRH             BLFS_CRYPTO_BYTES_MTRH // 32U
#define BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER     8U  // uint64_t
#define BLFS_HEAD_HEADER_BYTES_VERIFICATION     32U // Limited by BLFS_CRYPTO_BYTES_MTRH in vendor/mt_config
#define BLFS_HEAD_HEADER_BYTES_NUMNUGGETS       4U  // uint32_t
#define BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET  4U  // uint32_t
#define BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES  4U  // uint32_t
#define BLFS_HEAD_HEADER_BYTES_INITIALIZED      1U  // uint8_t
#define BLFS_HEAD_HEADER_BYTES_REKEYING         4U  // uint32_t (holds a nugget id)

#define BLFS_HEAD_NUM_HEADERS                   10U
#define BLFS_HEAD_BYTES_KEYCOUNT                8U // uint64_t
#define BLFS_HEAD_IS_INITIALIZED_VALUE          0x3CU
#define BLFS_HEAD_WAS_WIPED_VALUE               0x3DU

///////////////
// Backstore //
///////////////

#define BLFS_BACKSTORE_FILENAME                 "./blfs-%s.bkstr"
#define BLFS_BACKSTORE_DEVICEPATH               "/dev/%s"
#define BLFS_BACKSTORE_FILENAME_MAXLEN          256

#define BLFS_BACKSTORE_CREATE_MODE_UNKNOWN      0
#define BLFS_BACKSTORE_CREATE_MODE_CREATE       1
#define BLFS_BACKSTORE_CREATE_MODE_OPEN         2
#define BLFS_BACKSTORE_CREATE_MODE_WIPE         3
#define BLFS_BACKSTORE_CREATE_MAX_MODE_NUM      BLFS_BACKSTORE_CREATE_MODE_WIPE

//////////////
// Defaults //
//////////////

#ifndef BLFS_DEFAULT_DISABLE_KEY_CACHING
#define BLFS_DEFAULT_DISABLE_KEY_CACHING        TRUE // It might be faster just to recompute...
#endif

#ifndef BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION
#define BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION FALSE // Don't even think about it
#endif

#ifndef BLFS_NO_READ_INTEGRITY
#define BLFS_NO_READ_INTEGRITY FALSE // Reduce security guarantee to AES-XTS levels
#endif

#define BLFS_DEFAULT_BYTES_FLAKE                4096U
#define BLFS_DEFAULT_BYTES_BACKSTORE            1024ULL // 1GB
#define BLFS_DEFAULT_FLAKES_PER_NUGGET          64U
#define BLFS_DEFAULT_BACKSTORE_FILE_PERMS       0666
#define BLFS_DEFAULT_PASS                       "t" // Of course, its use is not secure...

#define BLFS_BACKSTORE_DEVNAME_MAXLEN           16
#define BLFS_PASSWORD_BUF_SIZE                  1025
#define BLFS_PASSWORD_MAX_SIZE                  "1024"

///////////
// Khash //
///////////

// These don't actually have to be defined, but the symbols are used as parts
// of type names!
// #define BLFS_KHASH_NUGGET_KEY_CACHE_NAME
// #define BLFS_KHASH_HEADERS_CACHE_NAME
// #define BLFS_KHASH_KCS_CACHE_NAME
// #define BLFS_KHASH_TJ_CACHE_NAME
#define BLFS_KHASH_NUGGET_KEY_SIZE_BYTES        100

/**
 * Put a pointer into the hashmap at the location specified by key.
 */
#define KHASH_CACHE_PUT(name, hashmap, key, value_ptr) \
    __extension__ ({ int _x; khint64_t _r = kh_put(name, hashmap, key, &_x); kh_value(hashmap, _r) = value_ptr; })

#define KHASH_CACHE_PUT_HEAP(n, h, k, v_ptr) \
    __extension__ ({ int _x; khint64_t _r = kh_put(n, h, k, &_x); kh_val(h, _r) = v_ptr; kh_key(h, _r) = strdup(k); })

/**
 * Delete a key and its associated pointer value from the hashmap. This
 * macro is slightly slower than its ITRP1 version.
 */
#define KHASH_CACHE_DEL_WITH_KEY(name, hashmap, key) \
    __extension__ ({ kh_del(name, hashmap, kh_get(name, hashmap, key)); })

/**
 * Delete a key and its associated pointer value from the hashmap based on the
 * special version of the iterator received from KHASH_CACHE_EXISTS (it's +1'd).
 */
#define KHASH_CACHE_DEL_WITH_ITRP1(name, hashmap, itr) \
    __extension__ ({ kh_del(name, hashmap, itr-1); })

/**
 * Determine if the key exists (is present) in the hashmap.
 */
#define KHASH_CACHE_EXISTS(name, hashmap, key) \
    __extension__ ({ khint64_t _r = kh_get(name, hashmap, key); _r == kh_end(hashmap) ? 0 : _r + 1; })

/**
 * Grab a pointer from the hashmap corresponding to the provided key. This
 * macro is slightly slower than its ITRP1 version.
 */
#define KHASH_CACHE_GET_WITH_KEY(name, hashmap, key) \
    __extension__ ({ kh_value(hashmap, kh_get(name, hashmap, key)); })

/**
 * Grab a pointer from the hashmap corresponding to a special version of the
 * iterator received from KHASH_CACHE_EXISTS (it's +1'd).
 */
#define KHASH_CACHE_GET_WITH_ITRP1(hashmap, itr) \
    __extension__ ({ kh_value(hashmap, itr-1); })

////////////////////////
// Exceptional Events //
////////////////////////

// See: config/cexception_configured.h
#include "cexception_configured.h"

#endif /* BLFS_CONSTANTS_H_ */
