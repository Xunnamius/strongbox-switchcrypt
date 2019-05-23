#ifndef BLFS_CONSTANTS_H_
#define BLFS_CONSTANTS_H_

//////////////////
// Configurable //
//////////////////

#define BLFS_CURRENT_VERSION 600U
#define BLFS_LEAST_COMPAT_VERSION 600U

// ! These would likely be non-static irl
#define BLFS_RPMB_KEY "thirtycharactersecurecounterkey!"
#define BLFS_RPMB_DEVICE "/dev/mmcblk0rpmb"

#define BLFS_CONFIG_ZLOG "../config/zlog_conf.conf"

// ! When adding new command line flags, don't forget to update this!
#define MAX_NUM_ARGC 20

#define VECTOR_GROWTH_FACTOR    2
#define VECTOR_INIT_SIZE        10

// 0 - no debugging, log writing, or any such output
// 1U - light debugging to designated log file
// 2U - ^ and some informative messages to stdout
// 3U - ^ with the addition that every single function call is now logged
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

////////////////////
// Cipher Choices //
////////////////////

// ? These are the valid values for the --cipher CLI flag

// ! Note: we are limited to 255 cipher implementations (see: header size)
typedef enum swappable_cipher_e {
    sc_default                  =1,
    sc_not_impl                 =2,
    sc_chacha8_neon             =3,
    sc_chacha12_neon            =4,
    sc_chacha20_neon            =5,
    sc_chacha20                 =6,
    sc_salsa8                   =7,
    sc_salsa12                  =8,
    sc_salsa20                  =9,
    sc_aes128_ctr               =10,
    sc_aes256_ctr               =11,
    sc_hc128                    =12, // ?? Slow because estream impl is low (4 blks/op) throughput?
    sc_rabbit                   =13,
    sc_sosemanuk                =14,
    sc_freestyle_fast           =15,
    sc_freestyle_balanced       =16,
    sc_freestyle_secure         =17,
    sc_aes256_xts               =18,
} swappable_cipher_e;

typedef enum swap_strategy_e {
    swap_default        = 1,
    swap_immediate      = 2,
    swap_forward        = 3,
    swap_aggressive     = 4,
    swap_opportunistic  = 5,
    swap_mirrored       = 6,
    swap_disabled       = 7,
    swap_not_impl       = 8, // ! Make sure this is always the last one
} swap_strategy_e;

typedef enum usecase_e {
    uc_default              = 1,
    uc_secure_regions       = 2,
    uc_fixed_energy         = 3,
    uc_offset_slowdown      = 4,
    uc_lockdown             = 5,
    uc_auto_locations       = 6,
    uc_disabled             = 7,
    uc_no_impl              = 8, // ! Make sure this is always the last one
} usecase_e;

#include <string.h> /* strdup() */

///////////////////
// Useful Macros //
///////////////////

#define SWAP_WHILE_READ 0
#define SWAP_WHILE_WRITE 1

#if BLFS_DEBUG_LEVEL > 0
#define IFDEBUG(expression) expression
#define IFNDEBUG(expression)
#else
#define IFDEBUG(expression)
#define IFNDEBUG(expression) expression
#endif

#if BLFS_DEBUG_LEVEL > 1
#define IFDEBUG2(expression) expression
#else
#define IFDEBUG2(expression)
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

#define CEIL(dividend,divisor) __extension__    \
    ({                                          \
        __typeof__ (dividend) _dd = (dividend); \
        __typeof__ (divisor) _dr = (divisor);   \
        _dd / _dr + (_dd % _dr > 0);            \
    })

#define LAMBDA(return_type, function_body) __extension__    \
    ({                                                      \
        return_type __fn__ function_body                    \
        __fn__;                                             \
    })

// ! Only works for stack initialized arrays!
#define COUNT(x) __extension__ ({ (sizeof(x) / sizeof((x)[0])); })

////////////
// Crypto //
////////////

#define BLFS_CRYPTO_BYTES_AESXTS_KEY            64U // OpenSSL AES-XTS 256-bit requires 64-bit keys (2 32-bit AES keys) 
#define BLFS_CRYPTO_BYTES_AESXTS_TWEAK          16U // OpenSSL AES-XTS 256-bit requires 16-bit IV
#define BLFS_CRYPTO_BYTES_AESXTS_DATA_MIN       16U // ! OpenSSL AES-XTS 256-bit will CHOKE AND DIE!!! if passed less
#define BLFS_CRYPTO_BYTES_FSTYLE_INIT_HASHES    56U // see src/cipher/_freestyle.c
#define BLFS_CRYPTO_BYTES_KDF_OUT               32U // !! cannot be changed without several changes to swappable.c // crypto_box_SEEDBYTES
#define BLFS_CRYPTO_BYTES_KDF_SALT              16U // crypto_pwhash_SALTBYTES
#define BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT         16U // crypto_onetimeauth_poly1305_BYTES
#define BLFS_CRYPTO_BYTES_STRUCT_HASH_OUT       16U // crypto_onetimeauth_poly1305_BYTES
#define BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY         32U // crypto_onetimeauth_poly1305_KEYBYTES; <= BLFS_CRYPTO_BYTES_KDF_OUT
#define BLFS_CRYPTO_BYTES_MTRH                  32U // HASH_LENGTH ; this x8 is also an upper bound on flakes per nugget
#define BLFS_CRYPTO_RPMB_KEY                    32U // See spec
#define BLFS_CRYPTO_RPMB_MAC_OUT                32U // See spec
#define BLFS_CRYPTO_RPMB_BLOCK                  256U // See spec

#define BLFS_CRYPTO_BYTES_AES128_BLOCK          16U // OpenSSL AES-128 outputs 16-byte blocks
#define BLFS_CRYPTO_BYTES_AES128_KEY            16U // AES 128 key size
#define BLFS_CRYPTO_BYTES_AES128_IV             16U // We use AES-128 in ECB mode with 16 byte "IV"
#define BLFS_CRYPTO_BYTES_AES256_BLOCK          16U // OpenSSL AES-256 outputs 16-byte blocks
#define BLFS_CRYPTO_BYTES_AES256_KEY            32U // AES 256 key size
#define BLFS_CRYPTO_BYTES_AES256_IV             32U // We use AES-256 in ECB mode with 32 byte "IV"
#define BLFS_CRYPTO_BYTES_CHACHA20_BLOCK        64U // Chacha20/20 outputs randomly accessible 512-bit (64-byte) blocks
#define BLFS_CRYPTO_BYTES_CHACHA20_KEY          32U // crypto_stream_chacha20_KEYBYTES
#define BLFS_CRYPTO_BYTES_CHACHA20_NONCE        8U  // crypto_stream_chacha20_NONCEBYTES
#define BLFS_CRYPTO_BYTES_CHACHA20N_BLOCK       64U // Chacha20/20 outputs randomly accessible 512-bit (64-byte) blocks
#define BLFS_CRYPTO_BYTES_CHACHA20N_KEY         32U // crypto_stream_chacha20_KEYBYTES
#define BLFS_CRYPTO_BYTES_CHACHA20N_NONCE       8U  // crypto_stream_chacha20_NONCEBYTES
#define BLFS_CRYPTO_BYTES_CHACHA12N_BLOCK       64U // Chacha20/12 outputs randomly accessible 512-bit (64-byte) blocks
#define BLFS_CRYPTO_BYTES_CHACHA12N_KEY         32U // (cipher defined)
#define BLFS_CRYPTO_BYTES_CHACHA12N_NONCE       8U  // (cipher defined)
#define BLFS_CRYPTO_BYTES_CHACHA8N_BLOCK        64U // Chacha20/8 outputs randomly accessible 512-bit (64-byte) blocks
#define BLFS_CRYPTO_BYTES_CHACHA8N_KEY          32U // (cipher defined)
#define BLFS_CRYPTO_BYTES_CHACHA8N_NONCE        8U  // (cipher defined)
#define BLFS_CRYPTO_BYTES_SALSA20_BLOCK         64U // Salsa20/20 outputs 64-byte blocks
#define BLFS_CRYPTO_BYTES_SALSA20_KEY           32U // Salsa20/20 uses 32 byte keys
#define BLFS_CRYPTO_BYTES_SALSA20_IV            8U  // Salsa20/20 uses 8 byte IV
#define BLFS_CRYPTO_BYTES_SALSA12_BLOCK         64U // Salsa20/12 outputs 64-byte blocks
#define BLFS_CRYPTO_BYTES_SALSA12_KEY           32U // Salsa20/12 uses 32 byte keys
#define BLFS_CRYPTO_BYTES_SALSA12_IV            8U  // Salsa20/12 uses 8 byte IV
#define BLFS_CRYPTO_BYTES_SALSA8_BLOCK          64U // Salsa20/8 outputs 64-byte blocks
#define BLFS_CRYPTO_BYTES_SALSA8_KEY            32U // Salsa20/8 uses 32 byte keys
#define BLFS_CRYPTO_BYTES_SALSA8_IV             8U  // Salsa20/8 uses 8 byte IV
#define BLFS_CRYPTO_BYTES_RABBIT_BLOCK          16U // Rabbit outputs 16-byte blocks
#define BLFS_CRYPTO_BYTES_RABBIT_KEY            16U // Rabbit uses 16 byte keys
#define BLFS_CRYPTO_BYTES_RABBIT_IV             8U  // Rabbit uses 8 byte IV
#define BLFS_CRYPTO_BYTES_HC128_BLOCK           4U  // HC-128 outputs 4-byte blocks
#define BLFS_CRYPTO_BYTES_HC128_KEY             16U // HC-128 uses 16 byte keys
#define BLFS_CRYPTO_BYTES_HC128_IV              16U // HC-128 uses 16 byte IV
#define BLFS_CRYPTO_BYTES_SOSEK_BLOCK           16U // Sosemanuk outputs 16-byte blocks
#define BLFS_CRYPTO_BYTES_SOSEK_KEY             16U // Sosemanuk uses 16 byte keys
#define BLFS_CRYPTO_BYTES_SOSEK_IV              16U // Sosemanuk uses 16 byte IV
#define BLFS_CRYPTO_BYTES_FSTYLE_BLOCK          64U // Freestyle outputs 64-byte blocks
#define BLFS_CRYPTO_BYTES_FSTYLE_KEY            32U // Freestyle uses 32 byte keys
#define BLFS_CRYPTO_BYTES_FSTYLE_IV             12U // Freestyle uses 12 byte IV (nonce)

////////////
// Header //
////////////

// ? See the top of backstore.c to see the defined head section header order!
#define BLFS_HEAD_HEADER_TYPE_VERSION           0xF01U
#define BLFS_HEAD_HEADER_TYPE_SALT              0xF02U
#define BLFS_HEAD_HEADER_TYPE_MTRH              0xF04U
#define BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER      0xF08U
#define BLFS_HEAD_HEADER_TYPE_VERIFICATION      0xF10U
#define BLFS_HEAD_HEADER_TYPE_NUMNUGGETS        0xF20U
#define BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET   0xF40U
#define BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES   0xF80U
#define BLFS_HEAD_HEADER_TYPE_INITIALIZED       0xF100U

#define BLFS_HEAD_HEADER_BYTES_VERSION          4U  // uint32_t
#define BLFS_HEAD_HEADER_BYTES_SALT             BLFS_CRYPTO_BYTES_KDF_SALT // 16U
#define BLFS_HEAD_HEADER_BYTES_MTRH             BLFS_CRYPTO_BYTES_MTRH // 32U
#define BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER     8U  // uint64_t
#define BLFS_HEAD_HEADER_BYTES_VERIFICATION     32U // limited by BLFS_CRYPTO_BYTES_MTRH in vendor/mt_config
#define BLFS_HEAD_HEADER_BYTES_NUMNUGGETS       4U  // uint32_t
#define BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET  4U  // uint32_t
#define BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES  4U  // uint32_t
#define BLFS_HEAD_HEADER_BYTES_INITIALIZED      1U  // uint8_t

#define BLFS_HEAD_NUM_HEADERS                   9U
#define BLFS_HEAD_BYTES_KEYCOUNT                8U // uint64_t
#define BLFS_HEAD_MAX_FLAKESIZE_BYTES           16384U
#define BLFS_HEAD_MIN_FLAKESIZE_BYTES           512U
#define BLFS_HEAD_MAX_FLAKESPERNUGGET           256U
#define BLFS_HEAD_MIN_FLAKESPERNUGGET           8U
#define BLFS_HEAD_IS_INITIALIZED_VALUE          0x3CU
#define BLFS_HEAD_WAS_WIPED_VALUE               0x3DU

#define BLFS_GLOBAL_CORRECTNESS_ALL_GOOD        0
#define BLFS_GLOBAL_CORRECTNESS_POTENTIAL_CRASH 1 // potential crash occurred; c == d + 1
#define BLFS_GLOBAL_CORRECTNESS_ILLEGAL_MANIP   2 // bad manipulation occurred; c < d or c > d + 1

#ifndef BLFS_MANUAL_GV_FALLBACK
#define BLFS_MANUAL_GV_FALLBACK -1
#endif

// ! BLFS_HEAD_BYTES_NUGGET_METADATA is deprecated—now calculated dynamically in calc_handle; see swappable.h

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
#define BLFS_DEFAULT_DISABLE_KEY_CACHING        TRUE // It might be faster just to recompute?
#endif

#define BLFS_DEFAULT_BYTES_FLAKE                4096U
#define BLFS_DEFAULT_BYTES_BACKSTORE            1024ULL // 1GB
#define BLFS_DEFAULT_FLAKES_PER_NUGGET          64U
#define BLFS_DEFAULT_BACKSTORE_FILE_PERMS       0666
#define BLFS_DEFAULT_PASS                       "t" // Of course, its use is not secure...

#define BLFS_BACKSTORE_DEVNAME_MAXLEN           16
#define BLFS_PASSWORD_BUF_SIZE                  1025
#define BLFS_PASSWORD_MAX_SIZE                  "1024"
#define BLFS_MAX_SC_FNS                         255 // limited by uint8_t max

#define BLFS_DEFAULT_TPM_ID                     5U // Of course, one should consider changing this...

#ifndef BLFS_SV_QUEUE_INCOMING_NAME
#define BLFS_SV_QUEUE_INCOMING_NAME             "/incoming.strongbox.xunn.io"
#endif
#ifndef BLFS_SV_QUEUE_OUTGOING_NAME
#define BLFS_SV_QUEUE_OUTGOING_NAME             "/outgoing.strongbox.xunn.io"
#endif
#define BLFS_SV_QUEUE_PERM                      0777 // ! WARNING: very permissive!
#define BLFS_SV_QUEUE_MAX_MESSAGES              30
#define BLFS_SV_MESSAGE_SIZE_BYTES              256U // bytes; 1 byte op || 255 byte payload
#define BLFS_SV_MESSAGE_DEFAULT_PRIORITY        0 // uint; must be < ~30k. 0 - 30 recommended

#define BLFS_NUM_ACTIVE_CIPHERS                 2 // will probably never not be 2
#define BLFS_SWAP_AGGRESSIVENESS                1U // unit is "nuggets," might want to keep this small...

/////////
// MMC //
/////////

#define WP_BLKS_PER_QUERY                       32

#define USER_WP_PERM_PSWD_DIS                   0x80
#define USER_WP_CD_PERM_WP_DIS                  0x40
#define USER_WP_US_PERM_WP_DIS                  0x10
#define USER_WP_US_PWR_WP_DIS                   0x08
#define USER_WP_US_PERM_WP_EN                   0x04
#define USER_WP_US_PWR_WP_EN                    0x01
#define USER_WP_CLEAR                           (USER_WP_US_PERM_WP_DIS | USER_WP_US_PWR_WP_DIS \
                                                    | USER_WP_US_PERM_WP_EN | USER_WP_US_PWR_WP_EN)

#define WPTYPE_NONE                             0
#define WPTYPE_TEMP                             1
#define WPTYPE_PWRON                            2
#define WPTYPE_PERM                             3

///////////
// Khash //
///////////

// These don't actually have to be defined, but the symbols are used as parts
// of type names!
// #define BLFS_KHASH_NUGGET_KEY_CACHE_NAME
// #define BLFS_KHASH_HEADERS_CACHE_NAME
// #define BLFS_KHASH_KCS_CACHE_NAME
// #define BLFS_KHASH_TJ_CACHE_NAME
// #define BLFS_KHASH_MD_CACHE_NAME
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
 * special version of the iterator received from KHASH_CACHE_EXISTS (it's -1'd).
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
 * iterator received from KHASH_CACHE_EXISTS (it's -1'd).
 */
#define KHASH_CACHE_GET_WITH_ITRP1(hashmap, itr) \
    __extension__ ({ kh_value(hashmap, itr-1); })

////////////////////////
// Exceptional Events //
////////////////////////

// See: config/cexception_configured.h
#include "cexception_configured.h"

#endif /* BLFS_CONSTANTS_H_ */
