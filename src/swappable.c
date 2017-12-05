/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include "swappable.h"
#include "crypto.h"

#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include "openssl/aes.h"
#include "hc-128.h"
#include "rabbit.h"
#include "salsa20.h"
#include "sosemanuk.h"

/**
 * This struct represents the execution context of a generic stream cipher (sc).
 */
typedef struct sc_context_t {
    const char * output_name;
    const uint64_t output_size_bytes;
    uint8_t * crypted_data;
    const uint8_t * data;
    const uint32_t data_length;
    const uint8_t * nugget_key;
    const uint64_t kcs_keycount;
    const uint64_t nugget_internal_offset;

    void (*data_handle)(void *, // XXX: really sc_context_t *
                        uint64_t,
                        uint64_t,
                        uint64_t,
                        uint64_t,
                        uint64_t,
                        const uint8_t * const,
                        uint8_t *);
} sc_context_t;

/**
 * This is a generic implementation of using a stream cipher to crypt some
 * amount of data. Makes adding new algos much easier!
 *
 * @param sc_context
 */
static void generic_sc_impl(sc_context_t * sc_context)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint64_t interblock_offset = sc_context->nugget_internal_offset / sc_context->output_size_bytes;
    uint64_t intrablock_offset = sc_context->nugget_internal_offset % sc_context->output_size_bytes;
    uint64_t num_blocks = CEIL((intrablock_offset + sc_context->data_length), sc_context->output_size_bytes);
    uint64_t zero_str_length = num_blocks * sc_context->output_size_bytes;
    uint64_t block_read_upper_bound = intrablock_offset + sc_context->data_length;

    IFDEBUG(dzlog_debug("data in: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(sc_context->data, MIN(64U, sc_context->data_length)));

    const uint8_t * const kcs_keycount_ptr = (const uint8_t *) &sc_context->kcs_keycount;

    IFDEBUG(dzlog_debug("%s", sc_context->output_name));
    IFDEBUG(dzlog_debug("keycount = %"PRIu64, sc_context->kcs_keycount));
    IFDEBUG(dzlog_debug("keycount hex x2 (should match):"));
    IFDEBUG(hdzlog_debug(&(sc_context->kcs_keycount), BLFS_CRYPTO_BYTES_CHACHA_NONCE));
    IFDEBUG(hdzlog_debug(kcs_keycount_ptr, BLFS_CRYPTO_BYTES_CHACHA_NONCE));
    IFDEBUG(dzlog_debug("data_length = %"PRIu32, sc_context->data_length));
    IFDEBUG(dzlog_debug("nugget_internal_offset = %"PRIu64, sc_context->nugget_internal_offset));
    IFDEBUG(dzlog_debug("interblock_offset = %"PRIu64, interblock_offset));
    IFDEBUG(dzlog_debug("intrablock_offset = %"PRIu64, intrablock_offset));
    IFDEBUG(dzlog_debug("num_blocks = %"PRIu64, num_blocks));
    IFDEBUG(dzlog_debug("zero_str_length = %"PRIu64, zero_str_length));
    IFDEBUG(dzlog_debug("block_read_upper_bound = %"PRIu64, block_read_upper_bound));
    IFDEBUG(dzlog_debug("block read range = (%"PRIu64" to %"PRIu64" - 1) <=> %"PRIu64" [total, zero indexed]",
        intrablock_offset, block_read_upper_bound, block_read_upper_bound - intrablock_offset));

    assert(zero_str_length >= sc_context->data_length);

    uint8_t * xor_str  = calloc(zero_str_length, sizeof(*xor_str)); // XXX: be sure to maintain complete control over this pointer and its memory

    if(xor_str == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    IFDEBUG(dzlog_debug(">>>> entering LAMBDA function"));

    sc_context->data_handle((void *) sc_context,
                            interblock_offset,
                            intrablock_offset,
                            num_blocks,
                            zero_str_length,
                            block_read_upper_bound,
                            kcs_keycount_ptr,
                            xor_str);

    IFDEBUG(dzlog_debug("<<<< leaving LAMBDA function"));

    for(uint64_t i = intrablock_offset, j = block_read_upper_bound, k = 0; i < j; ++i, ++k)
    {
        assert(k < sc_context->data_length);
        sc_context->crypted_data[k] = sc_context->data[k] ^ xor_str[i];
    }

    IFDEBUG(dzlog_debug("crypted data out: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(sc_context->crypted_data, MIN(64U, sc_context->data_length)));

    free(xor_str);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

/**
 * This is a generic implementation of using the AES block cipher in CTR mode to
 * crypt some amount of data. Makes adding new AES-based algo versions much
 * easier!
 *
 * @param sc_context
 */
static void generic_sc_aes_impl(const char * output_name,
                                uint64_t output_size_bytes,
                                uint64_t key_size_bytes,
                                uint64_t iv_size_bytes,
                                uint8_t * crypted_data,
                                const uint8_t * data,
                                uint32_t data_length,
                                const uint8_t * nugget_key,
                                uint64_t kcs_keycount,
                                uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    sc_context_t sc_context = {
        .output_name = output_name,
        .output_size_bytes = output_size_bytes,
        .crypted_data = crypted_data,
        .data = data,
        .data_length = data_length,
        .nugget_key = nugget_key,
        .kcs_keycount = kcs_keycount,
        .nugget_internal_offset = nugget_internal_offset,
        .data_handle = LAMBDA(void,
            (void * context,
             uint64_t interblock_offset,
             uint64_t intrablock_offset,
             uint64_t num_blocks,
             uint64_t zero_str_length,
             uint64_t block_read_upper_bound,
             const uint8_t * const kcs_keycount_ptr,
             uint8_t * xor_str)
            {
                (void) intrablock_offset;
                (void) block_read_upper_bound;
                (void) zero_str_length;

                sc_context_t * sc_context = (sc_context_t *) context;

                uint64_t counter = interblock_offset;
                uint8_t stream_nonce[iv_size_bytes];
                uint8_t raw_key[key_size_bytes];

                const uint8_t * raw_key_bin = (const uint8_t *) &raw_key;
                int key_size_bits = (int)(key_size_bytes * BITS_IN_A_BYTE);

                AES_KEY aes_key;
                AES_KEY * aes_key_ptr = &aes_key;

                assert(sizeof(sc_context->kcs_keycount) + sizeof(counter) <= sizeof(stream_nonce));

                memset(stream_nonce, 0, sizeof(stream_nonce));
                memcpy(stream_nonce, kcs_keycount_ptr, sizeof(sc_context->kcs_keycount));
                memcpy(raw_key, sc_context->nugget_key, sizeof(raw_key)); // XXX: cutting off the key, bad bad not good! Need key schedule!

                for(uint64_t i = 0; i < num_blocks; i++, counter++)
                {
                    memcpy(stream_nonce + sizeof(sc_context->kcs_keycount), (uint8_t *) &counter, sizeof(counter));

                    AES_set_encrypt_key(raw_key_bin, key_size_bits, aes_key_ptr);
                    AES_encrypt(stream_nonce, xor_str + (i * output_size_bytes), aes_key_ptr);
                }
            }
        ),
    };

    generic_sc_impl(&sc_context);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

/**
 * This is a generic implementation of using the SALSA stream cipher to crypt
 * some amount of data. Made adding all the SALSA20/x variants much easier!
 *
 * @param sc_context
 */

static void generic_sc_salsa_impl(const char * output_name,
                                uint64_t output_size_bytes,
                                uint64_t key_size_bytes,
                                salsa20_variant salsa_rounds,
                                uint8_t * crypted_data,
                                const uint8_t * data,
                                uint32_t data_length,
                                const uint8_t * nugget_key,
                                uint64_t kcs_keycount,
                                uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    sc_context_t sc_context = {
        .output_name = output_name,
        .output_size_bytes = output_size_bytes,
        .crypted_data = crypted_data,
        .data = data,
        .data_length = data_length,
        .nugget_key = nugget_key,
        .kcs_keycount = kcs_keycount,
        .nugget_internal_offset = nugget_internal_offset,
        .data_handle = LAMBDA(void,
            (void * context,
             uint64_t interblock_offset,
             uint64_t intrablock_offset,
             uint64_t num_blocks,
             uint64_t zero_str_length,
             uint64_t block_read_upper_bound,
             const uint8_t * const kcs_keycount_ptr,
             uint8_t * xor_str)
            {
                (void) intrablock_offset;
                (void) block_read_upper_bound;
                (void) zero_str_length;

                sc_context_t * sc_context = (sc_context_t *) context;

                salsa20_master_state key_state;
                salsa20_state output_state;

                uint8_t key[key_size_bytes];
                // uint8_t iv[BLFS_CRYPTO_BYTES_SALSA8_IV]; // XXX: represented by the 8 byte keycount

                memcpy(key, sc_context->nugget_key, sizeof key); // XXX: cutting off the key, bad bad not good! Need key schedule!

                salsa20_init_key(&key_state, salsa_rounds, key, SALSA20_256_BITS);
                salsa20_init_iv(&output_state, &key_state, kcs_keycount_ptr);
                salsa20_set_counter(&output_state, interblock_offset);

                for(uint64_t i = 0; i < num_blocks; ++i)
                    salsa20_extract(&output_state, xor_str + (i * sc_context->output_size_bytes));
            }
        ),
    };

    generic_sc_impl(&sc_context);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

/**
 * Example stream_crypt_common implementation:
 * 
 * Accepts a byte array of data of length data_length and yields crypted_data of
 * the same length via the result of XOR-ing the output of some stream cipher
 * run with the provided secret (nugget_key), likely using kcs_keycount as a
 * nonce, and initial block count (also could be the nonce; calculated from
 * nugget_internal_offset).
 *
 * This function should be called within a per-nugget (conceptual) context.
 *
 * If you crypt something, and then pass crypted_data back in as data with the
 * same keys and offsets, then you will get the original message back.
 *
 * @example
 * void some_stream_cipher_impl(uint8_t * crypted_data,
 *                              const uint8_t * data,
 *                              uint32_t data_length,
 *                              const uint8_t * nugget_key,
 *                              uint64_t kcs_keycount,
 *                              uint64_t nugget_internal_offset);
 */

static void sc_impl_chacha20(uint8_t * crypted_data,
                             const uint8_t * data,
                             uint32_t data_length,
                             const uint8_t * nugget_key,
                             uint64_t kcs_keycount,
                             uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    sc_context_t sc_context = {
        .output_name = "sc_chacha20",
        .output_size_bytes = BLFS_CRYPTO_BYTES_CHACHA_BLOCK,
        .crypted_data = crypted_data,
        .data = data,
        .data_length = data_length,
        .nugget_key = nugget_key,
        .kcs_keycount = kcs_keycount,
        .nugget_internal_offset = nugget_internal_offset,
        .data_handle = LAMBDA(void,
            (void * context,
             uint64_t interblock_offset,
             uint64_t intrablock_offset,
             uint64_t num_blocks,
             uint64_t zero_str_length,
             uint64_t block_read_upper_bound,
             const uint8_t * const kcs_keycount_ptr,
             uint8_t * xor_str)
            {
                (void) intrablock_offset;
                (void) num_blocks;
                (void) block_read_upper_bound;

                uint8_t * zero_str = calloc(zero_str_length, sizeof(*zero_str));

                if(zero_str == NULL)
                    Throw(EXCEPTION_ALLOC_FAILURE);

                sc_context_t * sc_context = (sc_context_t *) context;

                if(crypto_stream_chacha20_xor_ic(
                        xor_str,
                        zero_str,
                        zero_str_length,
                        kcs_keycount_ptr,
                        interblock_offset,
                        sc_context->nugget_key) != 0)
                {
                    Throw(EXCEPTION_CHACHA20_BAD_RETVAL);
                }

                free(zero_str);
            }
        ),
    };

    generic_sc_impl(&sc_context);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

static void sc_impl_aes128_ctr(uint8_t * crypted_data,
                               const uint8_t * data,
                               uint32_t data_length,
                               const uint8_t * nugget_key,
                               uint64_t kcs_keycount,
                               uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    generic_sc_aes_impl("sc_aes128_ctr",
                        BLFS_CRYPTO_BYTES_AES128_BLOCK,
                        BLFS_CRYPTO_BYTES_AES128_KEY,
                        BLFS_CRYPTO_BYTES_AES128_IV,
                        crypted_data,
                        data,
                        data_length,
                        nugget_key,
                        kcs_keycount,
                        nugget_internal_offset);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

static void sc_impl_aes256_ctr(uint8_t * crypted_data,
                             const uint8_t * data,
                             uint32_t data_length,
                             const uint8_t * nugget_key,
                             uint64_t kcs_keycount,
                             uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    generic_sc_aes_impl("sc_aes256_ctr",
                        BLFS_CRYPTO_BYTES_AES256_BLOCK,
                        BLFS_CRYPTO_BYTES_AES256_KEY,
                        BLFS_CRYPTO_BYTES_AES256_IV,
                        crypted_data,
                        data,
                        data_length,
                        nugget_key,
                        kcs_keycount,
                        nugget_internal_offset);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

static void sc_impl_salsa8(uint8_t * crypted_data,
                           const uint8_t * data,
                           uint32_t data_length,
                           const uint8_t * nugget_key,
                           uint64_t kcs_keycount,
                           uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    generic_sc_salsa_impl("sc_salsa8",
                          BLFS_CRYPTO_BYTES_SALSA8_BLOCK,
                          BLFS_CRYPTO_BYTES_SALSA8_KEY,
                          SALSA20_8,
                          crypted_data,
                          data,
                          data_length,
                          nugget_key,
                          kcs_keycount,
                          nugget_internal_offset);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

static void sc_impl_salsa12(uint8_t * crypted_data,
                           const uint8_t * data,
                           uint32_t data_length,
                           const uint8_t * nugget_key,
                           uint64_t kcs_keycount,
                           uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    generic_sc_salsa_impl("sc_salsa12",
                          BLFS_CRYPTO_BYTES_SALSA12_BLOCK,
                          BLFS_CRYPTO_BYTES_SALSA12_KEY,
                          SALSA20_12,
                          crypted_data,
                          data,
                          data_length,
                          nugget_key,
                          kcs_keycount,
                          nugget_internal_offset);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

static void sc_impl_salsa20(uint8_t * crypted_data,
                           const uint8_t * data,
                           uint32_t data_length,
                           const uint8_t * nugget_key,
                           uint64_t kcs_keycount,
                           uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    generic_sc_salsa_impl("sc_salsa20",
                          BLFS_CRYPTO_BYTES_SALSA20_BLOCK,
                          BLFS_CRYPTO_BYTES_SALSA20_KEY,
                          SALSA20_20,
                          crypted_data,
                          data,
                          data_length,
                          nugget_key,
                          kcs_keycount,
                          nugget_internal_offset);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

static void sc_impl_hc128(uint8_t * crypted_data,
                             const uint8_t * data,
                             uint32_t data_length,
                             const uint8_t * nugget_key,
                             uint64_t kcs_keycount,
                             uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    sc_context_t sc_context = {
        .output_name = "sc_hc128",
        .output_size_bytes = BLFS_CRYPTO_BYTES_HC128_BLOCK,
        .crypted_data = crypted_data,
        .data = data,
        .data_length = data_length,
        .nugget_key = nugget_key,
        .kcs_keycount = kcs_keycount,
        .nugget_internal_offset = nugget_internal_offset,
        .data_handle = LAMBDA(void,
            (void * context,
             uint64_t interblock_offset,
             uint64_t intrablock_offset,
             uint64_t num_blocks,
             uint64_t zero_str_length,
             uint64_t block_read_upper_bound,
             const uint8_t * const kcs_keycount_ptr,
             uint8_t * xor_str)
            {
                (void) intrablock_offset;
                (void) block_read_upper_bound;
                (void) zero_str_length;

                sc_context_t * sc_context = (sc_context_t *) context;

                hc128_state output_state;

                uint64_t counter = interblock_offset;
                uint8_t raw_key[BLFS_CRYPTO_BYTES_HC128_KEY];
                uint8_t stream_nonce[BLFS_CRYPTO_BYTES_HC128_IV];

                assert(sizeof(sc_context->kcs_keycount) + sizeof(counter) <= sizeof(stream_nonce));
                
                memset(stream_nonce, 0, sizeof(stream_nonce));
                memcpy(stream_nonce, kcs_keycount_ptr, sizeof(sc_context->kcs_keycount));
                memcpy(raw_key, sc_context->nugget_key, sizeof(raw_key)); // XXX: cutting off the key, bad bad not good! Need key schedule!

                for(uint64_t i = 0; i < num_blocks; i++, counter++)
                {
                    memcpy(stream_nonce + sizeof(sc_context->kcs_keycount), (uint8_t *) &counter, sizeof(counter));

                    hc128_init(&output_state, raw_key, stream_nonce);
                    hc128_extract(&output_state, xor_str + (i * sc_context->output_size_bytes));
                }
            }
        ),
    };

    generic_sc_impl(&sc_context);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

static void sc_impl_rabbit(uint8_t * crypted_data,
                             const uint8_t * data,
                             uint32_t data_length,
                             const uint8_t * nugget_key,
                             uint64_t kcs_keycount,
                             uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    sc_context_t sc_context = {
        .output_name = "sc_rabbit",
        .output_size_bytes = BLFS_CRYPTO_BYTES_RABBIT_BLOCK,
        .crypted_data = crypted_data,
        .data = data,
        .data_length = data_length,
        .nugget_key = nugget_key,
        .kcs_keycount = kcs_keycount,
        .nugget_internal_offset = nugget_internal_offset,
        .data_handle = LAMBDA(void,
            (void * context,
             uint64_t interblock_offset,
             uint64_t intrablock_offset,
             uint64_t num_blocks,
             uint64_t zero_str_length,
             uint64_t block_read_upper_bound,
             const uint8_t * const kcs_keycount_ptr,
             uint8_t * xor_str)
            {
                (void) intrablock_offset;
                (void) block_read_upper_bound;
                (void) zero_str_length;

                sc_context_t * sc_context = (sc_context_t *) context;

                rabbit_state key_state;
                rabbit_state iv_state;

                uint64_t counter = interblock_offset;
                uint8_t raw_key[BLFS_CRYPTO_BYTES_RABBIT_KEY];
                // uint8_t iv[BLFS_CRYPTO_BYTES_RABBIT_IV]; // XXX: handled by the 8 byte keycount

                memcpy(raw_key, sc_context->nugget_key, sizeof(raw_key)); // XXX: cutting off the key, bad bad not good! Need key schedule!

                rabbit_init_key(&key_state, raw_key);

                for(uint64_t i = 0; i < num_blocks; i++, counter++)
                {
                    // XXX: NOTE THAT THIS IMPLEMENTATION IS CERTAINLY NOT SECURE (we discard keycount here for expedience)
                    // Possible remedy: hash the keycount and the counter and use that output as IV
                    (void) kcs_keycount_ptr;
                    
                    rabbit_init_iv(&iv_state, &key_state, (uint8_t *) &counter);
                    rabbit_extract(&iv_state, xor_str + (i * sc_context->output_size_bytes));
                }
            }
        ),
    };

    generic_sc_impl(&sc_context);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

static void sc_impl_sosemanuk(uint8_t * crypted_data,
                             const uint8_t * data,
                             uint32_t data_length,
                             const uint8_t * nugget_key,
                             uint64_t kcs_keycount,
                             uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    sc_context_t sc_context = {
        .output_name = "sc_sosemanuk",
        .output_size_bytes = BLFS_CRYPTO_BYTES_SOSEK_BLOCK,
        .crypted_data = crypted_data,
        .data = data,
        .data_length = data_length,
        .nugget_key = nugget_key,
        .kcs_keycount = kcs_keycount,
        .nugget_internal_offset = nugget_internal_offset,
        .data_handle = LAMBDA(void,
            (void * context,
             uint64_t interblock_offset,
             uint64_t intrablock_offset,
             uint64_t num_blocks,
             uint64_t zero_str_length,
             uint64_t block_read_upper_bound,
             const uint8_t * const kcs_keycount_ptr,
             uint8_t * xor_str)
            {
                (void) intrablock_offset;
                (void) block_read_upper_bound;
                (void) zero_str_length;

                sc_context_t * sc_context = (sc_context_t *) context;

                sosemanuk_master_state key_state;
                sosemanuk_state iv_state;

                uint64_t counter = interblock_offset;
                uint8_t raw_key[BLFS_CRYPTO_BYTES_SOSEK_KEY];
                uint8_t stream_nonce[BLFS_CRYPTO_BYTES_SOSEK_IV];

                assert(sizeof(sc_context->kcs_keycount) + sizeof(counter) <= sizeof(stream_nonce));
                
                memset(stream_nonce, 0, sizeof(stream_nonce));
                memcpy(stream_nonce, kcs_keycount_ptr, sizeof(sc_context->kcs_keycount));
                memcpy(raw_key, sc_context->nugget_key, sizeof(raw_key)); // XXX: cutting off the key, bad bad not good! Need key schedule!

                sosemanuk_init_key(&key_state, raw_key, BLFS_CRYPTO_BYTES_SOSEK_KEY * BITS_IN_A_BYTE);

                for(uint64_t i = 0; i < num_blocks; i++, counter++)
                {
                    memcpy(stream_nonce + sizeof(sc_context->kcs_keycount), (uint8_t *) &counter, sizeof(counter));

                    sosemanuk_init_iv(&iv_state, &key_state, stream_nonce);
                    sosemanuk_extract(&iv_state, xor_str + (i * sc_context->output_size_bytes));
                }
            }
        ),
    };

    generic_sc_impl(&sc_context);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_set_stream_context(buselfs_state_t * buselfs_state, stream_cipher_e stream_cipher)
{
    buselfs_state->default_crypt_context = blfs_to_stream_context(stream_cipher);
}

stream_crypt_common blfs_to_stream_context(stream_cipher_e stream_cipher)
{
    stream_crypt_common fn = NULL;

    switch(stream_cipher)
    {
        case sc_default:
        case sc_chacha20:
        {
            fn = &sc_impl_chacha20;
            break;
        }

        case sc_aes128_ctr:
        {
            fn = &sc_impl_aes128_ctr;
            break;
        }

        case sc_aes256_ctr:
        {
            fn = &sc_impl_aes256_ctr;
            break;
        }

        case sc_salsa8:
        {
            fn = &sc_impl_salsa8;
            break;
        }

        case sc_salsa12:
        {
            fn = &sc_impl_salsa12;
            break;
        }

        case sc_salsa20:
        {
            fn = &sc_impl_salsa20;
            break;
        }

        case sc_hc128:
        {
            fn = &sc_impl_hc128;
            break;
        }

        case sc_rabbit:
        {
            fn = &sc_impl_rabbit;
            break;
        }

        case sc_sosemanuk:
        {
            fn = &sc_impl_sosemanuk;
            break;
        }

        case sc_chacha8:
        case sc_chacha12:
        case sc_not_impl:
        {
            Throw(EXCEPTION_SC_ALGO_NO_IMPL);
            break;
        }

        default:
        {
            Throw(EXCEPTION_SC_ALGO_NOT_FOUND);
            break;
        }
    }

    return fn;
}

stream_cipher_e stream_string_to_cipher(const char * stream_cipher_str)
{
    stream_cipher_e cipher = sc_not_impl;

    if(strcmp(stream_cipher_str, "sc_default") == 0)
        cipher = sc_default;

    else if(strcmp(stream_cipher_str, "sc_aes128_ctr") == 0)
        cipher = sc_aes128_ctr;
    
    else if(strcmp(stream_cipher_str, "sc_aes256_ctr") == 0)
        cipher = sc_aes256_ctr;

    else if(strcmp(stream_cipher_str, "sc_salsa8") == 0)
        cipher = sc_salsa8;
    
    else if(strcmp(stream_cipher_str, "sc_salsa12") == 0)
        cipher = sc_salsa12;

    else if(strcmp(stream_cipher_str, "sc_salsa20") == 0)
        cipher = sc_salsa20;

    else if(strcmp(stream_cipher_str, "sc_hc128") == 0)
        cipher = sc_hc128;

    else if(strcmp(stream_cipher_str, "sc_rabbit") == 0)
        cipher = sc_rabbit;
    
    else if(strcmp(stream_cipher_str, "sc_sosemanuk") == 0)
        cipher = sc_sosemanuk;

    else if(strcmp(stream_cipher_str, "sc_chacha8") == 0)
        cipher = sc_chacha8;

    else if(strcmp(stream_cipher_str, "sc_chacha12") == 0)
        cipher = sc_chacha12;
    
    else if(strcmp(stream_cipher_str, "sc_chacha20") == 0)
        cipher = sc_chacha20;

    else
        Throw(EXCEPTION_STRING_TO_CIPHER_FAILED);

    return cipher;
}
