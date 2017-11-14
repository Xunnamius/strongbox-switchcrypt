/*
 * <description>
 *
 * @author ANON
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
                        uint8_t *,
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

    uint8_t * kcs_keycount_ptr = (uint8_t *) &sc_context->kcs_keycount;

    IFDEBUG(dzlog_debug(sc_context->output_name));
    IFDEBUG(dzlog_debug("keycount = %"PRIu64, sc_context->kcs_keycount));
    IFDEBUG(dzlog_debug("keycount hex x2 (should match):"));
    IFDEBUG(hdzlog_debug(&(sc_context->kcs_keycount), BLFS_CRYPTO_BYTES_CHACHA_NONCE));
    IFDEBUG(hdzlog_debug(kcs_keycount_ptr, BLFS_CRYPTO_BYTES_CHACHA_NONCE));
    IFDEBUG(dzlog_debug("data_length = %"PRIu32, sc_context->data_length));
    IFDEBUG(dzlog_debug("nugget_internal_offset = %"PRIu64, sc_context->nugget_internal_offset));
    IFDEBUG(dzlog_debug("interblock_offset = %"PRIu64, interblock_offset));
    IFDEBUG(dzlog_debug("intrablock_offset = %"PRIu64, intrablock_offset));
    IFDEBUG(dzlog_debug("zero_str_length = %"PRIu64, zero_str_length));
    IFDEBUG(dzlog_debug("block_read_upper_bound = %"PRIu64, block_read_upper_bound));
    IFDEBUG(dzlog_debug("block read range = (%"PRIu64" to %"PRIu64" - 1) <=> %"PRIu64" [total, zero indexed]",
        intrablock_offset, block_read_upper_bound, block_read_upper_bound - intrablock_offset));

    assert(zero_str_length >= sc_context->data_length);

    uint8_t * xor_str  = calloc(zero_str_length, sizeof(*xor_str));

    if(xor_str == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    IFDEBUG(dzlog_debug(">>>> entering LAMBDA function"));

    sc_context->data_handle(sc_context,
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
             uint8_t * kcs_keycount_ptr,
             uint8_t * xor_str)
            {
                (void) intrablock_offset;
                (void) block_read_upper_bound;
                (void) zero_str_length;
                (void) kcs_keycount_ptr;

                sc_context_t * sc_context = (sc_context_t *) context;

                uint64_t counter = interblock_offset;
                uint8_t stream_nonce[iv_size_bytes];

                memset(stream_nonce, 0, sizeof(stream_nonce));

                assert(sizeof(sc_context->kcs_keycount) + sizeof(counter) <= sizeof(stream_nonce));
                memcpy(stream_nonce, (uint8_t *) &(sc_context->kcs_keycount), sizeof(sc_context->kcs_keycount));

                for(uint64_t i = 0; i < num_blocks; i++, counter++)
                {
                    AES_KEY aes_key;

                    uint8_t raw_key[key_size_bytes];
                    uint8_t * xor_str_ptr = xor_str + (i * sizeof(stream_nonce));

                    memcpy(stream_nonce + sizeof(sc_context->kcs_keycount), (uint8_t *) &counter, sizeof(counter));
                    memcpy(raw_key, sc_context->nugget_key, sizeof(raw_key)); // XXX: cutting off the key, bad bad not good! Need key schedule!

                    AES_set_encrypt_key((const uint8_t *) raw_key, (int)(key_size_bytes * 8), &aes_key);
                    AES_encrypt(stream_nonce, xor_str_ptr, &aes_key);
                }
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
             uint8_t * kcs_keycount_ptr,
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

void blfs_set_stream_context(buselfs_state_t * buselfs_state, stream_cipher_e stream_cipher)
{
    buselfs_state->default_crypt_context = blfs_to_stream_context(stream_cipher);
}

stream_crypt_common blfs_to_stream_context(stream_cipher_e stream_cipher)
{
    stream_crypt_common fn;

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
        /*{
            break;
        }*/

        case sc_salsa12:
        /*{
            break;
        }*/

        case sc_salsa20:
        /*{
            break;
        }*/

        case sc_hc128:
        /*{
            break;
        }*/

        case sc_rabbit:
        /*{
            break;
        }*/

        case sc_sosemanuk:
        /*{
            break;
        }*/

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
