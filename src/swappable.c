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

/**
 * Example stream_crypt_common implementation:
 * 
 * Accepts a byte array of data of length data_length and yields crypted_data of
 * the same length via the result of XOR-ing the output of some stream cipher
 * run with the provided secret (nugget_key), possibly using kcs_keycount as a
 * none, and initial block count (also could be the nonce; calculated from
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

    uint64_t interblock_offset = nugget_internal_offset / BLFS_CRYPTO_BYTES_CHACHA_BLOCK;
    uint64_t intrablock_offset = nugget_internal_offset % BLFS_CRYPTO_BYTES_CHACHA_BLOCK;
    uint64_t zero_str_length = CEIL((intrablock_offset + data_length), BLFS_CRYPTO_BYTES_CHACHA_BLOCK) * BLFS_CRYPTO_BYTES_CHACHA_BLOCK;
    uint64_t block_read_upper_bound = intrablock_offset + data_length;

    IFDEBUG(dzlog_debug("data in: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(data, MIN(64U, data_length)));

    unsigned char * kcs_keycount_ptr = (unsigned char *) &kcs_keycount;

    IFDEBUG(dzlog_debug("blfs_chacha20_crypt"));
    IFDEBUG(dzlog_debug("keycount = %"PRIu64, kcs_keycount));
    IFDEBUG(dzlog_debug("keycount hex x2 (should match):"));
    IFDEBUG(hdzlog_debug(&kcs_keycount, BLFS_CRYPTO_BYTES_CHACHA_NONCE));
    IFDEBUG(hdzlog_debug(kcs_keycount_ptr, BLFS_CRYPTO_BYTES_CHACHA_NONCE));
    IFDEBUG(dzlog_debug("data_length = %"PRIu32, data_length));
    IFDEBUG(dzlog_debug("nugget_internal_offset = %"PRIu64, nugget_internal_offset));
    IFDEBUG(dzlog_debug("interblock_offset = %"PRIu64, interblock_offset));
    IFDEBUG(dzlog_debug("intrablock_offset = %"PRIu64, intrablock_offset));
    IFDEBUG(dzlog_debug("zero_str_length = %"PRIu64, zero_str_length));
    IFDEBUG(dzlog_debug("block_read_upper_bound = %"PRIu64, block_read_upper_bound));
    IFDEBUG(dzlog_debug("block read range = (%"PRIu64" to %"PRIu64" - 1) <=> %"PRIu64" [total, zero indexed]",
        intrablock_offset, block_read_upper_bound, block_read_upper_bound - intrablock_offset));

    assert(zero_str_length >= data_length);

    unsigned char * zero_str = calloc(zero_str_length, sizeof(char));
    unsigned char * xor_str = malloc(zero_str_length);

    if(zero_str == NULL || xor_str == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    if(crypto_stream_chacha20_xor_ic(
        xor_str,
        zero_str,
        zero_str_length,
        kcs_keycount_ptr,
        interblock_offset,
        nugget_key) != 0)
    {
        Throw(EXCEPTION_CHACHA20_BAD_RETVAL);
    }

    for(uint64_t i = intrablock_offset, j = block_read_upper_bound, k = 0; i < j; ++i, ++k)
    {
        assert(k < data_length);
        crypted_data[k] = data[k] ^ xor_str[i];
    }


    IFDEBUG(dzlog_debug("crypted data out: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(crypted_data, MIN(64U, data_length)));

    free(zero_str);
    free(xor_str);

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

    uint64_t interblock_offset = nugget_internal_offset / BLFS_CRYPTO_BYTES_AES_BLOCK;
    uint64_t intrablock_offset = nugget_internal_offset % BLFS_CRYPTO_BYTES_AES_BLOCK;
    uint64_t num_aes_blocks = CEIL((intrablock_offset + data_length), BLFS_CRYPTO_BYTES_AES_BLOCK);
    uint64_t zero_str_length = num_aes_blocks * BLFS_CRYPTO_BYTES_AES_BLOCK;
    uint64_t block_read_upper_bound = intrablock_offset + data_length;

    IFDEBUG(dzlog_debug("data in: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(data, MIN(64U, data_length)));

    IFDEBUG(dzlog_debug("blfs_aesctr_crypt"));
    IFDEBUG(dzlog_debug("data_length = %"PRIu32, data_length));
    IFDEBUG(dzlog_debug("nugget_internal_offset = %"PRIu64, nugget_internal_offset));
    IFDEBUG(dzlog_debug("interblock_offset = %"PRIu64, interblock_offset));
    IFDEBUG(dzlog_debug("intrablock_offset = %"PRIu64, intrablock_offset));
    IFDEBUG(dzlog_debug("num_aes_blocks = %"PRIu64, num_aes_blocks));
    IFDEBUG(dzlog_debug("zero_str_length = %"PRIu64, zero_str_length));
    IFDEBUG(dzlog_debug("block_read_upper_bound = %"PRIu64, block_read_upper_bound));
    IFDEBUG(dzlog_debug("block read range = (%"PRIu64" to %"PRIu64" - 1) <=> %"PRIu64" [total, zero indexed]",
        intrablock_offset, block_read_upper_bound, block_read_upper_bound - intrablock_offset));

    assert(zero_str_length >= data_length);

    uint8_t * xor_str = calloc(zero_str_length, sizeof(*xor_str));

    if(xor_str == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    uint64_t counter = interblock_offset;
    uint8_t stream_nonce[BLFS_CRYPTO_BYTES_AES_BLOCK] = { 0x00 };

    assert(sizeof(kcs_keycount) + sizeof(counter) == BLFS_CRYPTO_BYTES_AES_IV);
    memcpy(stream_nonce, (uint8_t *) &kcs_keycount, sizeof(kcs_keycount));

    for(uint64_t i = 0; i < num_aes_blocks; i++, counter++)
    {
        AES_KEY aes_key;

        uint8_t raw_key[BLFS_CRYPTO_BYTES_AES_KEY] = { 0x00 };
        uint8_t * xor_str_ptr = xor_str + (i * sizeof(stream_nonce));

        memcpy(stream_nonce + sizeof(kcs_keycount), (uint8_t *) &counter, sizeof(counter));
        memcpy(raw_key, nugget_key, sizeof(raw_key)); // XXX: cutting off the key, bad bad not good! Need key schedule!

        AES_set_encrypt_key((const uint8_t *) raw_key, 128, &aes_key);
        AES_encrypt(stream_nonce, xor_str_ptr, &aes_key);
    }

    for(uint64_t i = intrablock_offset, j = block_read_upper_bound, k = 0; i < j; ++i, ++k)
    {
        assert(k < data_length);
        crypted_data[k] = data[k] ^ xor_str[i];
    }

    IFDEBUG(dzlog_debug("crypted data out: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(crypted_data, MIN(64U, data_length)));

    free(xor_str);

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

        case sc_aes256_ctr:
        {
            fn = &sc_impl_aes256_ctr;
            break;
        }

        case sc_chacha8:
        /*{
            break;
        }*/

        case sc_chacha12:
        /*{
            break;
        }*/

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

        case sc_aes128_ctr:
        /*{
            break;
        }*/

        case sc_aes512_ctr:
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
