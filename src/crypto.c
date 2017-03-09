/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "crypto.h"

void blfs_password_to_secret(uint8_t * secret, const char * passwd, uint32_t passwd_length, const uint8_t * salt)
{
    // BLFS_CRYPTO_BYTES_KDF_OUT
    if(crypto_pwhash(secret, BLFS_CRYPTO_BYTES_KDF_OUT, passwd, passwd_length, salt,
                     crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0)
    {
        Throw(EXCEPTION_OUT_OF_MEMORY);
    }
}

void blfs_nugget_key_from_data(uint8_t * nugget_key, uint8_t * secret, uint64_t nugget_index)
{
    memcpy(nugget_key, secret, BLFS_CRYPTO_BYTES_KDF_OUT);
    uint64_t * secret8bytes = (uint64_t *) nugget_key;
    secret8bytes[0] += nugget_index;
}

void blfs_poly1305_key_from_data(uint8_t * new_key,
                                 const uint8_t * nugget_key,
                                 uint32_t flake_index,
                                 uint64_t kcs_keycount)
{
    memcpy(new_key, nugget_key, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY);
    uint64_t * nk8bytes = (uint64_t *) new_key;
    nk8bytes[0] += ((uint64_t) flake_index) + kcs_keycount;
}

void blfs_poly1305_generate_tag(uint8_t * tag, const uint8_t * data, uint32_t data_length, const uint8_t * flake_key)
{
    crypto_onetimeauth(tag, data, data_length, flake_key);
}

void blfs_chacha20_crypt(uint8_t * crypted_data,
                         const uint8_t * data,
                         uint32_t data_length,
                         const uint8_t * nugget_key,
                         const uint64_t * kcs_keycount,
                         uint64_t nugget_internal_offset)
{

    uint64_t interblock_offset = nugget_internal_offset / BLFS_CRYPTO_BYTES_CHACHA_BLOCK;
    uint64_t intrablock_offset = nugget_internal_offset % BLFS_CRYPTO_BYTES_CHACHA_BLOCK;
    uint64_t zero_str_length = CEIL((intrablock_offset + data_length), BLFS_CRYPTO_BYTES_CHACHA_BLOCK) * BLFS_CRYPTO_BYTES_CHACHA_BLOCK;
    uint64_t block_read_upper_bound = intrablock_offset + data_length;

    IFDEBUG(dzlog_debug("blfs_chacha20_crypt"));
    IFDEBUG(dzlog_debug("keycount = %"PRIu64, *kcs_keycount));
    IFDEBUG(dzlog_debug("keycount hex x2 (should match):"));
    IFDEBUG(hdzlog_debug(kcs_keycount, BLFS_CRYPTO_BYTES_CHACHA_NONCE));
    IFDEBUG(hdzlog_debug((unsigned char *) kcs_keycount, BLFS_CRYPTO_BYTES_CHACHA_NONCE));
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
        (unsigned char *) kcs_keycount,
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

    free(zero_str);
    free(xor_str);
}

int blfs_globalversion_verify(uint64_t id, uint64_t global_version)
{
    (void) id;
    (void) global_version;

    // TODO: spin our wheels here for a bit to simulate verification

    return 0;
}

int blfs_globalversion_commit(uint64_t id, uint64_t global_version)
{
    (void) id;
    (void) global_version;

    // TODO: spin our wheels here for a bit to simulate committing
    
    return 0;
}

void blfs_KDF_generate_salt(uint8_t * generated_salt)
{
    randombytes_buf(generated_salt, BLFS_CRYPTO_BYTES_KDF_SALT);
}
