/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include "crypto.h"

#include <assert.h>
#include <string.h>
#include <inttypes.h>

void blfs_password_to_secret(uint8_t * secret, const char * passwd, uint32_t passwd_length, const uint8_t * salt)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("passwd = %s", passwd));
    IFDEBUG(dzlog_debug("passwd_length = %"PRIu32, passwd_length));
    IFDEBUG(dzlog_debug("salt:"));
    IFDEBUG(hdzlog_debug(salt, BLFS_CRYPTO_BYTES_KDF_SALT));

    // BLFS_CRYPTO_BYTES_KDF_OUT
    if(crypto_pwhash(secret, BLFS_CRYPTO_BYTES_KDF_OUT, passwd, passwd_length, salt,
                     crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0)
    {
        Throw(EXCEPTION_OUT_OF_MEMORY);
    }

    IFDEBUG(dzlog_debug("secret (set to):"));
    IFDEBUG(hdzlog_debug(secret, BLFS_CRYPTO_BYTES_KDF_OUT));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_chacha20_128(uint8_t * xored_value, const uint8_t * secret)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("secret:"));
    IFDEBUG(hdzlog_debug(secret, BLFS_CRYPTO_BYTES_KDF_OUT));

    uint8_t xored[BLFS_HEAD_HEADER_BYTES_VERIFICATION] = { 0x00 };
    uint8_t nonce[BLFS_CRYPTO_BYTES_CHACHA_NONCE] = { 0x00 };

    crypto_stream_chacha20(xored, sizeof xored, nonce, secret);

    memcpy(xored_value, xored, BLFS_HEAD_HEADER_BYTES_VERIFICATION);

    IFDEBUG(dzlog_debug("xored_value:"));
    IFDEBUG(hdzlog_debug(xored_value, BLFS_HEAD_HEADER_BYTES_VERIFICATION));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_nugget_key_from_data(uint8_t * nugget_key, const uint8_t * secret, uint64_t nugget_index)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("nugget_index = %"PRIu64, nugget_index));
    IFDEBUG(dzlog_debug("secret:"));
    IFDEBUG(hdzlog_debug(secret, BLFS_CRYPTO_BYTES_KDF_OUT));

    memcpy(nugget_key, secret, BLFS_CRYPTO_BYTES_KDF_OUT);

    IFDEBUG(dzlog_debug("nugget_key (phase 1, set to):"));
    IFDEBUG(hdzlog_debug(nugget_key, BLFS_CRYPTO_BYTES_KDF_OUT));

    uint64_t * secret8bytes = (uint64_t *) nugget_key;
    secret8bytes[0] += nugget_index;

    IFDEBUG(dzlog_debug("nugget_key (final, set to):"));
    IFDEBUG(hdzlog_debug(nugget_key, BLFS_CRYPTO_BYTES_KDF_OUT));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_poly1305_key_from_data(uint8_t * new_key,
                                 const uint8_t * nugget_key,
                                 uint32_t flake_index,
                                 uint64_t kcs_keycount)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("flake_index = %"PRIu32, flake_index));
    IFDEBUG(dzlog_debug("kcs_keycount = %"PRIu64, kcs_keycount));
    IFDEBUG(dzlog_debug("nugget_key:"));
    IFDEBUG(hdzlog_debug(nugget_key, BLFS_CRYPTO_BYTES_KDF_OUT));

    memcpy(new_key, nugget_key, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY);

    IFDEBUG(dzlog_debug("new_key (phase 1, set to):"));
    IFDEBUG(hdzlog_debug(new_key, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY));

    uint64_t * nk8bytes = (uint64_t *) new_key;
    nk8bytes[0] += ((uint64_t) flake_index) + kcs_keycount;

    IFDEBUG(dzlog_debug("new_key (final, set to):"));
    IFDEBUG(hdzlog_debug(new_key, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_poly1305_generate_tag(uint8_t * tag, const uint8_t * data, uint32_t data_length, const uint8_t * flake_key)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("data_length = %"PRIu32, data_length));
    IFDEBUG(dzlog_debug("flake_key:"));
    IFDEBUG(hdzlog_debug(flake_key, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY));

    crypto_onetimeauth(tag, data, data_length, flake_key);

    IFDEBUG(dzlog_debug("tag (set to):"));
    IFDEBUG(hdzlog_debug(tag, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_chacha20_crypt(uint8_t * crypted_data,
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

    free(zero_str);
    free(xor_str);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_globalversion_verify(uint64_t id, uint64_t global_version)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("id = %"PRIu64, id));
    IFDEBUG(dzlog_debug("global_version = %"PRIu64, global_version));

    // TODO: spin our wheels here for a bit to simulate verification
    // EXCEPTION_TPM_VERSION_CHECK_FAILURE

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_globalversion_commit(uint64_t id, uint64_t global_version)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("id = %"PRIu64, id));
    IFDEBUG(dzlog_debug("global_version = %"PRIu64, global_version));

    // TODO: spin our wheels here for a bit to simulate committing
    // EXCEPTION_TPM_VERSION_CHECK_FAILURE

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_KDF_generate_salt(uint8_t * generated_salt)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    randombytes_buf(generated_salt, BLFS_CRYPTO_BYTES_KDF_SALT);

    IFDEBUG(dzlog_debug("generated_salt:"));
    IFDEBUG(hdzlog_debug(generated_salt, BLFS_CRYPTO_BYTES_KDF_SALT));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
