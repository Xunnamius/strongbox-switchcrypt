/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include "crypto.h"
#include "mmc_cmds.h"

#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include "openssl/aes.h"

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

void blfs_chacha20_verif(uint8_t * xored_value, const uint8_t * secret)
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

void blfs_chacha20_tj_hash(uint8_t * tj_hash, const uint8_t * tj_data, uint64_t tj_data_length, const uint8_t * master_secret)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("tj_data:"));
    IFDEBUG(hdzlog_debug(tj_data, tj_data_length));

    crypto_generichash(tj_hash, BLFS_CRYPTO_BYTES_TJ_HASH_OUT, tj_data, tj_data_length, master_secret, BLFS_CRYPTO_BYTES_KDF_OUT);

    IFDEBUG(dzlog_debug("tj_hash:"));
    IFDEBUG(hdzlog_debug(tj_hash, BLFS_CRYPTO_BYTES_TJ_HASH_OUT));

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

int blfs_globalversion_verify(uint64_t id, uint64_t global_version)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("id = %"PRIu64, id));
    IFDEBUG(dzlog_debug("global_version = %"PRIu64, global_version));

    uint8_t data[BLFS_CRYPTO_RPMB_BLOCK];

    sb_rpmb_read_block((uint16_t) id, data);

    IFDEBUG(dzlog_debug("RPMB block read in:"));
    IFDEBUG(hdzlog_debug(data, BLFS_CRYPTO_RPMB_BLOCK));

    uint8_t * first_8 = malloc(8);
    memcpy(first_8, data, 8);

    IFDEBUG(dzlog_debug("first_8:"));
    IFDEBUG(hdzlog_debug(first_8, 8));

    uint64_t actual_gversion = *(uint64_t *) first_8;
    IFDEBUG(dzlog_debug("actual_gversion = %"PRIu64, actual_gversion));

    //Throw(EXCEPTION_TPM_VERSION_CHECK_FAILURE);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));

    if(actual_gversion < global_version || actual_gversion > global_version + 1)
        return BLFS_GLOBAL_CORRECTNESS_ILLEGAL_MANIP;

    if(actual_gversion == global_version + 1)
        return BLFS_GLOBAL_CORRECTNESS_POTENTIAL_CRASH;

    return BLFS_GLOBAL_CORRECTNESS_ALL_GOOD;
}

void blfs_globalversion_commit(uint64_t id, uint64_t global_version)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("id = %"PRIu64, id));
    IFDEBUG(dzlog_debug("global_version = %"PRIu64, global_version));

    uint8_t data[BLFS_CRYPTO_RPMB_BLOCK] = { 0 };
    memcpy(data, (uint8_t *) &global_version, sizeof(global_version));

    IFDEBUG(dzlog_debug("RPMB block to commit:"));
    IFDEBUG(hdzlog_debug(data, BLFS_CRYPTO_RPMB_BLOCK));

    sb_rpmb_write_block((uint16_t) id, data);

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

void blfs_aesxts_encrypt(uint8_t * encrypted_data,
                         const uint8_t * plaintext_data,
                         uint32_t data_length,
                         const uint8_t * flake_key,
                         uint32_t sector_tweak)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        Throw(EXCEPTION_BAD_AESXTS);

    if(data_length < BLFS_CRYPTO_BYTES_AES_DATA_MIN)
        Throw(EXCEPTION_AESXTS_DATA_LENGTH_TOO_SMALL);

    uint8_t doublekey[BLFS_CRYPTO_BYTES_AESXTS_KEY];
    uint8_t iv_tweak[BLFS_CRYPTO_BYTES_AESXTS_TWEAK] = { 0x00 };

    memcpy(doublekey, flake_key, BLFS_CRYPTO_BYTES_CHACHA_KEY);
    memcpy(doublekey + BLFS_CRYPTO_BYTES_CHACHA_KEY, flake_key, BLFS_CRYPTO_BYTES_CHACHA_KEY);
    memcpy(iv_tweak, (uint8_t *) &sector_tweak, sizeof sector_tweak);

    IFDEBUG(dzlog_debug("sector_tweak: %"PRIu32, sector_tweak));
    IFDEBUG(dzlog_debug("data in: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(plaintext_data, MIN(64U, data_length)));

    EVP_CIPHER_CTX * ctx = NULL;
    int len = 0;

    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        IFDEBUG(dzlog_fatal("ERROR @ 1: %s", ERR_error_string(ERR_peek_last_error(), NULL)));

        IFDEBUG(ERR_print_errors_fp(stdout));
        Throw(EXCEPTION_AESXTS_BAD_RETVAL);
    }

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, doublekey, iv_tweak) != 1)
    {
        IFDEBUG(dzlog_fatal("ERROR @ 2: %s", ERR_error_string(ERR_peek_last_error(), NULL)));

        IFDEBUG(ERR_print_errors_fp(stdout));
        Throw(EXCEPTION_AESXTS_BAD_RETVAL);
    }

    if(EVP_EncryptUpdate(ctx, encrypted_data, &len, plaintext_data, data_length) != 1)
    {
        IFDEBUG(dzlog_fatal("ERROR @ 3: %s", ERR_error_string(ERR_peek_last_error(), NULL)));

        IFDEBUG(ERR_print_errors_fp(stdout));
        Throw(EXCEPTION_AESXTS_BAD_RETVAL);
    }

    if(EVP_EncryptFinal_ex(ctx, encrypted_data + len, &len) != 1)
    {
        IFDEBUG(dzlog_fatal("ERROR @ 4: %s", ERR_error_string(ERR_peek_last_error(), NULL)));

        IFDEBUG(ERR_print_errors_fp(stdout));
        Throw(EXCEPTION_AESXTS_BAD_RETVAL);
    }

    EVP_CIPHER_CTX_free(ctx);

    IFDEBUG(dzlog_debug("encrypted data out: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(encrypted_data, MIN(64U, data_length)));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_aesxts_decrypt(uint8_t * plaintext_data,
                         const uint8_t * encrypted_data,
                         uint32_t data_length,
                         const uint8_t * flake_key,
                         uint32_t sector_tweak)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        Throw(EXCEPTION_BAD_AESXTS);

    if(data_length < BLFS_CRYPTO_BYTES_AES_DATA_MIN)
        Throw(EXCEPTION_AESXTS_DATA_LENGTH_TOO_SMALL);

    uint8_t doublekey[BLFS_CRYPTO_BYTES_AESXTS_KEY];
    uint8_t iv_tweak[BLFS_CRYPTO_BYTES_AESXTS_TWEAK] = { 0x00 };

    memcpy(doublekey, flake_key, BLFS_CRYPTO_BYTES_CHACHA_KEY);
    memcpy(doublekey + BLFS_CRYPTO_BYTES_CHACHA_KEY, flake_key, BLFS_CRYPTO_BYTES_CHACHA_KEY);

    assert(sizeof sector_tweak <= BLFS_CRYPTO_BYTES_AESXTS_TWEAK);

    memcpy(iv_tweak, (uint8_t *) &sector_tweak, sizeof sector_tweak);

    IFDEBUG(dzlog_debug("sector_tweak: %"PRIu32, sector_tweak));
    IFDEBUG(dzlog_debug("doublekey:"));
    IFDEBUG(hdzlog_debug(doublekey, BLFS_CRYPTO_BYTES_AESXTS_KEY));
    IFDEBUG(dzlog_debug("iv_tweak:"));
    IFDEBUG(hdzlog_debug(iv_tweak, BLFS_CRYPTO_BYTES_AESXTS_TWEAK));
    IFDEBUG(dzlog_debug("data in: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(encrypted_data, MIN(64U, data_length)));

    EVP_CIPHER_CTX * ctx = NULL;
    int len = 0;

    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        IFDEBUG(dzlog_fatal("ERROR @ 1: %s", ERR_error_string(ERR_peek_last_error(), NULL)));
        IFDEBUG(ERR_print_errors_fp(stdout));
        Throw(EXCEPTION_AESXTS_BAD_RETVAL);
    }

    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, doublekey, iv_tweak) != 1)
    {
        IFDEBUG(dzlog_fatal("ERROR @ 2: %s", ERR_error_string(ERR_peek_last_error(), NULL)));
        IFDEBUG(ERR_print_errors_fp(stdout));
        Throw(EXCEPTION_AESXTS_BAD_RETVAL);
    }

    if(EVP_DecryptUpdate(ctx, plaintext_data, &len, encrypted_data, data_length) != 1)
    {
        IFDEBUG(dzlog_fatal("ERROR @ 3: %s", ERR_error_string(ERR_peek_last_error(), NULL)));
        IFDEBUG(ERR_print_errors_fp(stdout));
        Throw(EXCEPTION_AESXTS_BAD_RETVAL);
    }

    if(EVP_DecryptFinal_ex(ctx, plaintext_data + len, &len) != 1)
    {
        IFDEBUG(dzlog_fatal("ERROR @ 4: %s", ERR_error_string(ERR_peek_last_error(), NULL)));
        IFDEBUG(ERR_print_errors_fp(stdout));
        Throw(EXCEPTION_AESXTS_BAD_RETVAL);
    }

    EVP_CIPHER_CTX_free(ctx);

    IFDEBUG(dzlog_debug("plaintext data out: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(plaintext_data, MIN(64U, data_length)));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_aesctr_crypt(uint8_t * crypted_data,
                         const uint8_t * data,
                         uint32_t data_length,
                         const uint8_t * nugget_key,
                         uint64_t kcs_keycount,
                         uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(!BLFS_BADBADNOTGOOD_USE_AESCTR_EMULATION)
        Throw(EXCEPTION_BAD_AESCTR);

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

    uint8_t * xor_str = calloc(zero_str_length, sizeof(xor_str));

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
