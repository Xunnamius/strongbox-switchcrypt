/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include "crypto.h"
#include "./mmc.h"

#include <assert.h>
#include <string.h>
#include <inttypes.h>
// TODO: make sure things work without OpenSSL and other similar deps when apropos flags are false
#include "openssl/aes.h"

// If you're looking for the stream cipher functions, those were all moved
// to swappable.h and swappable.c

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

int blfs_globalversion_verify(uint64_t id, uint64_t global_version)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("id = %"PRIu64, id));
    IFDEBUG(dzlog_debug("global_version (expected) = %"PRIu64, global_version));

    uint8_t data[BLFS_CRYPTO_RPMB_BLOCK];
    volatile CEXCEPTION_T e = EXCEPTION_NO_EXCEPTION;

    Try
    {
        rpmb_read_block((uint16_t) id, data);
    }

    Catch(e)
    {
        if(e == EXCEPTION_RPMB_DOES_NOT_EXIST && BLFS_MANUAL_GV_FALLBACK != -1)
        {
            dzlog_warn("RPMB device is not able to be opened. Falling back to BLFS_MANUAL_GV_FALLBACK (%i)",
                       BLFS_MANUAL_GV_FALLBACK);
            
            return BLFS_MANUAL_GV_FALLBACK;
        }

        Throw(e);
    }

    IFDEBUG(dzlog_debug("RPMB block read in:"));
    IFDEBUG(hdzlog_debug(data, BLFS_CRYPTO_RPMB_BLOCK));

    uint8_t * first_8 = malloc(8);
    memcpy(first_8, data, 8);

    IFDEBUG(dzlog_debug("first_8:"));
    IFDEBUG(hdzlog_debug(first_8, 8));

    uint64_t actual_gversion = *(uint64_t *) first_8;
    IFDEBUG(dzlog_debug("actual_gversion (what RPMB reports) = %"PRIu64, actual_gversion));

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
    IFDEBUG(dzlog_debug("global_version (to be written) = %"PRIu64, global_version));

    uint8_t data[BLFS_CRYPTO_RPMB_BLOCK] = { 0 };
    memcpy(data, (uint8_t *) &global_version, sizeof(global_version));

    IFDEBUG(dzlog_debug("RPMB block to commit:"));
    IFDEBUG(hdzlog_debug(data, BLFS_CRYPTO_RPMB_BLOCK));

    volatile CEXCEPTION_T e = EXCEPTION_NO_EXCEPTION;

    Try
    {
        rpmb_write_block((uint16_t) id, data);
    }

    Catch(e)
    {
        if(e == EXCEPTION_RPMB_DOES_NOT_EXIST && BLFS_MANUAL_GV_FALLBACK != -1)
            dzlog_info("RPMB device is not able to be opened. Commit attempt was silently ignored");
        else
            Throw(e);
    }

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

    if(data_length < BLFS_CRYPTO_BYTES_AESXTS_DATA_MIN)
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

    if(data_length < BLFS_CRYPTO_BYTES_AESXTS_DATA_MIN)
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
