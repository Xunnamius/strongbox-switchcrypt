#include <limits.h>
#include <string.h>

#include "unity.h"
#include "crypto.h"

#define TRY_FN_CATCH_EXCEPTION(fn_call)           \
e_actual = EXCEPTION_NO_EXCEPTION;                \
Try                                               \
{                                                 \
    fn_call;                                      \
    TEST_FAIL();                                  \
}                                                 \
Catch(e_actual)                                   \
    TEST_ASSERT_EQUAL_HEX_MESSAGE(e_expected, e_actual, "Encountered an unsuspected error condition!");

#define _TEST_BLFS_TPM_ID 1

void setUp(void)
{
    static int runonce = 0;

    if(!runonce && BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        OPENSSL_config(NULL);
        runonce = 1;
    }

    if(sodium_init() == -1)
        exit(EXCEPTION_SODIUM_INIT_FAILURE);

    char buf[100] = { 0x00 };
    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), "test");

    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        exit(EXCEPTION_ZLOG_INIT_FAILURE);
}

void tearDown(void)
{
    zlog_fini();
}

void test_blfs_password_to_secret_returns_secret_as_expected(void)
{
    char passwd[10] = "10charpas";
    uint8_t salt[BLFS_CRYPTO_BYTES_KDF_SALT] = "sixteencharsalt!";
    uint8_t actual_secret1[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };
    uint8_t actual_secret2[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };

    uint8_t expected_secret[BLFS_CRYPTO_BYTES_KDF_OUT] = {
        0x6d, 0x36, 0x75, 0xbb, 0xfb, 0x93, 0xbb, 0x89, 0x90, 0x6c, 0xba, 0x50,
        0x63, 0x37, 0xb0, 0xb1, 0xd6, 0xdc, 0xd8, 0xc4, 0xa9, 0x86, 0xd8, 0x5d,
        0x9f, 0x26, 0x4a, 0x26, 0xb7, 0xbb, 0xc9, 0xfe
    };

    blfs_password_to_secret(actual_secret1, passwd, sizeof passwd, salt);
    blfs_password_to_secret(actual_secret2, passwd, sizeof passwd, salt);

    TEST_ASSERT_EQUAL_MEMORY(expected_secret, actual_secret1, BLFS_CRYPTO_BYTES_KDF_OUT);
    TEST_ASSERT_EQUAL_MEMORY(expected_secret, actual_secret2, BLFS_CRYPTO_BYTES_KDF_OUT);
}

void test_blfs_chacha20_verif_returns_expected_data(void)
{
    uint8_t actual_hash[BLFS_HEAD_HEADER_BYTES_VERIFICATION] = { 0x00 };
    uint8_t secret[BLFS_CRYPTO_BYTES_KDF_OUT] = {
        0xd9, 0x2e, 0x63, 0x4c, 0xd9, 0xaa, 0x1, 0xea, 0xa5, 0xad, 0xdc, 0x68,
        0xcf, 0xe1, 0x8f, 0xc1, 0xa7, 0xa5, 0x10, 0x4b, 0x63, 0x1b, 0x46, 0x2d,
        0x78, 0xda, 0xb6, 0x18, 0x18, 0x6, 0x19, 0xab
    };

    uint8_t expected_hash[BLFS_HEAD_HEADER_BYTES_VERIFICATION] = {
        0x96, 0x40, 0x46, 0x08, 0x30, 0x6a, 0x57, 0xab, 0x7f, 0xe7, 0x82, 0x48, 0xbe, 0x96, 0xde, 0x78,
        0x05, 0x01, 0xee, 0x93, 0x17, 0x20, 0x43, 0x1e, 0x5f, 0xb0, 0x0c, 0x7b, 0x82, 0x95, 0x2c, 0xd0
    };

    blfs_chacha20_verif(actual_hash, secret);
    TEST_ASSERT_EQUAL_MEMORY(expected_hash, actual_hash, BLFS_HEAD_HEADER_BYTES_VERIFICATION);
}

void test_blfs_chacha20_tj_hash_returns_expected_data(void)
{
    uint8_t actual_hash[BLFS_CRYPTO_BYTES_TJ_HASH_OUT] = { 0x00 };

    uint8_t secret[BLFS_CRYPTO_BYTES_KDF_OUT] = {
        0xd9, 0x2e, 0x63, 0x4c, 0xd9, 0xaa, 0x1, 0xea, 0xa5, 0xad, 0xdc, 0x68,
        0xcf, 0xe1, 0x8f, 0xc1, 0xa7, 0xa5, 0x10, 0x4b, 0x63, 0x1b, 0x46, 0x2d,
        0x78, 0xda, 0xb6, 0x18, 0x18, 0x6, 0x19, 0xab
    };

    uint8_t input_vector[] = {
        0xaa, 0x1b, 0x46, 0x2a, 0x70, 0xaa, 0x10, 0x4b, 0x63, 0xb6, 0x1f, 0x08,
        0x06
    };

    uint8_t expected_hash[BLFS_CRYPTO_BYTES_TJ_HASH_OUT] = {
        0x0f, 0x58, 0x41, 0xe2, 0xae, 0xfc, 0xc6, 0xf4, 0x99, 0xc9, 0x9e, 0xae,
        0x67, 0x94, 0xeb, 0x04
    };

    blfs_chacha20_tj_hash(actual_hash, input_vector, sizeof input_vector, secret);
    TEST_ASSERT_EQUAL_MEMORY(expected_hash, actual_hash, BLFS_CRYPTO_BYTES_TJ_HASH_OUT);
}

// XXX: upgrade this test if we ever get around to making this work for big endian systems
void test_blfs_nugget_key_from_data_fails_bad_endianness(void)
{
    uint8_t actual_nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };

    uint8_t secret[BLFS_CRYPTO_BYTES_KDF_OUT] = {
        0xd9, 0x2e, 0x63, 0x4c, 0xd9, 0xaa, 0x1, 0xea, 0xa5, 0xad, 0xdc, 0x68,
        0xcf, 0xe1, 0x8f, 0xc1, 0xa7, 0xa5, 0x10, 0x4b, 0x63, 0x1b, 0x46, 0x2d,
        0x78, 0xda, 0xb6, 0x18, 0x18, 0x6, 0x19, 0xab
    };

    uint64_t nugget_index = 10242048;

    blfs_nugget_key_from_data(actual_nugget_key, secret, nugget_index);

    // XXX: This test will fail on big endian machines!
    uint8_t expected_nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT] = {
        0xd9, 0x76, 0xff, 0x4c, 0xd9, 0xaa, 0x1, 0xea, 0xa5, 0xad, 0xdc, 0x68,
        0xcf, 0xe1, 0x8f, 0xc1, 0xa7, 0xa5, 0x10, 0x4b, 0x63, 0x1b, 0x46, 0x2d,
        0x78, 0xda, 0xb6, 0x18, 0x18, 0x6, 0x19, 0xab
    };

    TEST_ASSERT_EQUAL_MEMORY(expected_nugget_key, actual_nugget_key, BLFS_CRYPTO_BYTES_KDF_OUT);
    
}

// XXX: upgrade this test if we ever get around to making this work for big endian systems
void test_blfs_poly1305_key_from_data_fails_bad_endianness(void)
{
    uint8_t new_key[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };

    uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT] = {
        0xd9, 0x2e, 0x63, 0x4c, 0xd9, 0xaa, 0x1, 0xea, 0xa5, 0xad, 0xdc, 0x68,
        0xcf, 0xe1, 0x8f, 0xc1, 0xa7, 0xa5, 0x10, 0x4b, 0x63, 0x1b, 0x46, 0x2d,
        0x78, 0xda, 0xb6, 0x18, 0x18, 0x6, 0x19, 0xab
    };

    uint32_t flake_index = 1;
    uint64_t kcs_keycount = 2;

    blfs_poly1305_key_from_data(new_key, nugget_key, flake_index, kcs_keycount);

    // XXX: This test will fail on big endian machines!
    uint8_t expected_key[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = {
        0xdc, 0x2e, 0x63, 0x4c, 0xd9, 0xaa, 0x1, 0xea, 0xa5, 0xad, 0xdc, 0x68,
        0xcf, 0xe1, 0x8f, 0xc1, 0xa7, 0xa5, 0x10, 0x4b, 0x63, 0x1b, 0x46, 0x2d,
        0x78, 0xda, 0xb6, 0x18, 0x18, 0x6, 0x19, 0xab
    };

    TEST_ASSERT_EQUAL_MEMORY(expected_key, new_key, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY);
}

void test_blfs_poly1305_generate_tag_yields_expected_tag(void)
{
    uint8_t actual_tag[BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT] = { 0x00 };
    uint8_t data[10] = "10chardat";

    uint8_t key[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = {
        0xdf, 0x2e, 0x63, 0x4c, 0xd9, 0xaa, 0x1, 0xea, 0xa5, 0xad, 0xdc, 0x68,
        0xcf, 0xe1, 0x8f, 0xc1, 0xa7, 0xa5, 0x10, 0x4b, 0x63, 0x1b, 0x46, 0x2d,
        0x78, 0xda, 0xb6, 0x18, 0x18, 0x6, 0x19, 0xab
    };

    blfs_poly1305_generate_tag(actual_tag, data, sizeof data, key);

    uint8_t expected_tag[BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT] = {
        0xe6, 0x44, 0x53, 0x52, 0x6c, 0x90, 0x41, 0xa6, 0xad, 0x00, 0xa0, 0xe3,
        0xf8, 0x6b, 0xe3, 0xf7
    };

    TEST_ASSERT_EQUAL_MEMORY(expected_tag, actual_tag, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT);
}

void test_aesxts_in_openssl_is_supported(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect, so this test will be skipped!");

    else
    {
        // XXX" AES key + AES-XEX key (512 bits)
        uint8_t flake_key1[] = "01234567890123456789012345678901";
        uint8_t flake_key2[sizeof flake_key1] = { 0x00 };
        uint32_t sector_tweak1 = 5;
        uint32_t sector_tweak2 = 0;

        uint8_t plaintext[] = "Zara is my dog. She is a good dog.";

        uint8_t decryptedtext1[sizeof plaintext] = { 0x00 };
        uint8_t decryptedtext2[sizeof plaintext] = { 0x00 };
        uint8_t decryptedtext3[sizeof plaintext] = { 0x00 };
        uint8_t decryptedtext4[sizeof plaintext] = { 0x00 };
        uint8_t ciphertext[sizeof plaintext] = { 0x00 };

        blfs_aesxts_encrypt(ciphertext, plaintext, sizeof ciphertext, flake_key1, sector_tweak1);
        blfs_aesxts_decrypt(decryptedtext1, ciphertext, sizeof decryptedtext1, flake_key1, sector_tweak1);
        blfs_aesxts_decrypt(decryptedtext2, ciphertext, sizeof decryptedtext2, flake_key2, sector_tweak1);
        blfs_aesxts_decrypt(decryptedtext3, ciphertext, sizeof decryptedtext3, flake_key1, sector_tweak2);
        blfs_aesxts_decrypt(decryptedtext4, ciphertext, sizeof decryptedtext4, flake_key1, sector_tweak1);

        TEST_ASSERT_EQUAL_MEMORY(plaintext, decryptedtext1, sizeof plaintext);
        TEST_ASSERT_EQUAL_MEMORY(plaintext, decryptedtext4, sizeof plaintext);

        TEST_ASSERT_TRUE(memcmp(plaintext, decryptedtext2, sizeof plaintext) != 0);
        TEST_ASSERT_TRUE(memcmp(plaintext, decryptedtext3, sizeof plaintext) != 0);
    }
}

void test_aesxts_supports_sameptr_operations(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect, so this test will be skipped!");

    else
    {
        // XXX" AES key + AES-XEX key (512 bits)
        uint8_t flake_key[] = "01234567890123456789012345678901";
        uint32_t sector_tweak = 5;

        uint8_t original_data[] = "Zara is my dog. She is a good dog.";
        uint8_t data[sizeof original_data];

        memcpy(data, original_data, sizeof original_data);

        blfs_aesxts_encrypt(data, data, sizeof data, flake_key, sector_tweak);

        TEST_ASSERT_TRUE(memcmp(original_data, data, sizeof data) != 0);

        blfs_aesxts_decrypt(data, data, sizeof data, flake_key, sector_tweak);

        TEST_ASSERT_EQUAL_MEMORY(original_data, data, sizeof data);
    }
}

void test_aesxts_throws_exceptions_if_length_too_small(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect, so this test will be skipped!");

    else
    {
        uint8_t flake_key[] = "01234567890123456789012345678901";
        uint32_t sector_tweak = 5;
        uint8_t plaintext[] = "Zara";
        uint8_t ciphertext[sizeof plaintext] = { 0x00 };

        CEXCEPTION_T e_expected = EXCEPTION_AESXTS_DATA_LENGTH_TOO_SMALL;
        volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

        TRY_FN_CATCH_EXCEPTION(blfs_aesxts_encrypt(ciphertext, plaintext, sizeof ciphertext, flake_key, sector_tweak));

        e_actual = EXCEPTION_NO_EXCEPTION;

        TRY_FN_CATCH_EXCEPTION(blfs_aesxts_decrypt(plaintext, ciphertext, sizeof plaintext, flake_key, sector_tweak));
    }
}
