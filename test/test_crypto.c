/*
 * @author Bernard Dickens
 */

#include <limits.h>
#include <string.h>

#include "unity.h"
#include "crypto.h"

void setUp(void)
{
    if(sodium_init() == -1)
        exit(EXCEPTION_SODIUM_INIT_FAILURE);

    char buf[100];
    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), "test");
    printf(">> %s\n", buf);
    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        exit(EXCEPTION_ZLOG_INIT_FAILURE);
}

void tearDown(void)
{
    zlog_fini();
}

void test_blfs_password_to_secret_returns_secret_as_expected(void)
{
    char passwd[10] = "10charpass";
    uint8_t salt[BLFS_CRYPTO_BYTES_KDF_SALT] = "sixteencharsalt!";
    uint8_t actual_secret1[BLFS_CRYPTO_BYTES_KDF_OUT];
    uint8_t actual_secret2[BLFS_CRYPTO_BYTES_KDF_OUT];

    uint8_t expected_secret[BLFS_CRYPTO_BYTES_KDF_OUT] = {
        0xe0, 0x5f, 0xc, 0x88, 0xc8, 0x69, 0x7e, 0xa3, 0xa6, 0x12, 0xc9, 0xb,
        0xc0, 0x38, 0x5d, 0x2a, 0x92, 0x6c, 0x5a, 0x4d, 0x8c, 0x5b, 0x6b, 0xa0,
        0xeb, 0xd8, 0x70, 0xbc, 0xaa, 0x47, 0x27, 0x40
    };

    blfs_password_to_secret(actual_secret1, passwd, sizeof passwd, salt);
    blfs_password_to_secret(actual_secret2, passwd, sizeof passwd, salt);

    TEST_ASSERT_EQUAL_MEMORY(expected_secret, actual_secret1, BLFS_CRYPTO_BYTES_KDF_OUT);
    TEST_ASSERT_EQUAL_MEMORY(expected_secret, actual_secret2, BLFS_CRYPTO_BYTES_KDF_OUT);
}

// XXX: upgrade this test if we ever get around to making this work for big endian systems
void test_blfs_nugget_key_from_data_fails_bad_endianness(void)
{
    uint8_t actual_nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT];

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
    uint8_t new_key[BLFS_CRYPTO_BYTES_KDF_OUT];

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
    uint8_t actual_tag[BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT];
    uint8_t data[10] = "10chardata";

    uint8_t key[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = {
        0xdf, 0x2e, 0x63, 0x4c, 0xd9, 0xaa, 0x1, 0xea, 0xa5, 0xad, 0xdc, 0x68,
        0xcf, 0xe1, 0x8f, 0xc1, 0xa7, 0xa5, 0x10, 0x4b, 0x63, 0x1b, 0x46, 0x2d,
        0x78, 0xda, 0xb6, 0x18, 0x18, 0x6, 0x19, 0xab
    };

    blfs_poly1305_generate_tag(actual_tag, data, sizeof data, key);

    uint8_t expected_tag[BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT] = {
        0xa0, 0x36, 0x91, 0xd7, 0x9e, 0x73, 0xf3, 0xb, 0x6b, 0x80, 0x62, 0x78,
        0xaa, 0x48, 0x9f, 0x99
    };

    TEST_ASSERT_EQUAL_MEMORY(expected_tag, actual_tag, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT);
}

void test_blfs_chacha20_crypt_crypts_properly(void)
{
    uint8_t data[10] = "10chardata";
    uint8_t crypted_data[10];
    uint64_t kcs_keycount = 10242048;
    uint64_t nugget_internal_offset = 64;

    uint8_t nugget_key[BLFS_CRYPTO_BYTES_CHACHA_KEY] = {
        0xd9, 0x76, 0xff, 0x4c, 0xd9, 0xaa, 0x1, 0xea, 0xa5, 0xad, 0xdc, 0x68,
        0xcf, 0xe1, 0x8f, 0xc1, 0xa7, 0xa5, 0x10, 0x4b, 0x63, 0x1b, 0x46, 0x2d,
        0x78, 0xda, 0xb6, 0x18, 0x18, 0x6, 0x19, 0xab
    };

    blfs_chacha20_crypt(crypted_data, data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

    uint8_t crypted_data_round2[10];

    blfs_chacha20_crypt(crypted_data_round2, crypted_data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

    TEST_ASSERT_EQUAL_MEMORY(data, crypted_data_round2, 10);
}
