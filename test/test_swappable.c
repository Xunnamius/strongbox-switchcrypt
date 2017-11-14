#include <limits.h>
#include <string.h>

#include "unity.h"
#include "swappable.h"

#define TRY_FN_CATCH_EXCEPTION(fn_call)           \
e_actual = EXCEPTION_NO_EXCEPTION;                \
Try                                               \
{                                                 \
    fn_call;                                      \
    TEST_FAIL();                                  \
}                                                 \
Catch(e_actual)                                   \
    TEST_ASSERT_EQUAL_HEX_MESSAGE(e_expected, e_actual, "Encountered an unsuspected error condition!");

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

void test_chacha20_crypts_properly(void)
{
    uint8_t data[10] = "10chardat";
    uint8_t crypted_data[10] = { 0x00 };
    uint64_t kcs_keycount = 10242048;
    uint64_t nugget_internal_offset = 64;

    uint8_t nugget_key[BLFS_CRYPTO_BYTES_CHACHA_KEY] = {
        0xd9, 0x76, 0xff, 0x4c, 0xd9, 0xaa, 0x1, 0xea, 0xa5, 0xad, 0xdc, 0x68,
        0xcf, 0xe1, 0x8f, 0xc1, 0xa7, 0xa5, 0x10, 0x4b, 0x63, 0x1b, 0x46, 0x2d,
        0x78, 0xda, 0xb6, 0x18, 0x18, 0x6, 0x19, 0xab
    };

    stream_crypt_common chacha20 = blfs_to_stream_context(sc_chacha20);

    chacha20(crypted_data, data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

    uint8_t crypted_data_round2[10] = { 0x00 };

    chacha20(crypted_data_round2, crypted_data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

    TEST_ASSERT_EQUAL_MEMORY(data, crypted_data_round2, 10);

    uint8_t crypted_data_round3[5] = { 0x00 };

    chacha20(crypted_data_round3, data, 5, nugget_key, kcs_keycount, nugget_internal_offset);

    TEST_ASSERT_EQUAL_MEMORY(crypted_data, crypted_data_round3, 5);

    uint8_t crypted_data_round4[5] = { 0x00 };

    chacha20(crypted_data_round4, crypted_data_round3, 5, nugget_key, kcs_keycount, nugget_internal_offset);

    TEST_ASSERT_EQUAL_MEMORY(data, crypted_data_round4, 5);
}

void test_chacha20_BIGLY(void)
{
    uint8_t data[4096] = { 0x00 };
    randombytes_buf(data, sizeof data);

    uint8_t crypted_data[4096] = { 0x00 };
    uint64_t kcs_keycount = 123456789101112;
    uint64_t nugget_internal_offset = 72;

    uint8_t nugget_key[BLFS_CRYPTO_BYTES_CHACHA_KEY] = {
        0xd9, 0x76, 0xff, 0x4c, 0x54, 0xaa, 0x1, 0xea, 0xa5, 0xad, 0xdc, 0x68,
        0xcf, 0xe1, 0x8f, 0xc1, 0xa7, 0xa5, 0x45, 0x4b, 0x63, 0xaa, 0x46, 0x2d,
        0x78, 0xda, 0xb6, 0x99, 0x18, 0x6, 0x19, 0xab
    };

    stream_crypt_common chacha20 = blfs_to_stream_context(sc_chacha20);

    chacha20(crypted_data, data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

    uint8_t crypted_data_round2[4096] = { 0x00 };

    chacha20(crypted_data_round2, crypted_data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

    TEST_ASSERT_EQUAL_MEMORY(data, crypted_data_round2, 4096);
}

void test_aesctr_crypts_properly(void)
{
    uint8_t data[20] = "20chardat20chardat!";
    uint8_t crypted_data[20] = { 0x00 };
    uint64_t kcs_keycount = 10242048;
    uint64_t nugget_internal_offset = 64;

    uint8_t nugget_key[BLFS_CRYPTO_BYTES_AES_KEY] = {
        0xd9, 0x76, 0xff, 0x4c, 0xd9, 0xaa, 0x1, 0xea,
        0xa5, 0xad, 0xdc, 0x68, 0xcf, 0xe1, 0x8f, 0xc1
    };

    stream_crypt_common aesctr = blfs_to_stream_context(sc_aes256_ctr);

    aesctr(crypted_data, data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

    uint8_t crypted_data_round2[20] = { 0x00 };

    aesctr(crypted_data_round2, crypted_data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

    TEST_ASSERT_EQUAL_MEMORY(data, crypted_data_round2, 20);

    uint8_t crypted_data_round3[1] = { 0x00 };

    aesctr(crypted_data_round3, data, 1, nugget_key, kcs_keycount, nugget_internal_offset);

    TEST_ASSERT_EQUAL_MEMORY(crypted_data, crypted_data_round3, 1);

    uint8_t crypted_data_round4[1] = { 0x00 };

    aesctr(crypted_data_round4, crypted_data_round3, 1, nugget_key, kcs_keycount, nugget_internal_offset);

    TEST_ASSERT_EQUAL_MEMORY(data, crypted_data_round4, 1);
}

void test_aesctr_BIGLY(void)
{
    uint8_t data[4096] = { 0x00 };
    randombytes_buf(data, sizeof data);

    uint8_t crypted_data[4096] = { 0x00 };
    uint64_t kcs_keycount = 123456789101112;
    uint64_t nugget_internal_offset = 72;

    uint8_t nugget_key[BLFS_CRYPTO_BYTES_AES_KEY] = {
        0xd9, 0x76, 0xff, 0x4c, 0xd9, 0xaa, 0x1, 0xea,
        0xa5, 0xad, 0xdc, 0x68, 0xcf, 0xe1, 0x8f, 0xc1
    };

    stream_crypt_common aesctr = blfs_to_stream_context(sc_aes256_ctr);

    aesctr(crypted_data, data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

    uint8_t crypted_data_round2[4096] = { 0x00 };

    aesctr(crypted_data_round2, crypted_data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

    TEST_ASSERT_EQUAL_MEMORY(data, crypted_data_round2, 4096);
}
