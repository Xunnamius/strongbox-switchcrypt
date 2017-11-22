#include <limits.h>
#include <string.h>

#include "unity.h"
#include "swappable.h"

static stream_cipher_e test_these_ciphers[] = {
    sc_aes128_ctr,
    sc_aes256_ctr,
    sc_salsa8,
    sc_salsa12,
    sc_salsa20,
    sc_rabbit,
    sc_hc128,
    sc_sosemanuk,
};

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

void test_algos_crypt_properly(void)
{
    for(size_t ri = 0, j = COUNT(test_these_ciphers) * 2; ri < j; ++ri)
    {
        size_t i = ri / 2;

        dzlog_notice("Testing algorithm #%i", (int) test_these_ciphers[i]);

        stream_crypt_common algo = blfs_to_stream_context(test_these_ciphers[i]);

        uint8_t data[20] = "20chardat20chardat!";
        uint8_t crypted_data[sizeof data] = { 0x00 };
        uint64_t kcs_keycount = 10242048;
        uint64_t nugget_internal_offset = 64;

        uint8_t nugget_key[BLFS_CRYPTO_BYTES_AES256_KEY] = {
            0xd9, 0x76, 0xff, 0x4c, 0xd9, 0xaa, 0x1, 0xea,
            0xa5, 0xad, 0xdc, 0x68, 0xcf, 0xe1, 0x8f, 0xc1
        };

        algo(crypted_data, data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

        uint8_t crypted_data_round2[sizeof data] = { 0x00 };

        algo(crypted_data_round2, crypted_data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

        TEST_ASSERT_EQUAL_MEMORY(data, crypted_data_round2, sizeof data);

        uint8_t crypted_data_round3[1] = { 0x00 };

        algo(crypted_data_round3, data, sizeof crypted_data_round3, nugget_key, kcs_keycount, nugget_internal_offset);

        TEST_ASSERT_EQUAL_MEMORY(crypted_data, crypted_data_round3, sizeof crypted_data_round3);

        uint8_t crypted_data_round4[1] = { 0x00 };

        algo(crypted_data_round4, crypted_data_round3, sizeof crypted_data_round4, nugget_key, kcs_keycount, nugget_internal_offset);

        TEST_ASSERT_EQUAL_MEMORY(data, crypted_data_round4, sizeof crypted_data_round4);
    }
}

void test_algos_BIGLY(void)
{
    for(size_t ri = 0, j = COUNT(test_these_ciphers) * 2; ri < j; ++ri)
    {
        size_t i = ri / 2;
        
        dzlog_notice("Testing algorithm #%i", (int) test_these_ciphers[i]);

        stream_crypt_common algo = blfs_to_stream_context(test_these_ciphers[i]);
    
        uint8_t data[4096] = { 0x00 };
        randombytes_buf(data, sizeof data);

        uint8_t crypted_data[sizeof data] = { 0x00 };
        uint64_t kcs_keycount = 123456789101112;
        uint64_t nugget_internal_offset = 72;

        uint8_t nugget_key[BLFS_CRYPTO_BYTES_AES256_KEY] = {
            0xd9, 0x76, 0xff, 0x4c, 0xd9, 0xaa, 0x1, 0xea,
            0xa5, 0xad, 0xdc, 0x68, 0xcf, 0xe1, 0x8f, 0xc1
        };

        algo(crypted_data, data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

        uint8_t crypted_data_round2[sizeof data] = { 0x00 };

        algo(crypted_data_round2, crypted_data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

        TEST_ASSERT_EQUAL_MEMORY(data, crypted_data_round2, sizeof crypted_data_round2);
    }
}
