/*
 * @author Bernard Dickens
 */

#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sodium.h>
#include <errno.h>

#include "unity.h"
#include "../src/mmc.h"

#define TRY_FN_CATCH_EXCEPTION(fn_call)           \
e_actual = EXCEPTION_NO_EXCEPTION;                \
Try                                               \
{                                                 \
    fn_call;                                      \
    TEST_FAIL();                                  \
}                                                 \
Catch(e_actual)                                   \
    TEST_ASSERT_EQUAL_HEX_MESSAGE(e_expected, e_actual, "Encountered an unsuspected error condition!");

#define _TEST_BLFS_TPM_ID 0

void setUp(void)
{
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

void test_rpmb_read_counter_works_as_expected(void)
{
    if(BLFS_MANUAL_GV_FALLBACK >= 0)
        TEST_IGNORE_MESSAGE("BLFS_MANUAL_GV_FALLBACK != -1; test skipped when GV fallback is in effect!");

    else
    {
        int dev_fd;
        unsigned int cnt, cnt2;

        errno = 0;
        dev_fd = open(BLFS_RPMB_DEVICE, O_RDWR);

        if(dev_fd < 0)
        {
            IFDEBUG(dzlog_warn("RPMB device "BLFS_RPMB_DEVICE" not found: %s", strerror(errno)));
            Throw(EXCEPTION_OPEN_FAILURE);
        }

        TEST_ASSERT_EQUAL_INT_MESSAGE(0, rpmb_read_counter(dev_fd, &cnt), "(rpmb_read_counter failed; 7 = key problem)");

        rpmb_read_counter(dev_fd, &cnt2);

        TEST_ASSERT_EQUAL_INT_MESSAGE(cnt, cnt2, "INT cnt == cnt2");
    }
}

void test_rpmb_readwrite_block_works_as_expected_with_small_input(void)
{
    if(BLFS_MANUAL_GV_FALLBACK >= 0)
        TEST_IGNORE_MESSAGE("BLFS_MANUAL_GV_FALLBACK != -1; test skipped when GV fallback is in effect!");

    else
    {
        const uint8_t data_in[6] = "small";
        uint8_t data_out[BLFS_CRYPTO_RPMB_BLOCK];

        rpmb_write_block(_TEST_BLFS_TPM_ID, data_in);
        rpmb_read_block(_TEST_BLFS_TPM_ID, data_out);

        TEST_ASSERT_EQUAL_MEMORY(data_in, data_out, sizeof data_in);
    }
}

void test_rpmb_write_block_works_as_expected_with_big_input(void)
{
    if(BLFS_MANUAL_GV_FALLBACK >= 0)
        TEST_IGNORE_MESSAGE("BLFS_MANUAL_GV_FALLBACK != -1; test skipped when GV fallback is in effect!");

    else
    {
        const uint8_t data_in[BLFS_CRYPTO_RPMB_BLOCK] = "twohundredandfiftysixwordsneedstobetypedheresowecanhaveadatastructure"
                                                        "thathastwohundredandfiftysixcharactersinitbecausecharactersarealsobytes"
                                                        "sotwohundredandfiftysixcharactersisthesamethingastwohundredandfiftysixb"
                                                        "ytesfunnyhowitallworksoutinthenendifyouletit!";
        uint8_t data_out[BLFS_CRYPTO_RPMB_BLOCK];

        rpmb_write_block(_TEST_BLFS_TPM_ID, data_in);
        rpmb_read_block(_TEST_BLFS_TPM_ID, data_out);

        TEST_ASSERT_EQUAL_MEMORY(data_in, data_out, sizeof data_in);
    }
}

void test_rpmb_write_block_works_as_expected_with_big_zero_input(void)
{
    if(BLFS_MANUAL_GV_FALLBACK >= 0)
        TEST_IGNORE_MESSAGE("BLFS_MANUAL_GV_FALLBACK != -1; test skipped when GV fallback is in effect!");

    else
    {
        const uint8_t data_in[BLFS_CRYPTO_RPMB_BLOCK] = { 0 };
        uint8_t data_out[BLFS_CRYPTO_RPMB_BLOCK];

        rpmb_write_block(_TEST_BLFS_TPM_ID, data_in);
        rpmb_read_block(_TEST_BLFS_TPM_ID, data_out);

        TEST_ASSERT_EQUAL_MEMORY(data_in, data_out, sizeof data_in);
    }
}

void test_rpmb_write_block_works_as_expected_with_too_big_input(void)
{
    if(BLFS_MANUAL_GV_FALLBACK >= 0)
        TEST_IGNORE_MESSAGE("BLFS_MANUAL_GV_FALLBACK != -1; test skipped when GV fallback is in effect!");

    else
    {
        uint8_t data_in[512];
        memset(&data_in, 111, sizeof data_in);
        uint8_t data_out[BLFS_CRYPTO_RPMB_BLOCK];

        rpmb_write_block(_TEST_BLFS_TPM_ID, data_in);
        rpmb_read_block(_TEST_BLFS_TPM_ID, data_out);

        TEST_ASSERT_EQUAL_MEMORY(data_in, data_out, sizeof data_out);
    }
}
