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
#include <assert.h>

#include "unity.h"
#include "strongbox.h"
#include "swappable.h"
#include "../src/mmc.h"

#include "_struts.h"

#define _TEST_BLFS_TPM_ID 1 // ! ensure different than prod value
#define BACKSTORE_FILE_PATH "/tmp/test.io.bin"

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

        TEST_ASSERT_EQUAL_INT_MESSAGE(0, rpmb_read_counter(dev_fd, &cnt),
            "(rpmb_read_counter failed; it is probably a key-related problem)");

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
        const uint8_t data_in[BLFS_CRYPTO_RPMB_BLOCK] = "small";
        uint8_t * data_out = calloc(BLFS_CRYPTO_RPMB_BLOCK, sizeof(*data_out));

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
        uint8_t data_in[512] = { 'A', 'a' };
        uint8_t data_out[BLFS_CRYPTO_RPMB_BLOCK];

        memset(data_in + 2, 111, 253);
        memset(data_in + 255, 222, 257);

        rpmb_write_block(_TEST_BLFS_TPM_ID, data_in);
        rpmb_read_block(_TEST_BLFS_TPM_ID, data_out);

        TEST_ASSERT_EQUAL_MEMORY(data_in, data_out, sizeof data_out);
    }
}

void test_integration_with_buselfs_works_as_expected(void)
{
    if(BLFS_MANUAL_GV_FALLBACK >= 0)
    {
        TEST_IGNORE_MESSAGE("BLFS_MANUAL_GV_FALLBACK != -1; test skipped when GV fallback is in effect!");
        return;
    }

    int iofd;

    // Initialize the dummy backstore

    buselfs_state_t * buselfs_state = malloc(sizeof *buselfs_state);

    buselfs_state->backstore                    = NULL;
    buselfs_state->cache_nugget_keys            = kh_init(BLFS_KHASH_NUGGET_KEY_CACHE_NAME);
    buselfs_state->merkle_tree                  = mt_create();
    buselfs_state->default_password             = BLFS_DEFAULT_PASS;
    buselfs_state->rpmb_secure_index            = _TEST_BLFS_TPM_ID;

    blfs_set_stream_context(buselfs_state, sc_default);

    iofd = open(BACKSTORE_FILE_PATH, O_CREAT | O_RDWR | O_TRUNC, 0777);

    buselfs_state->backstore                    = malloc(sizeof(blfs_backstore_t));
    buselfs_state->backstore->io_fd             = iofd;
    buselfs_state->backstore->body_real_offset  = 161;
    buselfs_state->backstore->file_size_actual  = (uint64_t)(sizeof buffer_init_backstore_state);

    blfs_backstore_write(buselfs_state->backstore, buffer_init_backstore_state, sizeof buffer_init_backstore_state, 0);

    // Clear the TJ

    blfs_backstore_t * backstore = blfs_backstore_open(BACKSTORE_FILE_PATH);

    blfs_tjournal_entry_t * entry0 = blfs_open_tjournal_entry(backstore, 0);
    blfs_tjournal_entry_t * entry1 = blfs_open_tjournal_entry(backstore, 1);
    blfs_tjournal_entry_t * entry2 = blfs_open_tjournal_entry(backstore, 2);

    memset(entry0->bitmask->mask, 0, entry0->data_length);
    memset(entry1->bitmask->mask, 0, entry1->data_length);
    memset(entry2->bitmask->mask, 0, entry2->data_length);

    blfs_commit_tjournal_entry(backstore, entry0);
    blfs_commit_tjournal_entry(backstore, entry1);
    blfs_commit_tjournal_entry(backstore, entry2);

    blfs_backstore_close(backstore);

    // Set proper rpmb value (0x908070609080706 == 650777868657755910)
    uint8_t data_in[BLFS_CRYPTO_RPMB_BLOCK] = { 0x06, 0x07, 0x08, 0x09, 0x06, 0x07, 0x08, 0x09 };

    assert(sizeof(data_in) - 8 > 0);

    memset(data_in + 8, 0, sizeof(data_in) - 8);

    rpmb_write_block(_TEST_BLFS_TPM_ID, data_in);

    // Run tests

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

    uint8_t buffer1[20] = { 0x00 };
    uint64_t offset1 = 28;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset1, sizeof buffer1, offset1, (void *) buselfs_state);
    buse_read(buffer1, sizeof buffer1, offset1, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset1, buffer1, sizeof buffer1);
}
