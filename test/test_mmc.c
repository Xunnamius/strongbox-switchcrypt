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
#include "buselfs.h"
#include "swappable.h"
#include "../src/mmc.h"

#define _TEST_BLFS_TPM_ID 1 // XXX: ensure different than prod value
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

static const uint8_t buffer_init_backstore_state[/*209*/] = {
    // HEAD
    // header section
    
    0xFF, 0xFF, 0xFF, 0xFF, // BLFS_HEAD_HEADER_BYTES_VERSION

    0x8f, 0xa2, 0x0d, 0x92, 0x35, 0xd6, 0xc2, 0x4c, 0xe4, 0xbc, 0x4f, 0x47,
    0xa4, 0xce, 0x69, 0xa8, // BLFS_HEAD_HEADER_BYTES_SALT

    0x05, 0x3b, 0xd1, 0x85, 0xfd, 0xed, 0xc9, 0x22, 0x33, 0x66, 0x48, 0x27,
    0x32, 0x4e, 0x80, 0x07, 0x4c, 0x4f, 0xdc, 0x4f, 0xd5, 0x75, 0x99, 0xee,
    0xa2, 0x88, 0x18, 0x22, 0x57, 0xf5, 0x79, 0xcb, // BLFS_HEAD_HEADER_BYTES_MTRH

    0x06, 0x07, 0x08, 0x09, 0x06, 0x07, 0x08, 0x09, // BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER

    0xa7, 0x35, 0x05, 0xed, 0x0a, 0x2c, 0x81, 0xf9, 0x74, 0xf9, 0xd4, 0xe7,
    0x59, 0xaf, 0x92, 0xca, 0xe7, 0x15, 0x52, 0x04, 0xed, 0xb1, 0xb5, 0x46,
    0x24, 0x18, 0x31, 0x7f, 0xfb, 0x84, 0x79, 0x1d, // BLFS_HEAD_HEADER_BYTES_VERIFICATION

    0x03, 0x00, 0x00, 0x00, // BLFS_HEAD_HEADER_BYTES_NUMNUGGETS

    0x02, 0x00, 0x00, 0x00, // BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET

    0x08, 0x00, 0x00, 0x00, // BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES

    0x3C, // BLFS_HEAD_HEADER_BYTES_INITIALIZED

    0xFF, 0xFF, 0xFF, 0xFF, // BLFS_HEAD_HEADER_BYTES_REKEYING

    // KCS 262144
    // 3 nuggets * 8 bytes per count

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // TJ
    // 3 nuggets * 2 flakes each
    
    0xF0,

    0xFF,

    0x0F,

    // JOURNALED KCS
    
    0x00, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // JOURNALED TJ
    
    0x00,

    // JOURNALED NUGGET
    
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0F, 0x10, 0x11,

    // BODY (offset 161)
    // 3 nuggets * 2 flakes each * each flake is 8 bytes
    
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,

    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,

    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2F, 0x30, 0x31,
    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39
};


static const uint8_t decrypted_body[] = {
    0xb5, 0x26, 0x11, 0xf8, 0x1c, 0x3b, 0x99, 0xe0,
    0x64, 0xe8, 0xc6, 0xf4, 0x4d, 0xba, 0x84, 0xdd,

    0xc2, 0xd5, 0xe3, 0x56, 0xab, 0xcd, 0x6a, 0xb9,
    0x26, 0xeb, 0x39, 0x2b, 0xef, 0xc5, 0x98, 0xaf,

    0x0c, 0xe2, 0x14, 0x71, 0x32, 0xe1, 0x69, 0xf4,
    0x38, 0xad, 0xdc, 0xf8, 0x64, 0xc2, 0xd1, 0x52
};

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
