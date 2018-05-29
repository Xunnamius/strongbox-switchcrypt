#include "unity.h"
#include "buselfs.h"
#include "merkletree.h"
#include "mt_err.h"
#include "khash.h"

#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>

// XXX: The passwords used for this test are always "t" (without the quotes, of
// course)
// 
// XXX: Note that these tests are leaky! Cache reduction logic was not included
// (it's not necessary outside tests)

#define TRY_FN_CATCH_EXCEPTION(fn_call)           \
e_actual = EXCEPTION_NO_EXCEPTION;                \
Try                                               \
{                                                 \
    fn_call;                                      \
    TEST_FAIL();                                  \
}                                                 \
Catch(e_actual)                                   \
    TEST_ASSERT_EQUAL_HEX_MESSAGE(e_expected, e_actual, "Encountered an unsuspected error condition!");

#define BACKSTORE_FILE_PATH "/tmp/test.io.bin"

static int iofd;
static buselfs_state_t * buselfs_state;

static const uint8_t buffer_init_backstore_state[/*273*/] = {
    // HEAD
    // header section
    
    0xFF, 0xFF, 0xFF, 0xFF, // BLFS_HEAD_HEADER_BYTES_VERSION

    0x8f, 0xa2, 0x0d, 0x92, 0x35, 0xd6, 0xc2, 0x4c, 0xe4, 0xbc, 0x4f, 0x47,
    0xa4, 0xce, 0x69, 0xa8, // BLFS_HEAD_HEADER_BYTES_SALT

    0xab, 0x9d, 0x1c, 0x11, 0xbd, 0xd5, 0xe7, 0x72, 0x93, 0x8e, 0xbd, 0xb8,
    0x17, 0x7f, 0xfd, 0x56, 0x04, 0x47, 0x08, 0x46, 0x77, 0xab, 0xf9, 0x19,
    0x1e, 0x5a, 0x38, 0xd6, 0x00, 0x6e, 0xf6, 0x35, // BLFS_HEAD_HEADER_BYTES_MTRH

    0x06, 0x07, 0x08, 0x09, 0x06, 0x07, 0x08, 0x09, // BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER

    0xa7, 0x35, 0x05, 0xed, 0x0a, 0x2c, 0x81, 0xf9, 0x74, 0xf9, 0xd4, 0xe7,
    0x59, 0xaf, 0x92, 0xca, 0xe7, 0x15, 0x52, 0x04, 0xed, 0xb1, 0xb5, 0x46,
    0x24, 0x18, 0x31, 0x7f, 0xfb, 0x84, 0x79, 0x1d, // BLFS_HEAD_HEADER_BYTES_VERIFICATION

    0x03, 0x00, 0x00, 0x00, // BLFS_HEAD_HEADER_BYTES_NUMNUGGETS

    0x02, 0x00, 0x00, 0x00, // BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET

    0x10, 0x00, 0x00, 0x00, // BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES

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
    
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,

    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,

    // BODY (offset 177)
    // 3 nuggets * 2 flakes each * each flake is 16 bytes
    
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,

    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,

    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2F, 0x30, 0x31,
    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,

    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,

    0x56, 0x57, 0x58, 0x59, 0x60, 0x61, 0x62, 0x63,
    0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71,

    0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87
};

static const uint8_t random_play_data[] = {
    0x0e, 0xb3, 0x82, 0x62, 0x85, 0xb6, 0x30, 0xd9,
    0xb8, 0xe2, 0x45, 0x70, 0x74, 0xf1, 0x2d, 0x96,

    0xab, 0x4d, 0x62, 0xa5, 0x7a, 0x64, 0xd1, 0xdd,
    0xa7, 0x34, 0xb9, 0xeb, 0x8b, 0xd9, 0x6d, 0xc8,

    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2F, 0x30, 0x31,
    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,

    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,

    0x56, 0x57, 0x58, 0x59, 0x60, 0x61, 0x62, 0x63,
    0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71,

    0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87
};

static void make_fake_state()
{
    buselfs_state = malloc(sizeof(*buselfs_state));

    buselfs_state->backstore                    = NULL;
    buselfs_state->cache_nugget_keys            = kh_init(BLFS_KHASH_NUGGET_KEY_CACHE_NAME);
    buselfs_state->merkle_tree                  = mt_create();
    buselfs_state->default_password             = BLFS_DEFAULT_PASS;
    buselfs_state->rpmb_secure_index            = BLFS_DEFAULT_TPM_ID;

    iofd = open(BACKSTORE_FILE_PATH, O_CREAT | O_RDWR | O_TRUNC, 0777);

    buselfs_state->backstore = malloc(sizeof(blfs_backstore_t));
    buselfs_state->backstore->io_fd             = iofd;
    buselfs_state->backstore->body_real_offset  = 161;
    buselfs_state->backstore->file_size_actual  = (uint64_t)(sizeof buffer_init_backstore_state);

    blfs_backstore_write(buselfs_state->backstore, buffer_init_backstore_state, sizeof buffer_init_backstore_state, 0);
}

static void clear_tj()
{
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
}

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
    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), "device_test");
    
    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        exit(EXCEPTION_ZLOG_INIT_FAILURE);
    
    make_fake_state();
}

void tearDown(void)
{
    mt_delete(buselfs_state->merkle_tree);

    if(!BLFS_DEFAULT_DISABLE_KEY_CACHING)
        kh_destroy(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys);

    free(buselfs_state);
    zlog_fini();
    close(iofd);
    unlink(BACKSTORE_FILE_PATH);
}

void test_buse_writeread_works_as_expected1(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect. All AES-XTS emulation tests will be ignored!");

    else
    {
        free(buselfs_state->backstore);

        clear_tj();

        blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

        uint8_t buffer1[40] = { 0x00 };
        uint64_t offset1 = 48;

        buse_write(random_play_data + offset1, sizeof buffer1, offset1, (void *) buselfs_state);
        buse_read(buffer1, sizeof buffer1, offset1, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY(random_play_data + offset1, buffer1, sizeof buffer1);
    }
}

void test_buse_writeread_works_as_expected2(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect. All AES-XTS emulation tests will be ignored!");

    else
    {
        free(buselfs_state->backstore);

        clear_tj();

        blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

        uint8_t buffer2[40] = { 0x00 };
        uint64_t offset2 = 48;

        buse_write(random_play_data + offset2, sizeof buffer2, offset2, (void *) buselfs_state);
        buse_read(buffer2, sizeof buffer2, offset2, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY(random_play_data + offset2, buffer2, sizeof buffer2);
    }
}

void test_buse_writeread_works_as_expected3(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect. All AES-XTS emulation tests will be ignored!");

    else
    {
        free(buselfs_state->backstore);

        clear_tj();

        blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

        uint8_t buffer3[80] = { 0x00 };
        uint64_t offset3 = 0;

        buse_write(random_play_data + offset3, sizeof buffer3, offset3, (void *) buselfs_state);
        buse_read(buffer3, sizeof buffer3, offset3, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY(random_play_data + offset3, buffer3, sizeof buffer3);
    }
}

void test_buse_writeread_works_as_expected4(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect. All AES-XTS emulation tests will be ignored!");

    else
    {
        free(buselfs_state->backstore);

        clear_tj();

        blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

        uint8_t buffer4[16] = { 0x00 };
        uint64_t offset4 = 0;

        buse_write(random_play_data + offset4, sizeof buffer4, offset4, (void *) buselfs_state);
        buse_read(buffer4, sizeof buffer4, offset4, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY(random_play_data + offset4, buffer4, sizeof buffer4);
    }
}

void test_buse_writeread_works_as_expected5(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect. All AES-XTS emulation tests will be ignored!");

    else
    {
        free(buselfs_state->backstore);

        clear_tj();

        blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

        uint8_t buffer5[16] = { 0x00 };
        uint64_t offset5 = 1;

        buse_write(random_play_data + offset5, sizeof buffer5, offset5, (void *) buselfs_state);
        buse_read(buffer5, sizeof buffer5, offset5, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY(random_play_data + offset5, buffer5, sizeof buffer5);
    }
}

void test_buse_writeread_works_as_expected6(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect. All AES-XTS emulation tests will be ignored!");

    else
    {
        free(buselfs_state->backstore);

        clear_tj();

        blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

        uint8_t buffer6[1] = { 0x00 };
        uint64_t offset6 = 94;

        buse_write(random_play_data + offset6, sizeof buffer6, offset6, (void *) buselfs_state);
        buse_read(buffer6, sizeof buffer6, offset6, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY(random_play_data + offset6, buffer6, sizeof buffer6);
    }
}

void test_buse_writeread_works_as_expected7(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect. All AES-XTS emulation tests will be ignored!");

    else
    {
        free(buselfs_state->backstore);

        clear_tj();

        blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

        uint8_t buffer7[5] = { 0x00 };
        uint64_t offset7 = 70;

        buse_write(random_play_data + offset7, sizeof buffer7, offset7, (void *) buselfs_state);
        buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY(random_play_data + offset7, buffer7, sizeof buffer7);
    }
}

void test_buse_writeread_works_as_expected8(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect. All AES-XTS emulation tests will be ignored!");

    else
    {
        free(buselfs_state->backstore);

        clear_tj();

        blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

        uint8_t buffer[16] = { 0x00 };
        uint64_t offset = 34;

        buse_write(random_play_data + offset, sizeof buffer, offset, (void *) buselfs_state);
        buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY(random_play_data + offset, buffer, sizeof buffer);
    }
}

void test_buse_writeread_works_as_expected9(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect. All AES-XTS emulation tests will be ignored!");

    else
    {
        free(buselfs_state->backstore);

        clear_tj();

        blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

        uint8_t buffer5[48] = { 0x00 };
        uint64_t offset5 = 1;

        buse_write(random_play_data + offset5, sizeof buffer5, offset5, (void *) buselfs_state);
        buse_read(buffer5, sizeof buffer5, offset5, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY(random_play_data + offset5, buffer5, sizeof buffer5);
    }
}

void test_buse_writeread_works_as_expected10(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect. All AES-XTS emulation tests will be ignored!");

    else
    {
        free(buselfs_state->backstore);

        clear_tj();

        blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

        uint8_t buffer5[32] = { 0x00 };
        uint64_t offset5 = 1;

        buse_write(random_play_data + offset5, sizeof buffer5, offset5, (void *) buselfs_state);
        buse_read(buffer5, sizeof buffer5, offset5, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY(random_play_data + offset5, buffer5, sizeof buffer5);
    }
}

void test_buse_writeread_works_as_expected11(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect. All AES-XTS emulation tests will be ignored!");

    else
    {
        free(buselfs_state->backstore);

        clear_tj();

        blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

        uint8_t buffer5[32] = { 0x00 };
        uint64_t offset5 = 0;

        buse_write(random_play_data + offset5, sizeof buffer5, offset5, (void *) buselfs_state);
        buse_read(buffer5, sizeof buffer5, offset5, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY(random_play_data + offset5, buffer5, sizeof buffer5);
    }
}

void test_buse_write_dirty_write_triggers_rekeying(void)
{
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is NOT in effect. All AES-XTS emulation tests will be ignored!");

    else
    {
        free(buselfs_state->backstore);

        blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

        uint8_t buffer[48] = { 0x00 };
        uint64_t offset = 1;

        buse_write(random_play_data + offset, sizeof buffer, offset, (void *) buselfs_state);
        buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);

        offset = 10;

        buse_write(random_play_data + offset, sizeof buffer, offset, (void *) buselfs_state);
        buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY(random_play_data + offset, buffer, sizeof buffer);
    }
}
