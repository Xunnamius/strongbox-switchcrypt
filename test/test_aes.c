#include "unity.h"
#include "strongbox.h"
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

#include "_struts.h"

// ? The passwords used for this test are always "t" (without the quotes, of
// ? course)
// 
// ! Note that these tests are leaky! Cache reduction logic was not included
// ! (it's not necessary outside tests)

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
    buselfs_state->backstore->file_size_actual  = (uint64_t)(sizeof buffer_init_backstore_state_aes);

    blfs_backstore_write(buselfs_state->backstore, buffer_init_backstore_state_aes, sizeof buffer_init_backstore_state_aes, 0);
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
        // ERR_load_crypto_strings();
        // OpenSSL_add_all_algorithms();
        // OPENSSL_config(NULL);
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
