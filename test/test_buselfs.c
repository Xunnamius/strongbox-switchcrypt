#include "unity.h"
#include "buselfs.h"
#include "swappable.h"
#include "mmc.h"
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

#define _TEST_BLFS_TPM_ID 1 // XXX: ensure different than prod value
#define BACKSTORE_FILE_PATH "/tmp/test.io.bin"

static int iofd;
static buselfs_state_t * buselfs_state;
static char blockdevice[BLFS_BACKSTORE_FILENAME_MAXLEN] = { 0x00 };

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

    // KCS
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

static void make_fake_state()
{
    buselfs_state = malloc(sizeof *buselfs_state);

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

    uint8_t data_in[BLFS_CRYPTO_RPMB_BLOCK] = { 0x06, 0x07, 0x08, 0x09, 0x06, 0x07, 0x08, 0x09 };
    volatile CEXCEPTION_T e = EXCEPTION_NO_EXCEPTION;

    memset(data_in + 8, 0, sizeof(data_in) - 8);

    Try
    {
        rpmb_write_block(_TEST_BLFS_TPM_ID, data_in);
    }

    Catch(e)
    {
        if(e == EXCEPTION_RPMB_DOES_NOT_EXIST && BLFS_MANUAL_GV_FALLBACK != -1)
        {
            dzlog_warn("RPMB device is not able to be opened but BLFS_MANUAL_GV_FALLBACK (%i) is in effect; ignoring...",
                       BLFS_MANUAL_GV_FALLBACK);
        }

        else
            Throw(e);
    }
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

static int is_dummy_source()
{
    #if BLFS_DEBUG_MONITOR_POWER > 0
    char em_source[16];
    energymon mon;
    energymon_get_default(&mon);
    (void) mon.fsource(em_source, sizeof em_source);
    return !strcmp(em_source, "Dummy Source");
    #else
    return 0;
    #endif
}

static int is_sudo()
{
    return !geteuid();
}

void setUp(void)
{
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

// XXX: Also need to test a delete function to fix the memory leak issue discussed in buselfs.h

void test_adding_and_evicting_from_the_keycache_works_as_expected(void)
{
    free(buselfs_state->backstore);
    
    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        TEST_IGNORE_MESSAGE("BLFS_DEFAULT_DISABLE_KEY_CACHING is in effect, so this test will be skipped!");

    else
    {
        uint32_t nugget_index1 = 0;
        uint32_t nugget_index2 = 55;
        uint32_t nugget_index3 = 124;

        uint8_t expected_nugget_key1[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0xFF, 0xF0, 0x0F };
        uint8_t expected_nugget_key2[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0xC0, 0xAF, 0x44 };
        uint8_t expected_nugget_key3[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0xBE, 0xCD, 0x12 };

        uint8_t expected_flake_key1[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0xC0, 0xF1, 0x04 };
        uint8_t expected_flake_key2[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0xFD, 0xA0, 0xFE };
        uint8_t expected_flake_key3[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0xB4, 0xFC, 0xF2 };

        uint8_t actual_nugget_key1[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };
        uint8_t actual_nugget_key2[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };
        uint8_t actual_nugget_key3[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };

        uint8_t actual_flake_key1[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0x00 };
        uint8_t actual_flake_key2[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0x00 };
        uint8_t actual_flake_key3[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0x00 };

        add_index_to_key_cache(buselfs_state, nugget_index1, expected_nugget_key1);
        add_index_to_key_cache(buselfs_state, nugget_index2, expected_nugget_key2);
        add_index_to_key_cache(buselfs_state, nugget_index3, expected_nugget_key3);

        get_nugget_key_using_index(actual_nugget_key1, buselfs_state, nugget_index1);
        get_nugget_key_using_index(actual_nugget_key2, buselfs_state, nugget_index2);
        get_nugget_key_using_index(actual_nugget_key3, buselfs_state, nugget_index3);

        add_keychain_to_key_cache(buselfs_state, nugget_index1, 7, 4, expected_flake_key1);
        add_keychain_to_key_cache(buselfs_state, nugget_index2, 8, 5, expected_flake_key2);
        add_keychain_to_key_cache(buselfs_state, nugget_index3, 9, 6, expected_flake_key3);

        get_flake_key_using_keychain(actual_flake_key1, buselfs_state, nugget_index1, 7, 4);
        get_flake_key_using_keychain(actual_flake_key2, buselfs_state, nugget_index2, 8, 5);
        get_flake_key_using_keychain(actual_flake_key3, buselfs_state, nugget_index3, 9, 6);

        TEST_ASSERT_EQUAL_MEMORY(expected_nugget_key1, actual_nugget_key1, BLFS_CRYPTO_BYTES_KDF_OUT);
        TEST_ASSERT_EQUAL_MEMORY(expected_nugget_key2, actual_nugget_key2, BLFS_CRYPTO_BYTES_KDF_OUT);
        TEST_ASSERT_EQUAL_MEMORY(expected_nugget_key3, actual_nugget_key3, BLFS_CRYPTO_BYTES_KDF_OUT);

        TEST_ASSERT_EQUAL_MEMORY(expected_flake_key1, actual_flake_key1, BLFS_CRYPTO_BYTES_KDF_OUT);
        TEST_ASSERT_EQUAL_MEMORY(expected_flake_key2, actual_flake_key2, BLFS_CRYPTO_BYTES_KDF_OUT);
        TEST_ASSERT_EQUAL_MEMORY(expected_flake_key3, actual_flake_key3, BLFS_CRYPTO_BYTES_KDF_OUT);
    }
}

// XXX: The password used was "t" but almost no matter what you input the test will win
// XXX: Don't forget to also test using the correct password!
void test_blfs_soft_open_throws_exception_on_invalid_password(void)
{
    free(buselfs_state->backstore);

    buselfs_state->backstore = blfs_backstore_open(BACKSTORE_FILE_PATH);
    blfs_header_t * header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);
    memset(header->data, 0xFF, BLFS_HEAD_HEADER_BYTES_VERIFICATION);
    blfs_commit_header(buselfs_state->backstore, header);

    CEXCEPTION_T e_expected = EXCEPTION_BAD_PASSWORD;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION(blfs_soft_open(buselfs_state, (uint8_t)(0)));
    blfs_backstore_close(buselfs_state->backstore);
}

void test_blfs_soft_open_throws_exception_on_bad_init_header(void)
{
    free(buselfs_state->backstore);

    buselfs_state->backstore = blfs_backstore_open(BACKSTORE_FILE_PATH);
    blfs_header_t * header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_INITIALIZED);
    memset(header->data, 0xFF, BLFS_HEAD_HEADER_BYTES_INITIALIZED);
    blfs_commit_header(buselfs_state->backstore, header);

    CEXCEPTION_T e_expected = EXCEPTION_BACKSTORE_NOT_INITIALIZED;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION(blfs_soft_open(buselfs_state, (uint8_t)(0)));
    blfs_backstore_close(buselfs_state->backstore);
}

void test_blfs_soft_open_throws_exception_on_invalid_mtrh(void)
{
    uint8_t data_write[BLFS_HEAD_HEADER_BYTES_MTRH] = { 0xFF, 0xFF };
    blfs_backstore_write(buselfs_state->backstore, data_write, sizeof data_write, 20);
    free(buselfs_state->backstore);
    
    buselfs_state->backstore = blfs_backstore_open(BACKSTORE_FILE_PATH);

    CEXCEPTION_T e_expected = EXCEPTION_INTEGRITY_FAILURE;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION(blfs_soft_open(buselfs_state, (uint8_t)(0)));
    blfs_backstore_close(buselfs_state->backstore);
}

void test_blfs_soft_open_does_not_throw_exception_if_ignore_flag_is_1(void)
{
    free(buselfs_state->backstore);

    buselfs_state->backstore = blfs_backstore_open(BACKSTORE_FILE_PATH);
    blfs_header_t * header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_MTRH);
    memset(header->data, 0xFF, BLFS_HEAD_HEADER_BYTES_MTRH);
    blfs_commit_header(buselfs_state->backstore, header);

    blfs_soft_open(buselfs_state, (uint8_t)(1));
    blfs_backstore_close(buselfs_state->backstore);
}

void test_blfs_soft_open_works_as_expected(void)
{
    free(buselfs_state->backstore);

    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");

    else
    {
        buselfs_state->backstore = blfs_backstore_open(BACKSTORE_FILE_PATH);
        blfs_soft_open(buselfs_state, (uint8_t)(0));

        // Ensure initial state is accurate

        TEST_ASSERT_EQUAL_STRING(BACKSTORE_FILE_PATH, buselfs_state->backstore->file_path);
        TEST_ASSERT_EQUAL_STRING("test.io.bin", buselfs_state->backstore->file_name);
        TEST_ASSERT_EQUAL_UINT(109, buselfs_state->backstore->kcs_real_offset);
        TEST_ASSERT_EQUAL_UINT(133, buselfs_state->backstore->tj_real_offset);
        TEST_ASSERT_EQUAL_UINT(136, buselfs_state->backstore->kcs_journaled_offset);
        TEST_ASSERT_EQUAL_UINT(144, buselfs_state->backstore->tj_journaled_offset);
        TEST_ASSERT_EQUAL_UINT(145, buselfs_state->backstore->nugget_journaled_offset);
        TEST_ASSERT_EQUAL_UINT(161, buselfs_state->backstore->body_real_offset);
        TEST_ASSERT_EQUAL_UINT(48, buselfs_state->backstore->writeable_size_actual);
        TEST_ASSERT_EQUAL_UINT(16, buselfs_state->backstore->nugget_size_bytes);
        TEST_ASSERT_EQUAL_UINT(8, buselfs_state->backstore->flake_size_bytes);
        TEST_ASSERT_EQUAL_UINT(3, buselfs_state->backstore->num_nuggets);
        TEST_ASSERT_EQUAL_UINT(2, buselfs_state->backstore->flakes_per_nugget);
        TEST_ASSERT_EQUAL_UINT(209, buselfs_state->backstore->file_size_actual);


        blfs_header_t * header_version = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERSION);
        blfs_header_t * header_salt = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_SALT);
        blfs_header_t * header_mtrh = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_MTRH);
        blfs_header_t * header_tpmglobalver = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
        blfs_header_t * header_verification = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);
        blfs_header_t * header_numnuggets = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_NUMNUGGETS);
        blfs_header_t * header_flakespernugget = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET);
        blfs_header_t * header_flakesize_bytes = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES);
        blfs_header_t * header_initialized = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_INITIALIZED);
        blfs_header_t * header_rekeying = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_REKEYING);

        uint8_t expected_ver[BLFS_HEAD_HEADER_BYTES_VERSION] = { 0xFF, 0xFF, 0xFF, 0xFF };
        uint8_t expected_salt[BLFS_HEAD_HEADER_BYTES_SALT] = {
            0x8f, 0xa2, 0x0d, 0x92, 0x35, 0xd6, 0xc2, 0x4c, 0xe4, 0xbc, 0x4f, 0x47,
            0xa4, 0xce, 0x69, 0xa8
        };

        uint8_t expected_tpmglobalver[BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER] = { 0x06, 0x07, 0x08, 0x09, 0x06, 0x07, 0x08, 0x09 };
        uint8_t expected_verification[BLFS_HEAD_HEADER_BYTES_VERIFICATION] = {
            0xa7, 0x35, 0x05, 0xed, 0x0a, 0x2c, 0x81, 0xf9, 0x74, 0xf9, 0xd4, 0xe7,
            0x59, 0xaf, 0x92, 0xca, 0xe7, 0x15, 0x52, 0x04, 0xed, 0xb1, 0xb5, 0x46,
            0x24, 0x18, 0x31, 0x7f, 0xfb, 0x84, 0x79, 0x1d
        };

        uint8_t expected_rekeying[BLFS_HEAD_HEADER_BYTES_REKEYING];
        uint8_t nexpected_master_secret[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };
        uint8_t set_initialized[BLFS_HEAD_HEADER_BYTES_INITIALIZED] = { BLFS_HEAD_IS_INITIALIZED_VALUE };

        memset(expected_rekeying, 0xFF, BLFS_HEAD_HEADER_BYTES_REKEYING);

        TEST_ASSERT_EQUAL_UINT(*(uint32_t *) expected_ver, *(uint32_t *) header_version->data);
        TEST_ASSERT_EQUAL_MEMORY(expected_salt, header_salt->data, BLFS_HEAD_HEADER_BYTES_SALT);
        TEST_ASSERT_EQUAL_MEMORY(buffer_init_backstore_state + 20, header_mtrh->data, BLFS_HEAD_HEADER_BYTES_MTRH);
        TEST_ASSERT_EQUAL_MEMORY(expected_tpmglobalver, header_tpmglobalver->data, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER);
        TEST_ASSERT_EQUAL_MEMORY(expected_verification, header_verification->data, BLFS_HEAD_HEADER_BYTES_VERIFICATION);
        TEST_ASSERT_EQUAL_UINT32(3, *(uint32_t *) header_numnuggets->data);
        TEST_ASSERT_EQUAL_UINT32(2, *(uint32_t *) header_flakespernugget->data);
        TEST_ASSERT_EQUAL_UINT32(8, *(uint32_t *) header_flakesize_bytes->data);
        TEST_ASSERT_EQUAL_MEMORY(set_initialized, header_initialized->data, BLFS_HEAD_HEADER_BYTES_INITIALIZED);
        TEST_ASSERT_EQUAL_MEMORY(expected_rekeying, header_rekeying->data, BLFS_HEAD_HEADER_BYTES_REKEYING);

        // Ensure remaining state is accurate
        TEST_ASSERT_TRUE(memcmp(buselfs_state->backstore->master_secret, nexpected_master_secret, BLFS_CRYPTO_BYTES_KDF_OUT) != 0);

        blfs_backstore_close(buselfs_state->backstore);
    }
}

void test_blfs_soft_open_initializes_keycache_and_merkle_tree_properly(void)
{
    free(buselfs_state->backstore);

    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        TEST_IGNORE_MESSAGE("BLFS_DEFAULT_DISABLE_KEY_CACHING is in effect, so this test will be skipped!");

    else
    {
        buselfs_state->backstore = blfs_backstore_open(BACKSTORE_FILE_PATH);
        blfs_soft_open(buselfs_state, (uint8_t)(0));

        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "2"));
        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "3"));

        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||0||0"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||1||0"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "2||0||2"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "2||1||2"));

        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||0||2"));
        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||2||0"));
        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "3||||0"));

        blfs_header_t * version_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERSION);
        blfs_header_t * salt_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_SALT);
        blfs_header_t * tpmgv_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
        blfs_header_t * verification_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);
        blfs_header_t * numnuggets_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_NUMNUGGETS);
        blfs_header_t * flakespernugget_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET);
        blfs_header_t * flakesize_bytes_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES);
        blfs_header_t * rekeying_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_REKEYING);

        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, tpmgv_header->data, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER, 0) == MT_SUCCESS);

        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, version_header->data, BLFS_HEAD_HEADER_BYTES_VERSION, 1) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, salt_header->data, BLFS_HEAD_HEADER_BYTES_SALT, 2) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, verification_header->data, BLFS_HEAD_HEADER_BYTES_VERIFICATION, 3) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, numnuggets_header->data, BLFS_HEAD_HEADER_BYTES_NUMNUGGETS, 4) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, flakespernugget_header->data, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET, 5) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, flakesize_bytes_header->data, BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES, 6) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, rekeying_header->data, BLFS_HEAD_HEADER_BYTES_REKEYING, 7) == MT_SUCCESS);

        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 8));
        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 10));

        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 11));
        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 13));

        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 14));
        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 19));

        TEST_ASSERT_FALSE(mt_exists(buselfs_state->merkle_tree, 20));
        blfs_backstore_close(buselfs_state->backstore);
    }
}

void test_blfs_run_mode_create_works_when_backstore_exists_already(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");

    else
    {
        blfs_run_mode_create(BACKSTORE_FILE_PATH, 4096, 2, 12, buselfs_state);
        blfs_backstore_t * backstore = buselfs_state->backstore;

        // Ensure initial state is accurate

        TEST_ASSERT_EQUAL_STRING(BACKSTORE_FILE_PATH, backstore->file_path);
        TEST_ASSERT_EQUAL_STRING("test.io.bin", backstore->file_name);
        TEST_ASSERT_EQUAL_UINT(109, backstore->kcs_real_offset);
        TEST_ASSERT_EQUAL_UINT(1037, backstore->tj_real_offset);
        TEST_ASSERT_EQUAL_UINT(1269, backstore->kcs_journaled_offset);
        TEST_ASSERT_EQUAL_UINT(1277, backstore->tj_journaled_offset);
        TEST_ASSERT_EQUAL_UINT(1279, backstore->nugget_journaled_offset);
        TEST_ASSERT_EQUAL_UINT(1303, backstore->body_real_offset);
        TEST_ASSERT_EQUAL_UINT(2784, backstore->writeable_size_actual);
        TEST_ASSERT_EQUAL_UINT(24, backstore->nugget_size_bytes);
        TEST_ASSERT_EQUAL_UINT(2, backstore->flake_size_bytes);
        TEST_ASSERT_EQUAL_UINT(12, backstore->flakes_per_nugget);
        TEST_ASSERT_EQUAL_UINT(116, backstore->num_nuggets);
        TEST_ASSERT_EQUAL_UINT(4096, buselfs_state->backstore->file_size_actual);

        // Ensure headers are accurate

        blfs_header_t * header_version = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_VERSION);
        blfs_header_t * header_salt = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_SALT);
        blfs_header_t * header_mtrh = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_MTRH);
        blfs_header_t * header_tpmglobalver = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
        blfs_header_t * header_verification = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);
        blfs_header_t * header_numnuggets = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_NUMNUGGETS);
        blfs_header_t * header_flakespernugget = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET);
        blfs_header_t * header_flakesize_bytes = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES);
        blfs_header_t * header_initialized = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_INITIALIZED);
        blfs_header_t * header_rekeying = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_REKEYING);

        uint8_t zero_salt[BLFS_HEAD_HEADER_BYTES_SALT] = { 0x00 };
        uint8_t zero_tpmglobalver[BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER] = { 0x00 };
        uint8_t zero_verification[BLFS_HEAD_HEADER_BYTES_VERIFICATION] = { 0x00 };
        uint8_t zero_rekeying[BLFS_HEAD_HEADER_BYTES_REKEYING];
        uint8_t zero_master_secret[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };
        uint8_t set_initialized[BLFS_HEAD_HEADER_BYTES_INITIALIZED] = { BLFS_HEAD_IS_INITIALIZED_VALUE };

        memset(zero_rekeying, 0xFF, BLFS_HEAD_HEADER_BYTES_REKEYING);

        TEST_ASSERT_EQUAL_UINT32(BLFS_CURRENT_VERSION, *(uint32_t *) header_version->data);
        TEST_ASSERT_TRUE(memcmp(header_salt->data, zero_salt, BLFS_HEAD_HEADER_BYTES_SALT) != 0);
        TEST_ASSERT_TRUE(memcmp(header_mtrh->data, buffer_init_backstore_state + 20, BLFS_HEAD_HEADER_BYTES_MTRH) != 0);
        TEST_ASSERT_TRUE(memcmp(header_tpmglobalver->data, zero_tpmglobalver, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER) != 0);
        TEST_ASSERT_TRUE(memcmp(header_verification->data, zero_verification, BLFS_HEAD_HEADER_BYTES_VERIFICATION) != 0);
        TEST_ASSERT_EQUAL_UINT32(116, *(uint32_t *) header_numnuggets->data);
        TEST_ASSERT_EQUAL_UINT32(12, *(uint32_t *) header_flakespernugget->data);
        TEST_ASSERT_EQUAL_UINT32(2, *(uint32_t *) header_flakesize_bytes->data);
        TEST_ASSERT_EQUAL_MEMORY(set_initialized, header_initialized->data, BLFS_HEAD_HEADER_BYTES_INITIALIZED);
        TEST_ASSERT_EQUAL_MEMORY(zero_rekeying, header_rekeying->data, BLFS_HEAD_HEADER_BYTES_REKEYING);

        // Ensure remaining state is accurate
        TEST_ASSERT_TRUE(memcmp(backstore->master_secret, zero_master_secret, BLFS_CRYPTO_BYTES_KDF_OUT) != 0);

        blfs_backstore_close(buselfs_state->backstore);
    }
}

void test_blfs_run_mode_create_works_when_backstore_DNE(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");

    else
    {
        unlink(BACKSTORE_FILE_PATH);
        blfs_run_mode_create(BACKSTORE_FILE_PATH, 4096, 2, 12, buselfs_state);

        blfs_backstore_t * backstore = buselfs_state->backstore;

        // Ensure initial state is accurate

        TEST_ASSERT_EQUAL_STRING(BACKSTORE_FILE_PATH, backstore->file_path);
        TEST_ASSERT_EQUAL_STRING("test.io.bin", backstore->file_name);
        TEST_ASSERT_EQUAL_UINT(109, backstore->kcs_real_offset);
        TEST_ASSERT_EQUAL_UINT(1037, backstore->tj_real_offset);
        TEST_ASSERT_EQUAL_UINT(1269, backstore->kcs_journaled_offset);
        TEST_ASSERT_EQUAL_UINT(1277, backstore->tj_journaled_offset);
        TEST_ASSERT_EQUAL_UINT(1279, backstore->nugget_journaled_offset);
        TEST_ASSERT_EQUAL_UINT(1303, backstore->body_real_offset);
        TEST_ASSERT_EQUAL_UINT(2784, backstore->writeable_size_actual);
        TEST_ASSERT_EQUAL_UINT(24, backstore->nugget_size_bytes);
        TEST_ASSERT_EQUAL_UINT(2, backstore->flake_size_bytes);
        TEST_ASSERT_EQUAL_UINT(12, backstore->flakes_per_nugget);
        TEST_ASSERT_EQUAL_UINT(116, backstore->num_nuggets);
        TEST_ASSERT_EQUAL_UINT(4096, buselfs_state->backstore->file_size_actual);

        blfs_backstore_close(buselfs_state->backstore);
    }
}

void test_blfs_run_mode_create_initializes_keycache_and_merkle_tree_properly(void)
{
    free(buselfs_state->backstore);

    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        TEST_IGNORE_MESSAGE("BLFS_DEFAULT_DISABLE_KEY_CACHING is in effect, so this test will be skipped!");

    else if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");

    else
    {
        blfs_run_mode_create(BACKSTORE_FILE_PATH, 4096, 2, 12, buselfs_state);

        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "2"));
        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "116"));

        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||0||0"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||10||0"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "115||0||0"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "115||11||0"));

        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "116||0||0"));
        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||0||10"));
        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||12||0"));

        blfs_header_t * version_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERSION);
        blfs_header_t * salt_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_SALT);
        blfs_header_t * tpmgv_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
        blfs_header_t * verification_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);
        blfs_header_t * numnuggets_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_NUMNUGGETS);
        blfs_header_t * flakespernugget_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET);
        blfs_header_t * flakesize_bytes_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES);
        blfs_header_t * rekeying_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_REKEYING);

        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, tpmgv_header->data, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER, 0) == MT_SUCCESS);

        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, version_header->data, BLFS_HEAD_HEADER_BYTES_VERSION, 1) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, salt_header->data, BLFS_HEAD_HEADER_BYTES_SALT, 2) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, verification_header->data, BLFS_HEAD_HEADER_BYTES_VERIFICATION, 3) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, numnuggets_header->data, BLFS_HEAD_HEADER_BYTES_NUMNUGGETS, 4) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, flakespernugget_header->data, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET, 5) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, flakesize_bytes_header->data, BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES, 6) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, rekeying_header->data, BLFS_HEAD_HEADER_BYTES_REKEYING, 7) == MT_SUCCESS);

        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 8));
        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 130));

        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 124));
        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 239));

        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 240));
        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 1631));

        TEST_ASSERT_FALSE(mt_exists(buselfs_state->merkle_tree, 1632));

        blfs_backstore_close(buselfs_state->backstore);
    }
}

void test_buselfs_main_actual_throws_exception_if_wrong_argc(void)
{
   
    CEXCEPTION_T e_expected = EXCEPTION_MUST_HALT;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv[] = { "progname" };

    TRY_FN_CATCH_EXCEPTION(buselfs_main_actual(0, argv, blockdevice));
}

void test_buselfs_main_actual_throws_exception_if_bad_cmd(void)
{
    CEXCEPTION_T e_expected = EXCEPTION_UNKNOWN_MODE;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv[] = {
        "progname",
        "cmd",
        "device1"
    };
    TRY_FN_CATCH_EXCEPTION(buselfs_main_actual(3, argv, blockdevice));
}

void test_buselfs_main_actual_throws_exception_if_too_many_fpn(void)
{
    zlog_fini();

    CEXCEPTION_T e_expected = EXCEPTION_TOO_MANY_FLAKES_PER_NUGGET;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv[] = {
        "progname",
        "--flakes-per-nugget",
        "4000000000",
        "create",
        "device2"
    };

    TRY_FN_CATCH_EXCEPTION(buselfs_main_actual(5, argv, blockdevice));
}

void test_buselfs_main_actual_throws_exception_if_bad_numbers_given_as_args(void)
{
    CEXCEPTION_T e_expected = EXCEPTION_INVALID_FLAKES_PER_NUGGET;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv[] = {
        "progname",
        "--flakes-per-nugget",
        "10241024102410241024102410241024",
        "create",
        "device3"
    };

    TRY_FN_CATCH_EXCEPTION(buselfs_main_actual(5, argv, blockdevice));

    e_expected = EXCEPTION_INVALID_BACKSTORESIZE;
    e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv2[] = {
        "progname",
        "--backstore-size",
        "-5",
        "create",
        "device4"
    };

    TRY_FN_CATCH_EXCEPTION(buselfs_main_actual(5, argv2, blockdevice));

    e_expected = EXCEPTION_INVALID_BACKSTORESIZE;
    e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv3[] = {
        "progname",
        "--backstore-size",
        "40000000000",
        "create",
        "device5"
    };

    TRY_FN_CATCH_EXCEPTION(buselfs_main_actual(5, argv3, blockdevice));

    e_expected = EXCEPTION_INVALID_FLAKES_PER_NUGGET;
    e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv4[] = {
        "progname",
        "--flakes-per-nugget",
        "-5",
        "create",
        "device6"
    };

    TRY_FN_CATCH_EXCEPTION(buselfs_main_actual(5, argv4, blockdevice));

    e_expected = EXCEPTION_INVALID_FLAKES_PER_NUGGET;
    e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv5[] = {
        "progname",
        "--flakes-per-nugget",
        "5294967295",
        "create",
        "device7"
    };

    TRY_FN_CATCH_EXCEPTION(buselfs_main_actual(5, argv5, blockdevice));

    e_expected = EXCEPTION_INVALID_FLAKESIZE;
    e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv7[] = {
        "progname",
        "--flake-size",
        "-5",
        "create",
        "device8"
    };

    TRY_FN_CATCH_EXCEPTION(buselfs_main_actual(5, argv7, blockdevice));

    e_expected = EXCEPTION_INVALID_FLAKESIZE;
    e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv8[] = {
        "progname",
        "--flake-size",
        "40000000000",
        "create",
        "device9"
    };

    TRY_FN_CATCH_EXCEPTION(buselfs_main_actual(5, argv8, blockdevice));
}

void test_buselfs_main_actual_throws_exception_if_invalid_cipher(void)
{
    zlog_fini();

    CEXCEPTION_T e_expected = EXCEPTION_STRING_TO_CIPHER_FAILED;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv[] = {
        "progname",
        "--default-password",
        "--cipher",
        "fakecipher",
        "create",
        "device115"
    };

    TRY_FN_CATCH_EXCEPTION(buselfs_main_actual(6, argv, blockdevice));
}

void test_buselfs_main_actual_throws_exception_if_invalid_tpm_id(void)
{
    zlog_fini();

    CEXCEPTION_T e_expected = EXCEPTION_INVALID_TPM_ID;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv[] = {
        "progname",
        "--default-password",
        "--tpm-id",
        "fds",
        "create",
        "device115"
    };

    TRY_FN_CATCH_EXCEPTION(buselfs_main_actual(6, argv, blockdevice));

    e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv2[] = {
        "progname",
        "--default-password",
        "--tpm-id",
        "0",
        "create",
        "device115"
    };

    TRY_FN_CATCH_EXCEPTION(buselfs_main_actual(6, argv2, blockdevice));
}

void test_buselfs_main_actual_throws_exception_if_nonimpl_cipher(void)
{
    zlog_fini();

    CEXCEPTION_T e_expected = EXCEPTION_SC_ALGO_NO_IMPL;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv[] = {
        "progname",
        "--default-password",
        "--cipher",
        "sc_chacha8",
        "create",
        "device115"
    };

    TRY_FN_CATCH_EXCEPTION(buselfs_main_actual(6, argv, blockdevice));
}

// Metrics Tests

void test_blfs_energymon_init_works_as_expected(void)
{
    if(!BLFS_DEBUG_MONITOR_POWER)
    {
        TEST_IGNORE_MESSAGE("BLFS_DEBUG_MONITOR_POWER is disabled. All metric gathering tests are disabled!");
        return;
    }

    if(is_dummy_source())
    {
        TEST_IGNORE_MESSAGE("Dummy source detected. This test will be skipped.");
        return;
    }

    if(!is_sudo())
    {
        TEST_IGNORE_MESSAGE("Test skipped. You must be sudo to run this test.");
        return;
    }
    
    #if BLFS_DEBUG_MONITOR_POWER > 0
    blfs_energymon_init(buselfs_state);
    #endif
}

void test_blfs_energymon_fini_works_as_expected(void)
{
    if(!BLFS_DEBUG_MONITOR_POWER)
    {
        TEST_IGNORE_MESSAGE("BLFS_DEBUG_MONITOR_POWER is disabled. All metric gathering tests are disabled!");
        return;
    }

    if(is_dummy_source())
    {
        TEST_IGNORE_MESSAGE("Dummy source detected. This test will be skipped.");
        return;
    }

    if(!is_sudo())
    {
        TEST_IGNORE_MESSAGE("Test skipped. You must be sudo to run this test.");
        return;
    }

    #if BLFS_DEBUG_MONITOR_POWER > 0

    blfs_energymon_init(buselfs_state);
    blfs_energymon_fini(buselfs_state);
    blfs_energymon_init(buselfs_state);
    blfs_energymon_fini(buselfs_state);

    #endif
}

void test_blfs_energymon_collect_metrics_works_as_expected(void)
{
    if(!BLFS_DEBUG_MONITOR_POWER)
    {
        TEST_IGNORE_MESSAGE("BLFS_DEBUG_MONITOR_POWER is disabled. All metric gathering tests are disabled!");
        return;
    }

    if(is_dummy_source())
    {
        TEST_IGNORE_MESSAGE("Dummy source detected. This test will be skipped.");
        return;
    }

    if(!is_sudo())
    {
        TEST_IGNORE_MESSAGE("Test skipped. You must be sudo to run this test.");
        return;
    }

    #if BLFS_DEBUG_MONITOR_POWER > 0
    
    metrics_t metrics_start;
    metrics_t metrics_end;

    blfs_energymon_init(buselfs_state);
    blfs_energymon_collect_metrics(&metrics_start, buselfs_state);
    sleep(3);
    blfs_energymon_collect_metrics(&metrics_end, buselfs_state);
    blfs_energymon_fini(buselfs_state);

    TEST_ASSERT_TRUE_MESSAGE(metrics_end.energy_uj, "metrics_start.energy_uj == 0");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(metrics_start.energy_uj, metrics_end.energy_uj, "metrics_end.energy_uj <= metrics_start.energy_uj");

    TEST_ASSERT_TRUE_MESSAGE(metrics_start.time_ns, "metrics_start.time_ns == 0");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(metrics_start.time_ns, metrics_end.time_ns, "metrics_end.time_ns == metrics_start.time_ns");

    #endif
}

void test_blfs_energymon_writeout_metrics_works_as_expected(void)
{
    if(!BLFS_DEBUG_MONITOR_POWER)
    {
        TEST_IGNORE_MESSAGE("BLFS_DEBUG_MONITOR_POWER is disabled. All metric gathering tests are disabled!");
        return;
    }

    if(is_dummy_source())
    {
        TEST_IGNORE_MESSAGE("Dummy source detected. This test will be skipped.");
        return;
    }

    if(!is_sudo())
    {
        TEST_IGNORE_MESSAGE("Test skipped. You must be sudo to run this test.");
        return;
    }
    
    #if BLFS_DEBUG_MONITOR_POWER > 0

    metrics_t metrics_read_start  = { .energy_uj = 50000000,  .time_ns = 100000000000 };
    metrics_t metrics_read_end    = { .energy_uj = 100000000, .time_ns = 150000000000 };
    metrics_t metrics_write_start = { .energy_uj = 200000000, .time_ns = 250000000000 };
    metrics_t metrics_write_end   = { .energy_uj = 400000000, .time_ns = 450000000000 };

    FILE * metrics_output_fd = fopen(BLFS_ENERGYMON_OUTPUT_PATH, "w+");
    long fsize = 0;

    blfs_energymon_init(buselfs_state);
    blfs_energymon_writeout_metrics("test", &metrics_read_start, &metrics_read_end, &metrics_write_start, &metrics_write_end);

    fseek(metrics_output_fd, 0, SEEK_END);
    fsize = ftell(metrics_output_fd);
    fseek(metrics_output_fd, 0, SEEK_SET);

    char results[fsize];
    assert(fread(results, sizeof(char), fsize, metrics_output_fd) > 0);

    dzlog_notice("metrics_output_fd:\n%s\n", results);

    fclose(metrics_output_fd);
    remove(BLFS_ENERGYMON_OUTPUT_PATH);

    blfs_energymon_fini(buselfs_state);

    TEST_ASSERT_TRUE_MESSAGE(fsize, "expected a write (fsize == 0)");

    #endif
}

// XXX: All read and write tests should go below this line!

void test_buse_read_works_as_expected(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AES*_EMULATION is in effect. All non-AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer1[1] = { 0x00 };
    uint64_t offset1 = 0;

    buse_read(buffer1, sizeof buffer1, offset1, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset1, buffer1, sizeof buffer1);

    uint8_t buffer2[16] = { 0x00 };
    uint64_t offset2 = 0;

    buse_read(buffer2, sizeof buffer2, offset2, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset2, buffer2, sizeof buffer2);

    uint8_t buffer3[20] = { 0x00 };
    uint64_t offset3 = 0;

    buse_read(buffer3, sizeof buffer3, offset3, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset3, buffer3, sizeof buffer3);

    uint8_t buffer4[20] = { 0x00 };
    uint64_t offset4 = 20;

    buse_read(buffer4, sizeof buffer4, offset4, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset4, buffer4, sizeof buffer4);

    uint8_t buffer5[48] = { 0x00 };
    uint64_t offset5 = 0;

    buse_read(buffer5, sizeof buffer5, offset5, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset5, buffer5, sizeof buffer5);

    uint8_t buffer6[1] = { 0x00 };
    uint64_t offset6 = 47;

    buse_read(buffer6, sizeof buffer6, offset6, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset6, buffer6, sizeof buffer6);

    uint8_t buffer7[35] = { 0x00 };
    uint64_t offset7 = 10;

    buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset7, buffer7, sizeof buffer7);

    uint8_t buffer8[20] = { 0x00 };
    uint64_t offset8 = 28;

    buse_read(buffer8, sizeof buffer8, offset8, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset8, buffer8, sizeof buffer8);

    uint8_t buffer9[8] = { 0x00 };
    uint64_t offset9 = 1;

    buse_read(buffer9, sizeof buffer9, offset9, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset9, buffer9, sizeof buffer9);

    IFENERGYMON(blfs_energymon_fini(buselfs_state));
}

void test_buse_writeread_works_as_expected1(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

    uint8_t buffer1[20] = { 0x00 };
    uint64_t offset1 = 28;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset1, sizeof buffer1, offset1, (void *) buselfs_state);
    buse_read(buffer1, sizeof buffer1, offset1, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset1, buffer1, sizeof buffer1);
}

void test_buse_writeread_works_as_expected2(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

    uint8_t buffer2[20] = { 0x00 };
    uint64_t offset2 = 28;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset2, sizeof buffer2, offset2, (void *) buselfs_state);
    buse_read(buffer2, sizeof buffer2, offset2, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset2, buffer2, sizeof buffer2);
}

void test_buse_writeread_works_as_expected3(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

    uint8_t buffer3[48] = { 0x00 };
    uint64_t offset3 = 0;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset3, sizeof buffer3, offset3, (void *) buselfs_state);
    buse_read(buffer3, sizeof buffer3, offset3, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset3, buffer3, sizeof buffer3);
}

void test_buse_writeread_works_as_expected4(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

    uint8_t buffer4[8] = { 0x00 };
    uint64_t offset4 = 0;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset4, sizeof buffer4, offset4, (void *) buselfs_state);
    buse_read(buffer4, sizeof buffer4, offset4, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset4, buffer4, sizeof buffer4);
}

// XXX: interflake
void test_buse_writeread_works_as_expected5(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

    uint8_t buffer5[8] = { 0x00 };
    uint64_t offset5 = 1;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset5, sizeof buffer5, offset5, (void *) buselfs_state);
    buse_read(buffer5, sizeof buffer5, offset5, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset5, buffer5, sizeof buffer5);
}

void test_buse_writeread_works_as_expected6(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

    uint8_t buffer6[1] = { 0x00 };
    uint64_t offset6 = 47;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset6, sizeof buffer6, offset6, (void *) buselfs_state);
    buse_read(buffer6, sizeof buffer6, offset6, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset6, buffer6, sizeof buffer6);
}

void test_buse_writeread_works_as_expected7(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

    uint8_t buffer7[1] = { 0x00 };
    uint64_t offset7 = 35;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset7, sizeof buffer7, offset7, (void *) buselfs_state);
    buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset7, buffer7, sizeof buffer7);
}

void test_buse_writeread_works_as_expected8(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

    uint8_t buffer[8] = { 0x00 };
    uint64_t offset = 17;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset, sizeof buffer, offset, (void *) buselfs_state);
    buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset, buffer, sizeof buffer);
}

// XXX: interflake
void test_buse_writeread_works_as_expected9(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

    uint8_t buffer[32] = { 0x00 };
    uint64_t offset = 0;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset, sizeof buffer, offset, (void *) buselfs_state);
    buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset, buffer, sizeof buffer);
}

// XXX: interflake internugget
void test_buse_writeread_works_as_expected10(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

    uint8_t buffer[32] = { 0x00 };
    uint64_t offset = 1;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset, sizeof buffer, offset, (void *) buselfs_state);
    buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset, buffer, sizeof buffer);
}

// XXX: interflake internugget
void test_buse_writeread_works_as_expected11(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(1), buselfs_state);

    uint8_t buffer[46] = { 0x00 };
    uint64_t offset = 1;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset, sizeof buffer, offset, (void *) buselfs_state);
    buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset, buffer, sizeof buffer);
}

void test_buse_write_dirty_write_triggers_rekeying1(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer[8] = { 0x00 };
    uint64_t offset = 17;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset, sizeof buffer, offset, (void *) buselfs_state);
    buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset, buffer, sizeof buffer);
}

void test_buse_write_dirty_write_triggers_rekeying2(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer5[8] = { 0x00 };
    uint64_t offset5 = 1;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset5, sizeof buffer5, offset5, (void *) buselfs_state);
    buse_read(buffer5, sizeof buffer5, offset5, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset5, buffer5, sizeof buffer5);
}

void test_buse_write_dirty_write_triggers_rekeying3(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer6[1] = { 0x00 };
    uint64_t offset6 = 47;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset6, sizeof buffer6, offset6, (void *) buselfs_state);
    buse_read(buffer6, sizeof buffer6, offset6, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset6, buffer6, sizeof buffer6);
}

void test_buse_write_dirty_write_triggers_rekeying4(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer7[1] = { 0x00 };
    uint64_t offset7 = 35;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset7, sizeof buffer7, offset7, (void *) buselfs_state);
    buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset7, buffer7, sizeof buffer7);
}

void test_buse_write_dirty_write_triggers_rekeying5(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer7[1] = { 0x00 };
    uint64_t offset7 = 0;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset7, sizeof buffer7, offset7, (void *) buselfs_state);
    buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset7, buffer7, sizeof buffer7);
}

void test_buse_write_dirty_write_triggers_rekeying6(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer7[8] = { 0x00 };
    uint64_t offset7 = 0;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset7, sizeof buffer7, offset7, (void *) buselfs_state);
    buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset7, buffer7, sizeof buffer7);
}

void test_buse_write_dirty_write_triggers_rekeying7(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer7[1] = { 0x00 };
    uint64_t offset7 = 47;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset7, sizeof buffer7, offset7, (void *) buselfs_state);
    buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset7, buffer7, sizeof buffer7);
}

void test_buse_write_dirty_write_triggers_rekeying8(void)
{
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer7[8] = { 0x00 };
    uint64_t offset7 = 40;

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    buse_write(decrypted_body + offset7, sizeof buffer7, offset7, (void *) buselfs_state);
    buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);
    IFENERGYMON(blfs_energymon_fini(buselfs_state));

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset7, buffer7, sizeof buffer7);
}

static void readwrite_quicktests()
{
    dzlog_notice("Running read/write quicktests (stage 1)...\n");

    uint8_t expected_buffer1[4096];
    memset(&expected_buffer1, 0xCE, 4096);
    expected_buffer1[4095] = 0xAB;
    expected_buffer1[4094] = 0xAA;
    uint32_t offset = 0;

    IFENERGYMON(blfs_energymon_init(buselfs_state));

    for(; offset < 1024; offset++)
    {
        uint8_t buffer[sizeof expected_buffer1];

        char strbuf[100];
        snprintf(strbuf, sizeof strbuf, "loop offset: %"PRIu32, offset);

        buse_write(expected_buffer1, sizeof buffer, sizeof(buffer) * offset, (void *) buselfs_state);
        buse_read(buffer, sizeof buffer, sizeof(buffer) * offset, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected_buffer1, buffer, sizeof buffer, strbuf);
    }

    dzlog_notice("Running read/write quicktests (stage 2)...\n");

    uint8_t expected_buffer2[5000] = { 0x00 };
    memset(&expected_buffer2, 0xFA, 5000);

    for(; offset < 2048; offset+=2)
    {
        uint8_t buffer[sizeof expected_buffer2];

        char strbuf[100];
        snprintf(strbuf, sizeof strbuf, "loop offset: %"PRIu32, offset);

        buse_write(expected_buffer2, sizeof buffer, sizeof(buffer) * offset, (void *) buselfs_state);
        buse_read(buffer, sizeof buffer, sizeof(buffer) * offset, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected_buffer2, buffer, sizeof buffer, strbuf);
    }

    dzlog_notice("Running read/write quicktests (stage 3)...\n");

    // Test end writes
    uint8_t buffer[sizeof expected_buffer1];
    offset = buselfs_state->backstore->writeable_size_actual - sizeof(expected_buffer1);

    char strbuf[100];
    snprintf(strbuf, sizeof strbuf, "loop offset (final): %"PRIu32, offset);

    buse_write(expected_buffer1, sizeof buffer, offset, (void *) buselfs_state);
    buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected_buffer1, buffer, sizeof buffer, strbuf);

    IFENERGYMON(blfs_energymon_fini(buselfs_state));
}

void test_buselfs_main_actual_creates(void)
{
    zlog_fini();

    int argc = 4;

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "create",
        "device_actual1"
    };

    buselfs_state = buselfs_main_actual(argc, argv_create1, blockdevice);
    readwrite_quicktests();
}


void test_buselfs_main_actual_does_not_throw_exception_if_valid_cipher(void)
{
    zlog_fini();

    char * argv[] = {
        "progname",
        "--default-password",
        "--cipher",
        "sc_sosemanuk",
        "create",
        "device115"
    };

    buselfs_main_actual(6, argv, blockdevice);
}

void test_buselfs_main_actual_does_not_throw_exception_if_valid_tpm_id(void)
{
    zlog_fini();

    char * argv[] = {
        "progname",
        "--default-password",
        "--tpm-id",
        "115",
        "create",
        "device-115"
    };

    buselfs_main_actual(6, argv, blockdevice);
}

void test_buselfs_main_actual_creates_with_alternate_cipher_and_tpm(void)
{
    zlog_fini();

    int argc = 8;

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--tpm-id",
        "115",
        "--cipher",
        "sc_salsa8",
        "create",
        "device_actual115"
    };

    buselfs_state = buselfs_main_actual(argc, argv_create1, blockdevice);
    readwrite_quicktests();
}

/*void test_buselfs_main_actual_creates_expected_buselfs_state(void)
{
    // FIXME: something is wrong with having all of these changes at once...
    zlog_fini();

    int argc = 14;

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--tpm-id",
        "115",
        "--cipher",
        "sc_salsa8",
        "--backstore-size",
        "2048",
        "--flake-size",
        "2048",
        "--flakes-per-nugget",
        "32",
        "create",
        "device_actual-115"
    };

    buselfs_state = buselfs_main_actual(argc, argv_create1, blockdevice);
    
    TEST_ASSERT_EQUAL_UINT(sc_salsa8, buselfs_state->default_crypt_context);
    TEST_ASSERT_EQUAL_UINT(115, buselfs_state->rpmb_secure_index);
    TEST_ASSERT_EQUAL_UINT(65536, buselfs_state->backstore->nugget_size_bytes);
    TEST_ASSERT_EQUAL_UINT(2048, buselfs_state->backstore->flake_size_bytes);
    TEST_ASSERT_EQUAL_UINT(2147483648, buselfs_state->backstore->file_size_actual);
    TEST_ASSERT_EQUAL_UINT(32760, buselfs_state->backstore->num_nuggets); // XXX: space for headers!
    TEST_ASSERT_EQUAL_UINT(32, buselfs_state->backstore->flakes_per_nugget);
}*/

/*void test_buselfs_main_actual_opens(void)
{
    // FIXME

    zlog_fini();

    int argc = 4;

    char * argv_open1[] = {
        "progname",
        "--default-password",
        "open",
        "device_actual2"
    };

    buselfs_state = buselfs_main_actual(argc, argv_open1, blockdevice);
    blfs_backstore_close(buselfs_state->backstore);
}*/

/*void test_buselfs_main_actual_opens_after_create()
{
    // FIXME

    zlog_fini();

    int argc = 4;

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "create",
        "device_actual3"
    };

    buselfs_state = buselfs_main_actual(argc, argv_create1, blockdevice);

    char * argv_wipe1[] = {
        "progname",
        "--default-password",
        "wipe",
        "device_actual4"
    };

    buselfs_state = buselfs_main_actual(argc, argv_wipe1, blockdevice);

    uint8_t buffer5[8] = { 0x00 };
    uint64_t offset5 = 1;

    buse_write(decrypted_body + offset5, sizeof buffer5, offset5, (void *) buselfs_state);
    buse_read(buffer5, sizeof buffer5, offset5, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(decrypted_body + offset5, buffer5, sizeof buffer5);

    setUp();
}*/

/*void test_blfs_rekey_nugget_journaled_zeroes_out_everything_as_expected(void)
{
    // FIXME:
    // rekeying on a specific nugget on startup has the intended effect (0s written)
    TEST_IGNORE();
}

void test_blfs_incomplete_rekeying_triggers_blfs_rekey_nugget_journaled_on_startup(void)
{
    // FIXME:
    // rekeying on a specific nugget on startup has the intended effect (0s written)
    TEST_IGNORE();
}*/

/*void test_blfs_rekey_nugget_journaled_with_write_works_as_expected(void)
{
    // FIXME: need to implement crash recovery logic completely (clean out old
    // logic) before we can run this test properly
    
    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    blfs_tjournal_entry_t * entry0 = blfs_open_tjournal_entry(buselfs_state->backstore, 0);
    blfs_tjournal_entry_t * entry1 = blfs_open_tjournal_entry(buselfs_state->backstore, 1);
    blfs_tjournal_entry_t * entry2 = blfs_open_tjournal_entry(buselfs_state->backstore, 2);

    blfs_keycount_t * count0 = blfs_open_keycount(buselfs_state->backstore, 0);
    blfs_keycount_t * count1 = blfs_open_keycount(buselfs_state->backstore, 1);
    blfs_keycount_t * count2 = blfs_open_keycount(buselfs_state->backstore, 2);

    TEST_ASSERT_TRUE(bitmask_any_bits_set(entry0->bitmask, 0, 8));

    IFENERGYMON(blfs_energymon_init(buselfs_state));

    dzlog_error("[BEFORE] count0->keycount: %"PRIu64, count0->keycount);
    blfs_rekey_nugget_journaled_with_write(buselfs_state, 0, decrypted_body, 8, 0);
    dzlog_error("[AFTER!] count0->keycount: %"PRIu64, count0->keycount);

    TEST_ASSERT_TRUE(bitmask_is_bit_set(entry0->bitmask, 0));
    TEST_ASSERT_TRUE(bitmask_is_bit_set(entry0->bitmask, 1));
    TEST_ASSERT_EQUAL_UINT(1, count0->keycount); // XXX: these are getting +2'ed!

    blfs_rekey_nugget_journaled_with_write(buselfs_state, 0, decrypted_body + 1, 8, 1);

    TEST_ASSERT_TRUE(bitmask_is_bit_set(entry0->bitmask, 0));
    TEST_ASSERT_TRUE(bitmask_is_bit_set(entry0->bitmask, 1));
    TEST_ASSERT_EQUAL_UINT(2, count0->keycount);

    blfs_rekey_nugget_journaled_with_write(buselfs_state, 1, decrypted_body + 18, 8, 2);

    TEST_ASSERT_TRUE(bitmask_is_bit_set(entry1->bitmask, 0));
    TEST_ASSERT_TRUE(bitmask_is_bit_set(entry1->bitmask, 1));
    TEST_ASSERT_EQUAL_UINT(11, count1->keycount);

    blfs_rekey_nugget_journaled_with_write(buselfs_state, 2, decrypted_body + 44, 4, 12);

    TEST_ASSERT_FALSE(bitmask_is_bit_set(entry2->bitmask, 0));
    TEST_ASSERT_TRUE(bitmask_is_bit_set(entry2->bitmask, 1));
    TEST_ASSERT_EQUAL_UINT(3, count2->keycount);

    IFENERGYMON(blfs_energymon_fini(buselfs_state));
}*/

/*void test_blfs_run_mode_open_works_as_expected(void)
{
    // FIXME: fix run mode open completely first (this test uses outdated values)
    free(buselfs_state->backstore);

    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");

    else
    {
        buselfs_state->backstore = blfs_backstore_open(BACKSTORE_FILE_PATH);
        blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

        TEST_ASSERT_EQUAL_STRING(BACKSTORE_FILE_PATH, buselfs_state->backstore->file_path);
        TEST_ASSERT_EQUAL_STRING("test.io.bin", buselfs_state->backstore->file_name);
        TEST_ASSERT_EQUAL_UINT(109, buselfs_state->backstore->kcs_real_offset);
        TEST_ASSERT_EQUAL_UINT(133, buselfs_state->backstore->tj_real_offset);
        TEST_ASSERT_EQUAL_UINT(136, buselfs_state->backstore->kcs_journaled_offset);
        TEST_ASSERT_EQUAL_UINT(144, buselfs_state->backstore->tj_journaled_offset);
        TEST_ASSERT_EQUAL_UINT(145, buselfs_state->backstore->nugget_journaled_offset);
        TEST_ASSERT_EQUAL_UINT(161, buselfs_state->backstore->body_real_offset);
        TEST_ASSERT_EQUAL_UINT(48, buselfs_state->backstore->writeable_size_actual);
        TEST_ASSERT_EQUAL_UINT(16, buselfs_state->backstore->nugget_size_bytes);
        TEST_ASSERT_EQUAL_UINT(209, buselfs_state->backstore->file_size_actual);
        TEST_ASSERT_EQUAL_UINT(8, buselfs_state->backstore->flake_size_bytes);
        TEST_ASSERT_EQUAL_UINT(3, buselfs_state->backstore->num_nuggets);
        TEST_ASSERT_EQUAL_UINT(2, buselfs_state->backstore->flakes_per_nugget);
        TEST_ASSERT_EQUAL_UINT(209, buselfs_state->backstore->file_size_actual);

        blfs_backstore_close(buselfs_state->backstore);
    }
}*/

/*void test_blfs_run_mode_wipe_works_as_expected(void)
{
    // FIXME: fix run mode wipe

    free(buselfs_state->backstore);

    buselfs_state->backstore = blfs_backstore_open(BACKSTORE_FILE_PATH);

    CEXCEPTION_T e_expected = EXCEPTION_MUST_HALT;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION(blfs_run_mode_wipe(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state));

    uint8_t gv_header_zeroes[BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER] = { 0x00 };
    blfs_header_t * gv_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);

    TEST_ASSERT_EQUAL_MEMORY(gv_header_zeroes, gv_header->data, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER);

    uint8_t mtrh_header_zeroes[BLFS_HEAD_HEADER_BYTES_MTRH] = { 0x00 };
    blfs_header_t * mtrh_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_MTRH);

    TEST_ASSERT_EQUAL_MEMORY(mtrh_header_zeroes, mtrh_header->data, BLFS_HEAD_HEADER_BYTES_MTRH);

    uint8_t rekeying_header_zeroes[BLFS_HEAD_HEADER_BYTES_REKEYING];
    memset(rekeying_header_zeroes, 0xFF, BLFS_HEAD_HEADER_BYTES_REKEYING);
    blfs_header_t * rekeying_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_REKEYING);

    TEST_ASSERT_EQUAL_MEMORY(rekeying_header_zeroes, rekeying_header->data, BLFS_HEAD_HEADER_BYTES_REKEYING);

    blfs_header_t * init_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_INITIALIZED);
    uint8_t init_header_wiped[BLFS_HEAD_HEADER_BYTES_INITIALIZED] = { BLFS_HEAD_WAS_WIPED_VALUE };

    TEST_ASSERT_EQUAL_MEMORY(init_header_wiped, init_header->data, BLFS_HEAD_HEADER_BYTES_INITIALIZED);

    // The rest of the header (ksc and tj) and the journal space should be wiped
    uint64_t readsize = buselfs_state->backstore->body_real_offset - buselfs_state->backstore->kcs_real_offset;
    uint8_t * latter_head_actual = calloc(readsize, sizeof(*latter_head_actual));
    uint8_t * latter_head_zeroes = calloc(readsize, sizeof(*latter_head_zeroes));

    blfs_backstore_read(buselfs_state->backstore, latter_head_actual, readsize, buselfs_state->backstore->kcs_real_offset);

    TEST_ASSERT_EQUAL_MEMORY(latter_head_zeroes, latter_head_actual, readsize);

    free(latter_head_actual);
    free(latter_head_zeroes);

    readsize = buselfs_state->backstore->writeable_size_actual;
    latter_head_actual = calloc(readsize, sizeof(*latter_head_actual));
    latter_head_zeroes = calloc(readsize, sizeof(*latter_head_zeroes));

    blfs_backstore_read(buselfs_state->backstore, latter_head_actual, readsize, buselfs_state->backstore->body_real_offset);

    TEST_ASSERT_EQUAL_MEMORY(latter_head_zeroes, latter_head_actual, readsize);

    free(latter_head_actual);
    free(latter_head_zeroes);

    blfs_backstore_close(buselfs_state->backstore);
}*/

/*void test_blfs_run_mode_open_properly_opens_wiped_backstores(void)
{
    // FIXME: see above

    free(buselfs_state->backstore);

    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        TEST_IGNORE_MESSAGE("BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION is in effect. All non- AES-XTS emulation tests will be ignored!");
        return;
    }

    CEXCEPTION_T e_expected = EXCEPTION_MUST_HALT;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION(blfs_run_mode_wipe(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state));

    uint8_t init_header_data[BLFS_HEAD_HEADER_BYTES_INITIALIZED] = { 0x00 };
    blfs_backstore_read(buselfs_state->backstore, init_header_data, sizeof init_header_data, 104);

    TEST_ASSERT_EQUAL_UINT8(BLFS_HEAD_WAS_WIPED_VALUE, init_header_data[0]);

    blfs_backstore_close(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, 0, buselfs_state);

    uint8_t init_header_data2[BLFS_HEAD_HEADER_BYTES_INITIALIZED] = { 0x00 };
    blfs_backstore_read(buselfs_state->backstore, init_header_data2, sizeof init_header_data2, 104);

    TEST_ASSERT_EQUAL_UINT8(BLFS_HEAD_IS_INITIALIZED_VALUE, init_header_data2[0]);

    blfs_backstore_close(buselfs_state->backstore);
}*/
