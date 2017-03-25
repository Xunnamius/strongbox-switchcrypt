/*
 * @author Bernard Dickens
 */

#include "unity.h"
#include "buselfs.h"

#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define TRY_FN_CATCH_EXCEPTION(fn_call)           \
e_actual = EXCEPTION_NO_EXCEPTION;                \
Try                                               \
{                                                 \
    fn_call;                                      \
    TEST_FAIL();                                  \
}                                                 \
Catch(e_actual)                                   \
    TEST_ASSERT_EQUAL_INT(e_expected, e_actual);

#define BACKSTORE_FILE_PATH "/tmp/test.io.bin"

int iofd;

static const uint8_t buffer_init_backstore_state[] = {
    // HEAD
    // header section
    
    0xFF, 0xFF, 0xFF, 0xFF, // BLFS_HEAD_HEADER_BYTES_VERSION

    0x8f, 0xa2, 0x0d, 0x92, 0x35, 0xd6, 0xc2, 0x4c, 0xe4, 0xbc, 0x4f, 0x47,
    0xa4, 0xce, 0x69, 0xa8, // BLFS_HEAD_HEADER_BYTES_SALT

    0xFF, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x00, 0x01, 0xFF, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xFF, 0xFF, // BLFS_HEAD_HEADER_BYTES_MTRH

    0x06, 0x07, 0x08, 0x09, 0x06, 0x07, 0x08, 0x09, // BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER

    0xEB, 0x04, 0x1D, 0xB3, 0xC6, 0xF5, 0xC3, 0xB1, 0x10, 0x19, 0x1A, 0xBF, 0x25,
    0x12, 0xBC, 0xAD, 0xAC, 0x51, 0x59, 0xCC, 0x57, 0x99, 0x9B, 0xFF, 0x67, 0x3D,
    0xDA, 0xE8, 0x6F, 0xB8, 0x8D, 0x16, 0x01, 0x38, 0x81, 0xFE, 0xD9, 0x16, 0xCA,
    0xF9, 0x85, 0x3E, 0x12, 0xEB, 0xDD, 0xFC, 0x3A, 0x6F, 0x2D, 0x8C, 0xAE, 0x09,
    0xC0, 0x82, 0x13, 0x69, 0x7F, 0xBC, 0xBF, 0x6D, 0x34, 0x6A, 0xCB, 0xB0, 0xD9,
    0x58, 0x1E, 0xDC, 0xB3, 0x35, 0x70, 0x0D, 0x4C, 0x1B, 0xE6, 0x08, 0x7E, 0x1C,
    0x0E, 0x1A, 0x20, 0x6B, 0x57, 0xB8, 0x7B, 0x58, 0x94, 0xCC, 0xF1, 0x29, 0x1E,
    0xA6, 0x9A, 0xC2, 0xFA, 0xDA, 0xFA, 0xF6, 0x72, 0x94, 0x12, 0x20, 0x9C, 0xE9,
    0xE9, 0x96, 0xB9, 0xA5, 0xA0, 0x80, 0xBA, 0x62, 0x00, 0xE3, 0x33, 0xCA, 0x60,
    0x14, 0x98, 0xCA, 0x96, 0x66, 0x6C, 0xBC, 0x07, 0xE2, 0x0D, 0x14, // BLFS_HEAD_HEADER_BYTES_VERIFICATION

    0x03, 0x00, 0x00, 0x00, // BLFS_HEAD_HEADER_BYTES_NUMNUGGETS

    0x02, 0x00, 0x00, 0x00, // BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET

    0x08, 0x00, 0x00, 0x00, // BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES

    0x3C, // BLFS_HEAD_HEADER_BYTES_INITIALIZED

    0x00, 0x00, 0x00, 0x00, // BLFS_HEAD_HEADER_BYTES_REKEYING

    // KCS
    // 3 nuggets * 8 bytes per count

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // TJ
    // 3 nuggets * 2 flakes each
    
    0xF0, 0x00,

    0xFF, 0x00,

    0x0F, 0x00,

    // JOURNALED KCS
    
    0x00, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // JOURNALED TJ
    
    0x00, 0xF0,

    // JOURNALED NUGGET
    
    0x76, 0x65, 0x73, 0x74, 0x76, 0x65, 0x73, 0x74, 0x76, 0x65, 0x73, 0x74,
    0x76, 0x65, 0x73, 0x74,

    // BODY
    // 3 nuggets * 2 flakes each * each flake is 8 bytes
    
    0x74, 0x65, 0x73, 0x74, 0x74, 0x65, 0x73, 0x74, 0x74, 0x65, 0x73, 0x74,
    0x74, 0x65, 0x73, 0x74,

    0x62, 0x65, 0x73, 0x74, 0x62, 0x65, 0x73, 0x74, 0x62, 0x65, 0x73, 0x74,
    0x62, 0x65, 0x73, 0x74,

    0x72, 0x65, 0x73, 0x74, 0x72, 0x65, 0x73, 0x74, 0x72, 0x65, 0x73, 0x74,
    0x72, 0x65, 0x73, 0x74
};

static buselfs_state_t * make_fake_state()
{
    buselfs_state_t * buselfs_state = malloc(sizeof(*buselfs_state));
    buselfs_state->backstore                = NULL;
    buselfs_state->cache_nugget_keys        = kh_init(BLFS_KHASH_NUGGET_KEY_CACHE_NAME);
    buselfs_state->merkle_tree              = mt_create();
    buselfs_state->journaling_is_enabled    = FALSE;

    return buselfs_state;
}

void setUp(void)
{
    if(sodium_init() == -1)
        exit(EXCEPTION_SODIUM_INIT_FAILURE);

    char buf[100];
    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), "test");
    
    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        exit(EXCEPTION_ZLOG_INIT_FAILURE);

    iofd = open(BACKSTORE_FILE_PATH, O_CREAT | O_RDWR | O_TRUNC, 0777);
}

void tearDown(void)
{
    zlog_fini();
    close(iofd);
    unlink(BACKSTORE_FILE_PATH);
}

void test_buse_read_works_as_expected(void)
{
    TEST_IGNORE();
}

void test_buse_write_works_as_expected(void)
{
    TEST_IGNORE();
}

void test_blfs_rekey_nugget_journaled_works_as_expected(void)
{
    TEST_IGNORE();
}

void test_blfs_soft_open_works_as_expected(void)
{
    TEST_IGNORE();
}

void test_blfs_run_mode_create_works_when_backstore_exists_already(void)
{   
    buselfs_state_t * buselfs_state = make_fake_state();
    blfs_run_mode_create(BACKSTORE_FILE_PATH, 4096, 2, 12, buselfs_state);
    blfs_backstore_t * backstore = buselfs_state->backstore;

    // Ensure initial state is accurate

    TEST_ASSERT_EQUAL_STRING(BACKSTORE_FILE_PATH, backstore->file_path);
    TEST_ASSERT_EQUAL_STRING("test.io.bin", backstore->file_name);
    TEST_ASSERT_EQUAL_UINT64(205, backstore->kcs_real_offset);
    TEST_ASSERT_EQUAL_UINT64(1109, backstore->tj_real_offset);
    TEST_ASSERT_EQUAL_UINT64(1335, backstore->kcs_journaled_offset);
    TEST_ASSERT_EQUAL_UINT64(1343, backstore->tj_journaled_offset);
    TEST_ASSERT_EQUAL_UINT64(1345, backstore->nugget_journaled_offset);
    TEST_ASSERT_EQUAL_UINT64(1369, backstore->body_real_offset);
    TEST_ASSERT_EQUAL_UINT64(2727, backstore->writeable_size_actual);
    TEST_ASSERT_EQUAL_UINT64(24, backstore->nugget_size_bytes);

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
    uint8_t zero_mtrh[BLFS_HEAD_HEADER_BYTES_MTRH] = { 0x00 };
    uint8_t zero_tpmglobalver[BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER] = { 0x00 };
    uint8_t zero_verification[BLFS_HEAD_HEADER_BYTES_VERIFICATION] = { 0x00 };
    uint8_t zero_rekeying[BLFS_HEAD_HEADER_BYTES_REKEYING] = { 0x00 };
    uint8_t zero_master_secret[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };
    uint8_t set_initialized[BLFS_HEAD_HEADER_TYPE_INITIALIZED] = { BLFS_HEAD_IS_INITIALIZED_VALUE };

    TEST_ASSERT_EQUAL_UINT32(BLFS_CURRENT_VERSION, *(uint32_t *) header_version->data);
    TEST_ASSERT_TRUE(memcmp(header_salt->data, zero_salt, BLFS_HEAD_HEADER_BYTES_SALT) != 0);
    TEST_ASSERT_TRUE(memcmp(header_mtrh->data, zero_mtrh, BLFS_HEAD_HEADER_TYPE_MTRH) != 0);
    TEST_ASSERT_TRUE(memcmp(header_tpmglobalver->data, zero_tpmglobalver, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER) != 0);
    TEST_ASSERT_TRUE(memcmp(header_verification->data, zero_verification, BLFS_HEAD_HEADER_TYPE_VERIFICATION) != 0);
    TEST_ASSERT_EQUAL_UINT32(113, *(uint32_t *) header_numnuggets->data);
    TEST_ASSERT_EQUAL_UINT32(12, *(uint32_t *) header_flakespernugget->data);
    TEST_ASSERT_EQUAL_UINT32(2, *(uint32_t *) header_flakesize_bytes->data);
    TEST_ASSERT_EQUAL_MEMORY(set_initialized, header_initialized->data, BLFS_HEAD_HEADER_BYTES_INITIALIZED);
    TEST_ASSERT_EQUAL_MEMORY(zero_rekeying, header_rekeying->data, BLFS_HEAD_HEADER_BYTES_REKEYING);

    // Ensure remaining state is accurate
    TEST_ASSERT_TRUE(memcmp(backstore->master_secret, zero_master_secret, BLFS_CRYPTO_BYTES_KDF_OUT) != 0);
}

void test_blfs_run_mode_create_works_when_backstore_DNE(void)
{
    tearDown();
    buselfs_state_t * buselfs_state = make_fake_state();
    blfs_run_mode_create(BACKSTORE_FILE_PATH, 4096, 2, 12, buselfs_state);

    blfs_backstore_t * backstore = buselfs_state->backstore;

    // Ensure initial state is accurate

    TEST_ASSERT_EQUAL_STRING(BACKSTORE_FILE_PATH, backstore->file_path);
    TEST_ASSERT_EQUAL_STRING("test.io.bin", backstore->file_name);
    TEST_ASSERT_EQUAL_UINT64(205, backstore->kcs_real_offset);
    TEST_ASSERT_EQUAL_UINT64(1109, backstore->tj_real_offset);
    TEST_ASSERT_EQUAL_UINT64(1335, backstore->kcs_journaled_offset);
    TEST_ASSERT_EQUAL_UINT64(1343, backstore->tj_journaled_offset);
    TEST_ASSERT_EQUAL_UINT64(1345, backstore->nugget_journaled_offset);
    TEST_ASSERT_EQUAL_UINT64(1369, backstore->body_real_offset);
    TEST_ASSERT_EQUAL_UINT64(2727, backstore->writeable_size_actual);
    TEST_ASSERT_EQUAL_UINT64(24, backstore->nugget_size_bytes);

    // We assume from the prior test that everything else worked out
    setUp();
}

void test_blfs_run_mode_open_works_as_expected(void)
{
    TEST_IGNORE();
}

void test_blfs_run_mode_wipe_works_as_expected(void)
{
    TEST_IGNORE();
}

void test_buselfs_main_actual_works_as_expected(void)
{
    zlog_fini();
    TEST_IGNORE();
}
