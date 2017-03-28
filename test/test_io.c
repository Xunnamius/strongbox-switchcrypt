/*
 * @author Bernard Dickens
 */

#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "unity.h"
#include "io.h"

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

int iofd;

blfs_backstore_t * fake_backstore;

static const uint8_t buffer_init_backstore_state[] = {
    // HEAD
    // header section
    
    0xFF, 0xFF, 0xFF, 0xFE, // BLFS_HEAD_HEADER_BYTES_VERSION

    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x00, // BLFS_HEAD_HEADER_BYTES_SALT

    0xFF, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x00, 0x01, 0xFF, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xFF, 0xFF, // BLFS_HEAD_HEADER_BYTES_MTRH

    0x06, 0x07, 0x08, 0x09, 0x06, 0x07, 0x08, 0x09, // BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER

    0xEB, 0x04, 0x1D, 0xB3, 0xC6, 0xF5, 0xC3, 0xB1, 0x10, 0x19, 0x1A, 0xBF,
    0x25, 0x12, 0xBC, 0xAD, 0xAC, 0x51, 0x59, 0xCC, 0x57, 0x99, 0x9B, 0xFF,
    0x67, 0x3D, 0xDA, 0xE8, 0x6F, 0xB8, 0x8D, 0x16, // BLFS_HEAD_HEADER_BYTES_VERIFICATION

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
    
    0xF0,

    0x42,

    0x0F,

    // JOURNALED KCS
    
    0x00, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // JOURNALED TJ
    
    0x00,

    // JOURNALED NUGGET
    
    0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xFF, 0x00,

    // BODY
    // 3 nuggets * 2 flakes each * each flake is 8 bytes
    
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,

    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,

    0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA,
    0x55, 0xAA, 0x55, 0xAA
};

void setUp(void)
{
    char buf[100] = { 0x00 };
    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), "test");

    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        exit(EXCEPTION_ZLOG_INIT_FAILURE);

    iofd = open(BACKSTORE_FILE_PATH, O_CREAT | O_RDWR | O_TRUNC, 0777);

    fake_backstore = malloc(sizeof(blfs_backstore_t));
    fake_backstore->io_fd = iofd;
    fake_backstore->body_real_offset = 128;
}

void tearDown(void)
{
    zlog_fini();
    close(fake_backstore->io_fd);
    unlink(BACKSTORE_FILE_PATH);
    free(fake_backstore);
}

void test_blfs_backstore_read_and_write_works_as_expected(void)
{
    int random_offset = 255;
    uint8_t buffer_actual1[1024] = { 0x00 };
    uint8_t buffer_actual2[64] = { 0x00 };
    uint8_t buffer_actual3[64] = { 0x00 };

    uint8_t * buffer_actual3_ptr = buffer_actual3;
    uint8_t * buffer_expected_zeroes = calloc(sizeof buffer_actual1, sizeof(uint8_t));

    blfs_backstore_write(fake_backstore, buffer_expected_zeroes, sizeof buffer_actual1, 0);
    blfs_backstore_read(fake_backstore, buffer_actual1, sizeof buffer_actual1, 0);

    TEST_ASSERT_EQUAL_MEMORY(buffer_expected_zeroes, buffer_actual1, sizeof buffer_actual1);

    uint8_t buffer_expected_random[sizeof buffer_actual2] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x01, 0x02, 0x03, 0x04
    };

    blfs_backstore_write(fake_backstore, buffer_expected_random, sizeof buffer_actual2, random_offset);
    blfs_backstore_read(fake_backstore, buffer_actual2, sizeof buffer_actual2, random_offset);

    TEST_ASSERT_EQUAL_MEMORY(buffer_expected_random, buffer_actual2, sizeof buffer_actual2);

    blfs_backstore_read(fake_backstore, buffer_actual3_ptr, sizeof(buffer_actual2) / 2, random_offset);
    blfs_backstore_read(fake_backstore,
                        buffer_actual3_ptr + sizeof(buffer_actual2) / 2,
                        sizeof(buffer_actual2) / 2,
                        random_offset + sizeof(buffer_actual2) / 2);

    TEST_ASSERT_EQUAL_MEMORY(buffer_expected_random, buffer_actual3, sizeof buffer_actual3);
}

void test_blfs_backstore_read_body_and_write_body_works_as_expected(void)
{
    uint8_t buffer_actual1[45] = { 0x00 };
    uint8_t buffer_actual2[256] = { 0x00 };

    uint8_t buffer_expected_random[sizeof buffer_actual2] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06
    };

    uint8_t buffer_expected_welldefined[sizeof buffer_actual2] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06
    };

    uint8_t buffer_expected_head1[sizeof buffer_actual1] = {
        0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x05, 0x06, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04
    };

    uint8_t buffer_expected_head2[16] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF
    };

    blfs_backstore_write(fake_backstore, buffer_expected_random, sizeof buffer_expected_random, 0);
    blfs_backstore_read_body(fake_backstore, buffer_actual1, sizeof buffer_actual1, 19);

    TEST_ASSERT_EQUAL_MEMORY(buffer_expected_head1, buffer_actual1, sizeof buffer_actual1);

    blfs_backstore_write_body(fake_backstore, buffer_expected_head2, sizeof buffer_expected_head2, 0);
    blfs_backstore_read(fake_backstore, buffer_actual2, sizeof buffer_actual2, 0);
    
    TEST_ASSERT_EQUAL_MEMORY(buffer_expected_welldefined, buffer_actual2, sizeof buffer_actual2);
}

void test_blfs_backstore_create_work_as_expected(void)
{
    unlink(BACKSTORE_FILE_PATH);

    blfs_backstore_t * backstore = blfs_backstore_create(BACKSTORE_FILE_PATH, 4096);

    TEST_ASSERT_EQUAL_STRING(BACKSTORE_FILE_PATH, backstore->file_path);
    TEST_ASSERT_EQUAL_STRING("test.io.bin", backstore->file_name);
    TEST_ASSERT_EQUAL_UINT(0, backstore->kcs_real_offset);
    TEST_ASSERT_EQUAL_UINT(0, backstore->tj_real_offset);
    TEST_ASSERT_EQUAL_UINT(0, backstore->kcs_journaled_offset);
    TEST_ASSERT_EQUAL_UINT(0, backstore->tj_journaled_offset);
    TEST_ASSERT_EQUAL_UINT(0, backstore->nugget_journaled_offset);
    TEST_ASSERT_EQUAL_UINT(0, backstore->body_real_offset);
    TEST_ASSERT_EQUAL_UINT(0, backstore->writeable_size_actual);
    TEST_ASSERT_EQUAL_UINT(0, backstore->nugget_size_bytes);
    TEST_ASSERT_EQUAL_UINT(0, backstore->flake_size_bytes);
    TEST_ASSERT_EQUAL_UINT(0, backstore->num_nuggets);
    TEST_ASSERT_EQUAL_UINT(0, backstore->flakes_per_nugget);
    TEST_ASSERT_EQUAL_UINT(4096, backstore->file_size_actual);
}

void test_blfs_backstore_create_throws_exception_if_backstore_file_already_exists(void)
{
    CEXCEPTION_T e_expected = EXCEPTION_FILE_ALREADY_EXISTS;
    CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION((void) blfs_backstore_create(BACKSTORE_FILE_PATH, 4096));
}

void test_blfs_backstore_open_work_as_expected(void)
{
    blfs_backstore_write(fake_backstore, buffer_init_backstore_state, sizeof buffer_init_backstore_state, 0);

    blfs_backstore_t * backstore = blfs_backstore_open(BACKSTORE_FILE_PATH);

    // backstore size should be 209 bytes
    TEST_ASSERT_EQUAL_STRING(BACKSTORE_FILE_PATH, backstore->file_path);
    TEST_ASSERT_EQUAL_STRING("test.io.bin", backstore->file_name);
    TEST_ASSERT_EQUAL_UINT(109, backstore->kcs_real_offset);
    TEST_ASSERT_EQUAL_UINT(133, backstore->tj_real_offset);
    TEST_ASSERT_EQUAL_UINT(136, backstore->kcs_journaled_offset);
    TEST_ASSERT_EQUAL_UINT(144, backstore->tj_journaled_offset);
    TEST_ASSERT_EQUAL_UINT(145, backstore->nugget_journaled_offset);
    TEST_ASSERT_EQUAL_UINT(161, backstore->body_real_offset);
    TEST_ASSERT_EQUAL_UINT(48, backstore->writeable_size_actual);
    TEST_ASSERT_EQUAL_UINT(16, backstore->nugget_size_bytes);
    TEST_ASSERT_EQUAL_UINT(8, backstore->flake_size_bytes);
    TEST_ASSERT_EQUAL_UINT(3, backstore->num_nuggets);
    TEST_ASSERT_EQUAL_UINT(2, backstore->flakes_per_nugget);
    TEST_ASSERT_EQUAL_UINT(209, backstore->file_size_actual);
}

void test_blfs_backstore_close_work_as_expected(void)
{
    blfs_backstore_write(fake_backstore, buffer_init_backstore_state, sizeof buffer_init_backstore_state, 0);
    blfs_backstore_t * backstore = blfs_backstore_open(BACKSTORE_FILE_PATH);
    blfs_backstore_close(backstore); // No errors? All good!
}
