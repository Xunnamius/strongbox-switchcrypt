#include <limits.h>
#include <string.h>

#include "unity.h"

#ifndef __INTELLISENSE__
#include "mock_io.h"
#endif
#include "backstore.h"
#include "bitmask.h"
#include "_struts.h"

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
    char buf[100] = { 0x00 };
    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), "test");

    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        exit(EXCEPTION_ZLOG_INIT_FAILURE);
}

void tearDown(void)
{
    zlog_fini();
}

blfs_backstore_t * fake_initialize_backstore(blfs_backstore_t * backstore)
{
    backstore->cache_headers = kh_init(BLFS_KHASH_HEADERS_CACHE_NAME);
    backstore->cache_kcs_counts = kh_init(BLFS_KHASH_KCS_CACHE_NAME);
    backstore->cache_tj_entries = kh_init(BLFS_KHASH_TJ_CACHE_NAME);
    backstore->cache_nugget_md = kh_init(BLFS_KHASH_MD_CACHE_NAME);

    backstore->kcs_real_offset = 105;
    backstore->tj_real_offset = 129;
    backstore->md_real_offset = 132;

    backstore->nugget_size_bytes = 16;
    backstore->flake_size_bytes = 8;

    backstore->num_nuggets = 3;
    backstore->flakes_per_nugget = 2;

    return backstore;
}

void test_blfs_open_header_works_as_expected(void)
{
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    uint8_t expected_version[BLFS_HEAD_HEADER_BYTES_VERSION] = { 0xe0, 0x5f, 0xc, 0x88 };

    blfs_backstore_read_Expect(backstore, NULL, BLFS_HEAD_HEADER_BYTES_VERSION, 0);
    blfs_backstore_read_IgnoreArg_buffer();
    blfs_backstore_read_ReturnArrayThruPtr_buffer(expected_version, BLFS_HEAD_HEADER_BYTES_VERSION);

    blfs_header_t * actual_header = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_VERSION);

    uint8_t expected_salt[BLFS_HEAD_HEADER_BYTES_SALT] = {
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
    };

    blfs_backstore_read_Expect(backstore, NULL, BLFS_HEAD_HEADER_BYTES_SALT, 0x04);
    blfs_backstore_read_IgnoreArg_buffer();
    blfs_backstore_read_ReturnArrayThruPtr_buffer(expected_salt, BLFS_HEAD_HEADER_BYTES_SALT);

    blfs_header_t * actual_header2 = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_SALT);

    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_HEADER_TYPE_VERSION, actual_header->type);
    TEST_ASSERT_EQUAL_UINT(0x00, actual_header->data_offset);
    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_HEADER_BYTES_VERSION, actual_header->data_length);
    TEST_ASSERT_EQUAL_MEMORY(expected_version, actual_header->data, actual_header->data_length);

    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_HEADER_TYPE_SALT, actual_header2->type);
    TEST_ASSERT_EQUAL_UINT(0x04, actual_header2->data_offset);
    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_HEADER_BYTES_SALT, actual_header2->data_length);
    TEST_ASSERT_EQUAL_MEMORY(expected_salt, actual_header2->data, actual_header2->data_length);
}

void test_blfs_open_and_close_header_functions_cache_properly(void)
{
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    blfs_backstore_read_Ignore();
    blfs_header_t * actual_header = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_VERSION);
    blfs_backstore_read_Ignore();
    blfs_header_t * actual_header2 = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_VERSION);
    blfs_backstore_read_Ignore();
    blfs_header_t * actual_header3 = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);

    TEST_ASSERT_EQUAL_PTR(actual_header, actual_header2);
    TEST_ASSERT_TRUE(actual_header2 != actual_header3);

    blfs_close_header(backstore, actual_header2);

    TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_HEADERS_CACHE_NAME, backstore->cache_headers, BLFS_HEAD_HEADER_TYPE_VERSION));
}

void test_blfs_create_header_works_as_expected(void)
{
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    uint8_t data1[BLFS_HEAD_HEADER_BYTES_VERSION] = { 0x00 };
    uint8_t data2[BLFS_HEAD_HEADER_BYTES_VERIFICATION] = { 0x00 };

    blfs_header_t * actual_header1 = blfs_create_header(backstore, BLFS_HEAD_HEADER_TYPE_VERSION, data1);
    blfs_header_t * actual_header2 = blfs_create_header(backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION, data2);

    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_HEADER_TYPE_VERSION, actual_header1->type);
    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_HEADER_TYPE_VERIFICATION, actual_header2->type);

    TEST_ASSERT_EQUAL_UINT(0, actual_header1->data_offset);
    TEST_ASSERT_EQUAL_UINT(60, actual_header2->data_offset);

    TEST_ASSERT_EQUAL_UINT(4, actual_header1->data_length);
    TEST_ASSERT_EQUAL_UINT(32, actual_header2->data_length);

    TEST_ASSERT_EQUAL_MEMORY(data1, actual_header1->data, BLFS_HEAD_HEADER_BYTES_VERSION);
    TEST_ASSERT_EQUAL_MEMORY(data2, actual_header2->data, BLFS_HEAD_HEADER_BYTES_VERIFICATION);
}

void test_blfs_create_header_throws_exception_if_nugget_in_cache(void)
{
    int nugget_index = 60;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    (void) blfs_create_keycount(backstore, nugget_index);

    CEXCEPTION_T e_expected = EXCEPTION_INVALID_OPERATION;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION((void) blfs_create_keycount(backstore, nugget_index));
}

void test_blfs_commit_header_works_as_expected(void)
{
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);
    blfs_header_t * header = malloc(sizeof(blfs_header_t));

    uint8_t data[BLFS_HEAD_HEADER_BYTES_SALT] = {
        0xe0, 0x5f, 0xc, 0x88, 0xe0, 0x5f, 0xc, 0x88, 0xe0, 0x5f, 0xc, 0x88,
        0xe0, 0x5f, 0xc, 0x88
    };

    header->type = BLFS_HEAD_HEADER_TYPE_SALT;
    header->data_offset = 0x04;
    header->data_length = BLFS_HEAD_HEADER_BYTES_SALT;
    header->data = data;

    blfs_backstore_write_Expect(backstore, data, BLFS_HEAD_HEADER_BYTES_SALT, 0x04);

    blfs_commit_header(backstore, header);
}

void test_blfs_open_keycount_works_as_expected(void)
{
    int nugget_index = 555;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    uint8_t keycount[BLFS_HEAD_BYTES_KEYCOUNT] = { 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    blfs_backstore_read_Expect(backstore, NULL, BLFS_HEAD_BYTES_KEYCOUNT, backstore->kcs_real_offset + nugget_index * BLFS_HEAD_BYTES_KEYCOUNT);
    blfs_backstore_read_IgnoreArg_buffer();
    blfs_backstore_read_ReturnArrayThruPtr_buffer(keycount, BLFS_HEAD_BYTES_KEYCOUNT);

    blfs_keycount_t * actual_keycount = blfs_open_keycount(backstore, nugget_index);

    TEST_ASSERT_EQUAL_UINT(nugget_index, actual_keycount->nugget_index);
    TEST_ASSERT_EQUAL_UINT(backstore->kcs_real_offset + nugget_index * BLFS_HEAD_BYTES_KEYCOUNT, actual_keycount->data_offset);
    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_BYTES_KEYCOUNT, actual_keycount->data_length);
    TEST_ASSERT_EQUAL_MEMORY(keycount, (uint8_t *) &(actual_keycount->keycount), actual_keycount->data_length);

    uint64_t keycount2 = 123456789123;

    blfs_backstore_read_Expect(backstore, NULL, BLFS_HEAD_BYTES_KEYCOUNT, backstore->kcs_real_offset);
    blfs_backstore_read_IgnoreArg_buffer();
    blfs_backstore_read_ReturnArrayThruPtr_buffer((uint8_t *) &keycount2, BLFS_HEAD_BYTES_KEYCOUNT);

    blfs_keycount_t * actual_keycount2 = blfs_open_keycount(backstore, 0);

    TEST_ASSERT_EQUAL_UINT(0, actual_keycount2->nugget_index);
    TEST_ASSERT_EQUAL_UINT(backstore->kcs_real_offset, actual_keycount2->data_offset);
    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_BYTES_KEYCOUNT, actual_keycount2->data_length);
    TEST_ASSERT_EQUAL_UINT(keycount2, actual_keycount2->keycount);
}

void test_blfs_open_and_close_keycount_functions_cache_properly(void)
{
    int nugget_index = 50;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    blfs_backstore_read_Ignore();
    blfs_keycount_t * actual_keycount = blfs_open_keycount(backstore, nugget_index);
    blfs_backstore_read_Ignore();
    blfs_keycount_t * actual_keycount2 = blfs_open_keycount(backstore, nugget_index);
    blfs_backstore_read_Ignore();
    blfs_keycount_t * actual_keycount3 = blfs_open_keycount(backstore, 0);

    TEST_ASSERT_EQUAL_PTR(actual_keycount, actual_keycount2);
    TEST_ASSERT_TRUE(actual_keycount2 != actual_keycount3);

    blfs_close_keycount(backstore, actual_keycount2);

    TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_KCS_CACHE_NAME, backstore->cache_kcs_counts, nugget_index));
}

void test_blfs_create_keycount_works_as_expected(void)
{
    int nugget_index = 60;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    blfs_keycount_t * actual_keycount = blfs_create_keycount(backstore, nugget_index);

    TEST_ASSERT_EQUAL_UINT(nugget_index, actual_keycount->nugget_index);
    TEST_ASSERT_EQUAL_UINT(backstore->kcs_real_offset + nugget_index * BLFS_HEAD_BYTES_KEYCOUNT, actual_keycount->data_offset);
    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_BYTES_KEYCOUNT, actual_keycount->data_length);
    TEST_ASSERT_EQUAL_UINT(0, actual_keycount->keycount);
}

void test_blfs_create_keycount_throws_exception_if_nugget_in_cache(void)
{
    int nugget_index = 60;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    (void) blfs_create_keycount(backstore, nugget_index);

    CEXCEPTION_T e_expected = EXCEPTION_INVALID_OPERATION;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION((void) blfs_create_keycount(backstore, nugget_index));
}

void test_blfs_commit_keycount_works_as_expected(void)
{
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    blfs_keycount_t * count = malloc(sizeof(blfs_keycount_t));

    uint8_t data[BLFS_HEAD_BYTES_KEYCOUNT] = { 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    count->nugget_index = 25;
    count->data_offset = 0x04;
    count->data_length = BLFS_HEAD_BYTES_KEYCOUNT;
    memcpy(&(count->keycount), data, count->data_length);

    blfs_backstore_write_Expect(backstore, data, BLFS_HEAD_BYTES_KEYCOUNT, 0x04);

    blfs_commit_keycount(backstore, count);
}

void test_blfs_open_tjournal_entry_works_as_expected(void)
{
    int nugget_index = 555;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    uint8_t expected_ones[] = { 0xFF };
    uint8_t expected_zeroes[] = { 0x00 };

    blfs_backstore_read_Expect(backstore, NULL, 1, backstore->tj_real_offset + nugget_index);
    blfs_backstore_read_IgnoreArg_buffer();
    blfs_backstore_read_ReturnArrayThruPtr_buffer(expected_zeroes, 1);

    blfs_tjournal_entry_t * actual_tjournal_entry = blfs_open_tjournal_entry(backstore, nugget_index);

    TEST_ASSERT_EQUAL_UINT(nugget_index, actual_tjournal_entry->nugget_index);
    TEST_ASSERT_EQUAL_UINT(1, actual_tjournal_entry->data_length);
    TEST_ASSERT_EQUAL_UINT(backstore->tj_real_offset + nugget_index, actual_tjournal_entry->data_offset);
    TEST_ASSERT_EQUAL_MEMORY(expected_zeroes, actual_tjournal_entry->bitmask->mask, actual_tjournal_entry->data_length);

    blfs_backstore_read_Expect(backstore, NULL, 1, backstore->tj_real_offset);
    blfs_backstore_read_IgnoreArg_buffer();
    blfs_backstore_read_ReturnArrayThruPtr_buffer(expected_ones, 1);

    blfs_tjournal_entry_t * actual_tjournal_entry2 = blfs_open_tjournal_entry(backstore, 0);

    TEST_ASSERT_EQUAL_UINT(0, actual_tjournal_entry2->nugget_index);
    TEST_ASSERT_EQUAL_UINT(backstore->tj_real_offset, actual_tjournal_entry2->data_offset);
    TEST_ASSERT_EQUAL_UINT(1, actual_tjournal_entry2->data_length);
    TEST_ASSERT_EQUAL_MEMORY(expected_ones, actual_tjournal_entry2->bitmask->mask, actual_tjournal_entry2->data_length);
}

void test_blfs_open_and_close_tjournal_entry_functions_cache_properly(void)
{
    int nugget_index = 60;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    uint8_t expected_ones[1] = { 0xFF };
    uint8_t * expected_zeroes = calloc(1, sizeof(uint8_t));

    blfs_backstore_read_Expect(backstore, NULL, 1, backstore->tj_real_offset + nugget_index);
    blfs_backstore_read_IgnoreArg_buffer();
    blfs_backstore_read_ReturnArrayThruPtr_buffer(expected_zeroes, 1);

    blfs_tjournal_entry_t * actual_tjournal_entry = blfs_open_tjournal_entry(backstore, nugget_index);
    blfs_tjournal_entry_t * actual_tjournal_entry2 = blfs_open_tjournal_entry(backstore, nugget_index);

    blfs_backstore_read_Expect(backstore, NULL, 1, backstore->tj_real_offset);
    blfs_backstore_read_IgnoreArg_buffer();
    blfs_backstore_read_ReturnArrayThruPtr_buffer(expected_ones, 1);

    blfs_tjournal_entry_t * actual_tjournal_entry3 = blfs_open_tjournal_entry(backstore, 0);

    TEST_ASSERT_EQUAL_PTR(actual_tjournal_entry, actual_tjournal_entry2);
    TEST_ASSERT_TRUE(actual_tjournal_entry2 != actual_tjournal_entry3);

    blfs_close_tjournal_entry(backstore, actual_tjournal_entry2);

    TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_TJ_CACHE_NAME, backstore->cache_tj_entries, nugget_index));
}

void test_blfs_create_tjournal_entry_works_as_expected(void)
{
    int nugget_index = 60;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    uint8_t expected_zeroes[] = { 0x00 };

    blfs_tjournal_entry_t * tjournal_entry = blfs_create_tjournal_entry(backstore, nugget_index);

    TEST_ASSERT_EQUAL_UINT(nugget_index, tjournal_entry->nugget_index);
    TEST_ASSERT_EQUAL_UINT(backstore->tj_real_offset + nugget_index, tjournal_entry->data_offset);
    TEST_ASSERT_EQUAL_UINT(1, tjournal_entry->data_length);
    TEST_ASSERT_EQUAL_MEMORY(expected_zeroes, tjournal_entry->bitmask->mask, tjournal_entry->data_length);
}

void test_blfs_create_tjournal_entry_throws_exception_if_nugget_in_cache(void)
{
    int nugget_index = 60;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    (void) blfs_create_tjournal_entry(backstore, nugget_index);

    CEXCEPTION_T e_expected = EXCEPTION_INVALID_OPERATION;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION((void) blfs_create_tjournal_entry(backstore, nugget_index));
}

void test_blfs_commit_tjournal_entry_works_as_expected(void)
{
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    blfs_tjournal_entry_t * entry = malloc(sizeof(blfs_tjournal_entry_t));

    uint8_t * data = malloc(sizeof(uint8_t) * 2);
    data[0] = 0x05;
    data[1] = 0x50;

    entry->nugget_index = 50;
    entry->data_offset = 0x08;
    entry->data_length = 2;
    entry->bitmask = bitmask_init(data, entry->data_length);

    blfs_backstore_write_Expect(backstore, data, 2, 0x08);

    blfs_commit_tjournal_entry(backstore, entry);
}

void test_blfs_open_nugget_md_works_as_expected(void)
{
    int nugget_index = 555;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    uint8_t expected_output[BLFS_HEAD_BYTES_NUGGET_METADATA] = { 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t expected_ones[BLFS_HEAD_BYTES_NUGGET_METADATA] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
    uint64_t real_offset = backstore->md_real_offset + nugget_index * BLFS_HEAD_BYTES_NUGGET_METADATA;

    blfs_backstore_read_Expect(backstore, NULL, BLFS_HEAD_BYTES_NUGGET_METADATA, real_offset);
    blfs_backstore_read_IgnoreArg_buffer();
    blfs_backstore_read_ReturnArrayThruPtr_buffer(expected_output, BLFS_HEAD_BYTES_NUGGET_METADATA);

    blfs_nugget_metadata_t * actual_nugget_metadata = blfs_open_nugget_metadata(backstore, nugget_index);

    TEST_ASSERT_EQUAL_UINT(nugget_index, actual_nugget_metadata->nugget_index);
    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_BYTES_NUGGET_METADATA, actual_nugget_metadata->data_length);
    TEST_ASSERT_EQUAL_UINT(real_offset, actual_nugget_metadata->data_offset);
    TEST_ASSERT_EQUAL_UINT(expected_output[0], actual_nugget_metadata->cipher_ident);
    TEST_ASSERT_EQUAL_MEMORY(expected_output + 1, actual_nugget_metadata->data, actual_nugget_metadata->data_length - 1);

    blfs_backstore_read_Expect(backstore, NULL, BLFS_HEAD_BYTES_NUGGET_METADATA, backstore->md_real_offset);
    blfs_backstore_read_IgnoreArg_buffer();
    blfs_backstore_read_ReturnArrayThruPtr_buffer(expected_ones, BLFS_HEAD_BYTES_NUGGET_METADATA);

    blfs_nugget_metadata_t * actual_nugget_metadata2 = blfs_open_nugget_metadata(backstore, 0);

    TEST_ASSERT_EQUAL_UINT(0, actual_nugget_metadata2->nugget_index);
    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_BYTES_NUGGET_METADATA, actual_nugget_metadata2->data_length);
    TEST_ASSERT_EQUAL_UINT(backstore->md_real_offset, actual_nugget_metadata2->data_offset);
    TEST_ASSERT_EQUAL_UINT(expected_ones[0], actual_nugget_metadata2->cipher_ident);
    TEST_ASSERT_EQUAL_MEMORY(expected_ones + 1, actual_nugget_metadata2->data, actual_nugget_metadata2->data_length - 1);
}

void test_blfs_open_and_close_nugget_md_functions_cache_properly(void)
{
    int nugget_index = 50;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    uint8_t expected_output[BLFS_HEAD_BYTES_NUGGET_METADATA] = { 0x02, 0x10, 0x00, 0x0A, 0xBB, 0xC0, 0x00, 0x00 };
    uint8_t expected_ones[BLFS_HEAD_BYTES_NUGGET_METADATA] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
    uint64_t real_offset = backstore->md_real_offset + nugget_index * BLFS_HEAD_BYTES_NUGGET_METADATA;

    blfs_backstore_read_Expect(backstore, NULL, BLFS_HEAD_BYTES_NUGGET_METADATA, real_offset);
    blfs_backstore_read_IgnoreArg_buffer();
    blfs_backstore_read_ReturnArrayThruPtr_buffer(expected_output, BLFS_HEAD_BYTES_NUGGET_METADATA);

    blfs_nugget_metadata_t * actual_nugget_metadata = blfs_open_nugget_metadata(backstore, nugget_index);
    blfs_nugget_metadata_t * actual_nugget_metadata2 = blfs_open_nugget_metadata(backstore, nugget_index);

    blfs_backstore_read_Expect(backstore, NULL, BLFS_HEAD_BYTES_NUGGET_METADATA, backstore->md_real_offset);
    blfs_backstore_read_IgnoreArg_buffer();
    blfs_backstore_read_ReturnArrayThruPtr_buffer(expected_ones, BLFS_HEAD_BYTES_NUGGET_METADATA);

    blfs_nugget_metadata_t * actual_nugget_metadata3 = blfs_open_nugget_metadata(backstore, 0);

    TEST_ASSERT_EQUAL_PTR(actual_nugget_metadata, actual_nugget_metadata2);
    TEST_ASSERT_TRUE(actual_nugget_metadata2 != actual_nugget_metadata3);

    blfs_close_nugget_metadata(backstore, actual_nugget_metadata2);

    TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_MD_CACHE_NAME, backstore->cache_nugget_md, nugget_index));
}

void test_blfs_create_nugget_md_works_as_expected(void)
{
    int nugget_index = 60;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    uint8_t expected_zeroes[BLFS_HEAD_BYTES_NUGGET_METADATA] = { 0x00 };

    blfs_nugget_metadata_t * actual_nugget_metadata = blfs_create_nugget_metadata(backstore, nugget_index);

    TEST_ASSERT_EQUAL_UINT(nugget_index, actual_nugget_metadata->nugget_index);
    TEST_ASSERT_EQUAL_UINT(backstore->md_real_offset + nugget_index * BLFS_HEAD_BYTES_NUGGET_METADATA, actual_nugget_metadata->data_offset);
    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_BYTES_NUGGET_METADATA, actual_nugget_metadata->data_length);
    TEST_ASSERT_EQUAL_MEMORY(expected_zeroes + 1, actual_nugget_metadata->data, actual_nugget_metadata->data_length - 1);
}

void test_blfs_create_nugget_md_throws_exception_if_nugget_in_cache(void)
{
    int nugget_index = 50;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    (void) blfs_create_nugget_metadata(backstore, nugget_index);

    CEXCEPTION_T e_expected = EXCEPTION_INVALID_OPERATION;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION((void) blfs_create_nugget_metadata(backstore, nugget_index));
}

void test_blfs_commit_nugget_md_works_as_expected(void)
{
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    blfs_nugget_metadata_t * nugget_metadata = malloc(sizeof(blfs_nugget_metadata_t));

    uint8_t data[BLFS_HEAD_BYTES_NUGGET_METADATA] = { 0x05, 0x10, 0x0F, 0x0A, 0xBB, 0xC0, 0xDE, 0xF0 };

    nugget_metadata->cipher_ident = data[0];
    nugget_metadata->nugget_index = 25;
    nugget_metadata->data_offset = 0xF8;
    nugget_metadata->data_length = BLFS_HEAD_BYTES_NUGGET_METADATA;
    nugget_metadata->data = data + 1;

    blfs_backstore_write_Expect(backstore, data, BLFS_HEAD_BYTES_NUGGET_METADATA, 0xF8);

    blfs_commit_nugget_metadata(backstore, nugget_metadata);
}
