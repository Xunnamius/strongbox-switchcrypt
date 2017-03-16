/*
 * @author Bernard Dickens
 */

#include <limits.h>
#include <string.h>

#include "unity.h"
#include "mock_io.h"
#include "backstore.h"
#include "bitmask.h"

void setUp(void)
{
    char buf[100];
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

    backstore->kcs_real_offset = 12345;
    backstore->tj_real_offset = 10;

    return backstore;
}

/*void test_blfs_open_header_works_as_expected(void)
{
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    uint8_t expected_version[BLFS_HEAD_HEADER_BYTES_VERSION] = { 0xe0, 0x5f, 0xc, 0x88 };

    blfs_backstore_read_head_Expect(backstore, NULL, BLFS_HEAD_HEADER_BYTES_VERSION, 0);
    blfs_backstore_read_head_IgnoreArg_buffer();
    blfs_backstore_read_head_ReturnArrayThruPtr_buffer(expected_version, BLFS_HEAD_HEADER_BYTES_VERSION);

    blfs_header_t * actual_header = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_VERSION);

    uint8_t expected_rekeying[BLFS_HEAD_HEADER_BYTES_REKEYING] = { 0x01 };

    blfs_backstore_read_head_Expect(backstore, NULL, BLFS_HEAD_HEADER_BYTES_REKEYING, 0xC9);
    blfs_backstore_read_head_IgnoreArg_buffer();
    blfs_backstore_read_head_ReturnArrayThruPtr_buffer(expected_rekeying, BLFS_HEAD_HEADER_BYTES_REKEYING);

    blfs_header_t * actual_header2 = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_REKEYING);

    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_HEADER_TYPE_VERSION, actual_header->type);
    TEST_ASSERT_EQUAL_UINT(0x00, actual_header->data_offset);
    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_HEADER_BYTES_VERSION, actual_header->data_length);
    TEST_ASSERT_EQUAL_MEMORY(expected_version, actual_header->data, actual_header->data_length);

    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_HEADER_TYPE_REKEYING, actual_header2->type);
    TEST_ASSERT_EQUAL_UINT(0xC9, actual_header2->data_offset);
    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_HEADER_BYTES_REKEYING, actual_header2->data_length);
    TEST_ASSERT_EQUAL_MEMORY(expected_rekeying, actual_header2->data, actual_header2->data_length);
}

void test_blfs_open_and_close_header_functions_cache_properly(void)
{
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    blfs_backstore_read_head_Ignore();
    blfs_header_t * actual_header = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_VERSION);
    blfs_backstore_read_head_Ignore();
    blfs_header_t * actual_header2 = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_VERSION);
    blfs_backstore_read_head_Ignore();
    blfs_header_t * actual_header3 = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);

    TEST_ASSERT_EQUAL_PTR(actual_header, actual_header2);
    TEST_ASSERT_TRUE(actual_header2 != actual_header3);

    blfs_close_header(backstore, actual_header2);

    TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_HEADERS_CACHE_NAME, backstore->cache_headers, BLFS_HEAD_HEADER_TYPE_VERSION));
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

    blfs_backstore_write_head_Expect(backstore, data, BLFS_HEAD_HEADER_BYTES_SALT, 0x04);

    blfs_commit_header(backstore, header);
}*/

void test_blfs_open_keycount_works_as_expected(void)
{
    int nugget_index = 555;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    uint8_t * keycount = calloc(BLFS_HEAD_BYTES_KEYCOUNT, sizeof(uint8_t));// = { 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    blfs_backstore_read_head_Expect(backstore, NULL, BLFS_HEAD_BYTES_KEYCOUNT, backstore->kcs_real_offset + nugget_index * BLFS_HEAD_BYTES_KEYCOUNT);
    blfs_backstore_read_head_Ignore();
    blfs_backstore_read_head_ReturnArrayThruPtr_buffer(keycount, BLFS_HEAD_BYTES_KEYCOUNT);
    
    blfs_keycount_t * actual_keycount = blfs_open_keycount(backstore, nugget_index);

    TEST_ASSERT_EQUAL_UINT(nugget_index, actual_keycount->nugget_index);
    TEST_ASSERT_EQUAL_UINT(backstore->kcs_real_offset + nugget_index * BLFS_HEAD_BYTES_KEYCOUNT, actual_keycount->data_offset);
    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_BYTES_KEYCOUNT, actual_keycount->data_length);
    TEST_ASSERT_EQUAL_MEMORY(keycount, (uint8_t *) &(actual_keycount->keycount), actual_keycount->data_length);

    uint64_t keycount2 = 123456789123;

    blfs_backstore_read_head_Expect(backstore, NULL, BLFS_HEAD_BYTES_KEYCOUNT, backstore->kcs_real_offset);
    blfs_backstore_read_head_IgnoreArg_buffer();
    blfs_backstore_read_head_ReturnArrayThruPtr_buffer((uint8_t *) &keycount2, BLFS_HEAD_BYTES_KEYCOUNT);

    blfs_keycount_t * actual_keycount2 = blfs_open_keycount(backstore, 0);

    TEST_ASSERT_EQUAL_UINT(0, actual_keycount2->nugget_index);
    TEST_ASSERT_EQUAL_UINT(backstore->kcs_real_offset, actual_keycount2->data_offset);
    TEST_ASSERT_EQUAL_UINT(BLFS_HEAD_BYTES_KEYCOUNT, actual_keycount2->data_length);
    TEST_ASSERT_EQUAL_UINT64(keycount2, actual_keycount2->keycount);

    TEST_IGNORE();
}

/*void test_blfs_open_and_close_keycount_functions_cache_properly(void)
{
    int nugget_index = 50;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    blfs_backstore_read_head_Ignore();
    blfs_keycount_t * actual_keycount = blfs_open_keycount(backstore, nugget_index);
    blfs_backstore_read_head_Ignore();
    blfs_keycount_t * actual_keycount2 = blfs_open_keycount(backstore, nugget_index);
    blfs_backstore_read_head_Ignore();
    blfs_keycount_t * actual_keycount3 = blfs_open_keycount(backstore, 0);

    TEST_ASSERT_EQUAL_PTR(actual_keycount, actual_keycount2);
    TEST_ASSERT_TRUE(actual_keycount2 != actual_keycount3);

    blfs_close_keycount(backstore, actual_keycount2);

    TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_KCS_CACHE_NAME, backstore->cache_kcs_counts, nugget_index));
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
    count->keycount = *((uint64_t *) data);

    blfs_backstore_write_head_Expect(backstore, data, BLFS_HEAD_BYTES_KEYCOUNT, 0x04);

    blfs_commit_keycount(backstore, count);
}

void test_blfs_open_tjournal_entry_works_as_expected(void)
{
    int nugget_index = 555;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    uint8_t expected_fpn[BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET] = { 0x0B, 0x00, 0x00, 0x00 };
    uint8_t expected_ones[2] = { 0xFF, 0xFF };
    uint8_t expected_zeroes[2] = { 0x00, 0x00 };

    blfs_backstore_read_head_Expect(backstore, NULL, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET, 192);
    blfs_backstore_read_head_IgnoreArg_buffer();
    blfs_backstore_read_head_ReturnArrayThruPtr_buffer(expected_fpn, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET);

    blfs_backstore_read_head_Expect(backstore, NULL, 2, backstore->tj_real_offset + nugget_index * 2);
    blfs_backstore_read_head_IgnoreArg_buffer();
    blfs_backstore_read_head_ReturnArrayThruPtr_buffer(expected_zeroes, 2);

    blfs_tjournal_entry_t * actual_tjournal_entry = blfs_open_tjournal_entry(backstore, nugget_index);

    TEST_ASSERT_EQUAL_UINT(nugget_index, actual_tjournal_entry->nugget_index);
    TEST_ASSERT_EQUAL_UINT(2, actual_tjournal_entry->data_length);
    TEST_ASSERT_EQUAL_UINT(backstore->tj_real_offset + nugget_index * 2, actual_tjournal_entry->data_offset);
    TEST_ASSERT_EQUAL_MEMORY(expected_zeroes, actual_tjournal_entry->bitmask->mask, actual_tjournal_entry->data_length);

    blfs_backstore_read_head_Expect(backstore, NULL, 2, backstore->tj_real_offset);
    blfs_backstore_read_head_IgnoreArg_buffer();
    blfs_backstore_read_head_ReturnArrayThruPtr_buffer(expected_ones, 2);

    blfs_tjournal_entry_t * actual_tjournal_entry2 = blfs_open_tjournal_entry(backstore, 0);

    TEST_ASSERT_EQUAL_UINT(0, actual_tjournal_entry2->nugget_index);
    TEST_ASSERT_EQUAL_UINT(backstore->tj_real_offset, actual_tjournal_entry2->data_offset);
    TEST_ASSERT_EQUAL_UINT(2, actual_tjournal_entry2->data_length);
    TEST_ASSERT_EQUAL_MEMORY(expected_ones, actual_tjournal_entry2->bitmask->mask, actual_tjournal_entry2->data_length);
}

void test_blfs_open_and_close_tjournal_entry_functions_cache_properly(void)
{
    int nugget_index = 60;
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    uint8_t expected_fpn[BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET] = { 0x08, 0x00, 0x00, 0x00 };
    uint8_t expected_ones[1] = { 0xFF };
    uint8_t * expected_zeroes = calloc(1, sizeof(uint8_t));

    blfs_backstore_read_head_Expect(backstore, NULL, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET, 192);
    blfs_backstore_read_head_IgnoreArg_buffer();
    blfs_backstore_read_head_ReturnArrayThruPtr_buffer(expected_fpn, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET);

    blfs_backstore_read_head_Expect(backstore, NULL, 1, backstore->tj_real_offset + nugget_index);
    blfs_backstore_read_head_IgnoreArg_buffer();
    blfs_backstore_read_head_ReturnArrayThruPtr_buffer(expected_zeroes, 1);

    blfs_tjournal_entry_t * actual_tjournal_entry = blfs_open_tjournal_entry(backstore, nugget_index);
    blfs_tjournal_entry_t * actual_tjournal_entry2 = blfs_open_tjournal_entry(backstore, nugget_index);

    blfs_backstore_read_head_Expect(backstore, NULL, 1, backstore->tj_real_offset);
    blfs_backstore_read_head_IgnoreArg_buffer();
    blfs_backstore_read_head_ReturnArrayThruPtr_buffer(expected_ones, 1);

    blfs_tjournal_entry_t * actual_tjournal_entry3 = blfs_open_tjournal_entry(backstore, 0);

    TEST_ASSERT_EQUAL_PTR(actual_tjournal_entry, actual_tjournal_entry2);
    TEST_ASSERT_TRUE(actual_tjournal_entry2 != actual_tjournal_entry3);

    blfs_close_tjournal_entry(backstore, actual_tjournal_entry2);

    TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_TJ_CACHE_NAME, backstore->cache_tj_entries, nugget_index));
}

void test_blfs_commit_tjournal_entry_works_as_expected(void)
{
    blfs_backstore_t bs;
    blfs_backstore_t * backstore = fake_initialize_backstore(&bs);

    blfs_tjournal_entry_t * entry = malloc(sizeof(blfs_tjournal_entry_t));

    uint8_t * data = malloc(2);
    data[0] = 0x05;
    data[1] = 0x50;

    entry->nugget_index = 50;
    entry->data_offset = 0x08;
    entry->data_length = 2;
    entry->bitmask = bitmask_init(data, entry->data_length);

    blfs_backstore_write_head_Expect(backstore, data, 2, 0x08);

    blfs_commit_tjournal_entry(backstore, entry);
}*/
