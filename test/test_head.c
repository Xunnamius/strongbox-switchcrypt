/*
 * @author Bernard Dickens
 */

#include <limits.h>
#include <string.h>

#include "unity.h"
#include "mock_io.h"
#include "head.h"

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

void test_blfs_open_header_works_as_expected(void)
{
    blfs_backstore_t * backstore = malloc(sizeof(blfs_backstore_t));

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

}
