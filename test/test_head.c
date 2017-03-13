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

void test_not_implemented(void)
{
    TEST_IGNORE();
}
