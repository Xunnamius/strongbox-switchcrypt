/*
 * @author Bernard Dickens
 */

#include <limits.h>
#include <string.h>

#include "unity.h"
#include "buselfs.h"

void setUp(void)
{
    if(sodium_init() == -1)
        exit(EXCEPTION_SODIUM_INIT_FAILURE);

    char buf[100];
    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), "test");
    
    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        exit(EXCEPTION_ZLOG_INIT_FAILURE);
}

void tearDown(void)
{
    zlog_fini();
}

void test_buse_read_works_as_expected(void)
{
    TEST_IGNORE();
}

void test_buse_write_works_as_expected(void)
{
    TEST_IGNORE();
}

void test_rekey_nugget_journaled_works_as_expected(void)
{
    TEST_IGNORE();
}

void test_password_verify_works_as_expected(void)
{
    TEST_IGNORE();
}

void test_buselfs_main_actual_works_as_expected(void)
{
    zlog_fini();
    TEST_IGNORE();
}
