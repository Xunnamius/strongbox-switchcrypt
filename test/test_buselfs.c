/*
 * @author Bernard Dickens
 */

#include <limits.h>
#include <string.h>

#include "unity.h"
#include "buselfs.h"

void setUp(void)
{

}

void tearDown(void)
{

}

void test_not_implemented(void)
{
    buselfs_main(0, NULL);
    TEST_IGNORE();
}
