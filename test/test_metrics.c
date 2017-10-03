/*
 * @author Bernard Dickens
 */
#include "unity.h"
#include "buselfs.h"
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

static buselfs_state_t * buselfs_state;

void setUp(void){}

void tearDown(void)
{
    /*mt_delete(buselfs_state->merkle_tree);

    if(!BLFS_DEFAULT_DISABLE_KEY_CACHING)
        kh_destroy(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys);

    free(buselfs_state);
    zlog_fini();*/
}

void test_blfs_energymon_init(void)
{
    if(!BLFS_DEBUG_MONITOR_POWER)
        TEST_IGNORE_MESSAGE("BLFS_DEBUG_MONITOR_POWER is NOT in effect. All energy/power tests will be ignored!");

    else
    {
        // TODO
        TEST_IGNORE_MESSAGE("Implement me!");
    }
}

void test_blfs_energymon_collect_metrics(void)
{
    if(!BLFS_DEBUG_MONITOR_POWER)
        TEST_IGNORE_MESSAGE("BLFS_DEBUG_MONITOR_POWER is NOT in effect. All energy/power tests will be ignored!");

    else
    {
        // TODO
        TEST_IGNORE_MESSAGE("Implement me!");
    }
}
