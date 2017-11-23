#ifndef BLFS_BUSELFS_H_
#define BLFS_BUSELFS_H_

#include "constants.h"
#include "backstore.h"
#include "io.h"
#include "crypto.h"
#include "mmc.h"
#include "khash.h"
#include "merkletree.h"
#include "sodium.h"

#if BLFS_DEBUG_MONITOR_POWER > 0

#include "energymon/energymon-default.h"

// Struct that holds duration/energy/power data
typedef struct metrics_t {
    uint64_t time_ns;
    uint64_t energy_uj;
} metrics_t;

#endif /* BLFS_DEBUG_MONITOR_POWER > 0 */

KHASH_MAP_INIT_STR(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, uint8_t *)

/**
 * Struct that defines the common stream cipher interface for algorithm
 * swapping. See swappable.h for details.
 */
typedef void (*stream_crypt_common)(uint8_t *, const uint8_t *, uint32_t, const uint8_t *, uint64_t, uint64_t);

/**
 * This struct represents program state and is passed around to various
 * buselfs functions.
 *
 * The main use of this state object is to assist in proper unit testing.
 */
typedef struct buselfs_state_t
{
    /**
     * The backstore used by the buselfs software.
     */
    blfs_backstore_t * backstore;

    /**
     * A cache that holds each of the keys for every nugget and flake in the
     * filesystem.
     *
     * Keys look like:
     * nugget keys: nugget_index => master_secret||nugget_index
     * flake keys: nugget_index||flake_id||associated_keycount => master_secret||nugget_index||flake_id||associated_keycount
     *
     * XXX: This uses quite a bit of memory, perhaps unnecessarily from a perf
     * perspective. Then again, it may not be all that much. Profile if ballooning.
     *
     * XXX: strdup is used to persist keys; could be a memory leak location if not
     * careful. Watch out!
     */
    khash_t(BLFS_KHASH_NUGGET_KEY_CACHE_NAME) * cache_nugget_keys;

    /**
     * The Merkle Tree that ensures integrity protection. Leaves are legion.
     *
     * General structure:
     *
     * index 0: TPM global version
     * index [1, 7]: headers (excluding TPMGV, INITIALIZED and MTRH)
     * index [8, n+7]: keycounts
     * index [n+8, 2n+7]: transaction journal entries
     * index [2n+8, 2n+7+(n*fpn)]: flake poly1305 tags
     */
    mt_t * merkle_tree;
    mt_hash_t merkle_tree_root_hash;

    /**
     * If not null, this default password should be used and the user should not
     * be disturbed. Useful for unit testing.
     */
    char * default_password;

    /**
     * If StrongBox was compiled with the energy monitoring flags, this
     * will be used to store the monitor context.
     */
    IFENERGYMON(energymon * energymon_monitor;)

    /**
     * This stores the default stream cipher context. See swappable.h for
     * details.
     */
    stream_crypt_common default_crypt_context;

    /**
     * If we're in crash recover mode (TRUE) or not (FALSE). If we are, then
     * all rekeying efforts must increment the keycount store entries by +2
     * instead of +1 to avoid any unpleasantness.
     */
    int crash_recovery;

    /**
     * Index of the RPMB counter block in the RPMB space
     */
    uint64_t rpmb_secure_index;
} buselfs_state_t;

// These are all the external caching functions:
// XXX: These caches grow, but they never shrink, even though they DEFINITELY should during rekeying. This is a
// memory leak. To be fixed later.
void add_index_to_key_cache(buselfs_state_t * buselfs_state, uint32_t nugget_index, uint8_t * nugget_key);

void add_keychain_to_key_cache(buselfs_state_t * buselfs_state,
                                      uint32_t nugget_index,
                                      uint32_t flake_index,
                                      uint64_t keycount,
                                      uint8_t * flake_key);

void get_nugget_key_using_index(uint8_t * nugget_key, buselfs_state_t * buselfs_state, uint32_t nugget_index);

void get_flake_key_using_keychain(uint8_t * flake_key,
                                        buselfs_state_t * buselfs_state,
                                        uint32_t nugget_index,
                                        uint32_t flake_index,
                                        uint64_t keycount);

// Note: you may be wondering why the main file has been broken up like this.
// 
// The answer is simple: unit testing. One cannot unit test a big fat main
// function in any pleasing way. Comes with free organizational boons, too!

/**
 * BUSE read operation handler. Passed directly to the buse core. See buse
 * documentation for more information.
 * 
 * @param  buffer
 * @param  len
 * @param  offset
 * @param  userdata (buselfs_state*)
 */
int buse_read(void * buffer, uint32_t len, uint64_t offset, void * userdata);

/**
 * BUSE write operation handler. Passed directly to the buse core. See buse
 * documentation for more information.
 * 
 * @param  buffer
 * @param  len
 * @param  offset
 * @param  userdata (buselfs_state*)
 */
int buse_write(const void * buffer, uint32_t len, uint64_t offset, void * userdata);

/**
 * Implementation of the buselfs rekeying procedure for journaled data.
 * Re-encrypts a nugget with an entirely different key and updates the cache
 * accordingly. This is called when rekeying was interrupted and the system was
 * remounted.
 * 
 * @param buselfs_state
 * @param rekeying_nugget_id
 */
void blfs_rekey_nugget_journaled(buselfs_state_t * buselfs_state, uint32_t rekeying_nugget_id);

/**
 * Implementation of the buselfs rekeying procedure for on-write overwrite
 * attempts. Re-encrypts a nugget with an entirely different key, performing an
 * in-memory overwrite before writeback, and updates the cache accordingly. This
 * is called when an overwrite occurs during buse_write().
 *
 * @param buselfs_state
 * @param rekeying_nugget_id
 * @param buffer
 * @param length
 * @param nugget_internal_offset
 */
void blfs_rekey_nugget_journaled_with_write(buselfs_state_t * buselfs_state,
                                            uint32_t rekeying_nugget_id,
                                            const void * buffer,
                                            uint32_t length,
                                            uint64_t nugget_internal_offset);

/**
 * Open a backstore and perform initial validation checks and asserts.
 * 
 * @param buselfs_state
 */
void blfs_soft_open(buselfs_state_t * buselfs_state, uint8_t cin_allow_insecure_start);

/**
 * Implementation of the CREATE command mode.
 * 
 * @param backstore_path
 * @param cin_backstore_size
 * @param cin_flake_size
 * @param cin_flakes_per_nugget
 * @param buselfs_state
 */
void blfs_run_mode_create(const char * backstore_path,
                                   uint64_t cin_backstore_size,
                                   uint32_t cin_flake_size,
                                   uint32_t cin_flakes_per_nugget,
                                   buselfs_state_t * buselfs_state);

/**
 * Implementation of the OPEN command mode.
 * 
 * @param backstore_path
 * @param cin_backstore_size
 * @param cin_allow_insecure_start
 * @param buselfs_state
 */
void blfs_run_mode_open(const char * backstore_path, uint8_t cin_allow_insecure_start, buselfs_state_t * buselfs_state);

/**
 * Implementation of the WIPE command mode.
 * 
 * @param backstore_path
 * @param cin_backstore_size
 * @param cin_allow_insecure_start
 * @param buselfs_state
 */
void blfs_run_mode_wipe(const char * backstore_path, uint8_t cin_allow_insecure_start, buselfs_state_t * buselfs_state);

/**
 * The function that is actually responsible for assembling the disperate
 * pieces that come together to form the functioning buselfs instance. This
 * function should not be called directly. Call buselfs_main() instead.
 * 
 * @param argc
 * @param argv
 * @param blockdevice
 */
buselfs_state_t * buselfs_main_actual(int argc, char * argv[], char * blockdevice);

/**
 * The entry point for the buselfs software. Call this from main().
 * 
 * @param  argc
 * @param  argv
 */
int buselfs_main(int argc, char * argv[]);

#if BLFS_DEBUG_MONITOR_POWER > 0

// TODO:
void blfs_energymon_init(buselfs_state_t * buselfs_state);

// TODO:
void blfs_energymon_collect_metrics(metrics_t * metrics, buselfs_state_t * buselfs_state);

// TODO:
void blfs_energymon_writeout_metrics(char * tag,
                                     metrics_t * read_metrics_start,
                                     metrics_t * read_metrics_end,
                                     metrics_t * write_metrics_start,
                                     metrics_t * write_metrics_end);

// TODO:
void blfs_energymon_writeout_metrics_simple(char * tag, metrics_t * metrics_start, metrics_t * metrics_end);

// TODO:
void blfs_energymon_fini(buselfs_state_t * buselfs_state);

#endif /* BLFS_DEBUG_MONITOR_POWER > 0 */
#endif /* BLFS_BUSELFS_H_ */
