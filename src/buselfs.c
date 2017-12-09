/*
 * Backend virtual block device for any LFS using BUSE
 *
 * @author Bernard Dickens
 */

#include "buselfs.h"
#include "bitmask.h"
#include "interact.h"
#include "swappable.h"
#include "buse.h"
#include "mt_err.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#if BLFS_DEBUG_MONITOR_POWER > 0

#include "energymon-time-util.h"

static FILE * metrics_output_fd = NULL;

void blfs_energymon_init(buselfs_state_t * buselfs_state)
{
    uid_t euid = geteuid();

    if(euid != 0)
        Throw(EXCEPTION_MUST_BE_ROOT);

    // Setup energymon
    errno = 0;

    buselfs_state->energymon_monitor = malloc(sizeof *(buselfs_state->energymon_monitor));

    if(energymon_get_default(buselfs_state->energymon_monitor))
    {
        dzlog_fatal("energymon_get_default error: %s", strerror(errno));
        Throw(EXCEPTION_ENERGYMON_GET_DEFAULT_FAILURE);
    }

    errno = 0;

    if(buselfs_state->energymon_monitor->finit(buselfs_state->energymon_monitor))
    {
        dzlog_fatal("finit error: %s", strerror(errno));
        Throw(EXCEPTION_ENERGYMON_FINIT_FAILURE);
    }

    errno = 0;

    if(metrics_output_fd == NULL)
        metrics_output_fd = fopen(BLFS_ENERGYMON_OUTPUT_PATH, "a");
    
    if(metrics_output_fd == NULL || errno)
    {
        dzlog_fatal("failed to fopen metrics_output_fd: %s", strerror(errno));
        Throw(EXCEPTION_OPEN_FAILURE);
    }
}

void blfs_energymon_collect_metrics(metrics_t * metrics, buselfs_state_t * buselfs_state)
{
    // Grab the initial energy use and time
    errno = 0;
    metrics->energy_uj = buselfs_state->energymon_monitor->fread(buselfs_state->energymon_monitor);

    if(!metrics->energy_uj && errno)
    {
        dzlog_fatal("energymon metric collection error: %s", strerror(errno));
        buselfs_state->energymon_monitor->ffinish(buselfs_state->energymon_monitor);
        Throw(EXCEPTION_ENERGYMON_METRIC_COLLECTION_FAILURE);
    }

    metrics->time_ns = energymon_gettime_ns();
}

// TODO: document/comment these!
void blfs_energymon_writeout_metrics(char * tag,
                                     metrics_t * read_metrics_start,
                                     metrics_t * read_metrics_end,
                                     metrics_t * write_metrics_start,
                                     metrics_t * write_metrics_end)
{
    // Crunch the results
    double tr_energy = read_metrics_end->energy_uj - read_metrics_start->energy_uj;
    double tr_duration = read_metrics_end->time_ns - read_metrics_start->time_ns;

    double tw_energy = 0;
    double tw_duration = 0;
    double tr_power = 0;
    double tw_power = 0;

    tr_energy /= 1000000.0;
    tr_duration /= 1000000000.0;
    tr_power = tr_energy / tr_duration;

    if(write_metrics_start != NULL && write_metrics_end != NULL)
    {
        tw_energy = write_metrics_end->energy_uj - write_metrics_start->energy_uj;
        tw_duration = write_metrics_end->time_ns - write_metrics_start->time_ns;

        tw_energy /= 1000000.0;
        tw_duration /= 1000000000.0;
        tw_power = tw_energy / tw_duration;

        // Output the results
        fprintf(metrics_output_fd,
                "tag: %s\ntr_energy: %f\ntr_duration: %f\ntr_power: %f\ntw_energy: %f\ntw_duration: %f\ntw_power: %f\n---\n",
                tag,
                tr_energy,
                tr_duration,
                tr_power,
                tw_energy,
                tw_duration,
                tw_power);
    }

    else
    {
        // Output the results
        fprintf(metrics_output_fd,
                "tag: %s\nt_energy: %f\nt_duration: %f\nt_power: %f\n---\n",
                tag,
                tr_energy,
                tr_duration,
                tr_power);
    }

    // Flush the results
    fflush(metrics_output_fd);
}

void blfs_energymon_writeout_metrics_simple(char * tag, metrics_t * metrics_start, metrics_t * metrics_end)
{
    blfs_energymon_writeout_metrics(tag, metrics_start, metrics_end, NULL, NULL);
}

void blfs_energymon_fini(buselfs_state_t * buselfs_state)
{
    if(buselfs_state->energymon_monitor->ffinish(buselfs_state->energymon_monitor))
    {
        dzlog_fatal("ffinish error: %s", strerror(errno));
        Throw(EXCEPTION_ENERGYMON_FFINISH_FAILURE);
    }

    fflush(metrics_output_fd);
    fclose(metrics_output_fd);
    
    free(buselfs_state->energymon_monitor);
    
    metrics_output_fd = 0;
    buselfs_state->energymon_monitor = NULL;
}

#endif /* BLFS_DEBUG_MONITOR_POWER > 0 */

#if BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION && BLFS_NO_READ_INTEGRITY
#error "The BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION and BLFS_NO_READ_INTEGRITY compile flags CANNOT be used together!"
#endif

/**
 * Unimplemented BUSE internal function.
 */
static void buse_disc(void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) userdata;

    IFDEBUG(dzlog_info("Received a disconnect request (not implemented)."));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

/**
 * Unimplemented BUSE internal function.
 */
static int buse_flush(void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) userdata;

    IFDEBUG(dzlog_info("Received a flush request (not implemented)."));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return 0;
}

/**
 * Unimplemented BUSE internal function.
 */
static int buse_trim(uint64_t from, uint32_t len, void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) from;
    (void) len;
    (void) userdata;

    IFDEBUG(dzlog_info("Received a trim request (not implemented)"));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return 0;
}

/**
 * struct buse_operations buseops is required by the BUSE subsystem. It is very
 * similar to its FUSE counterpart in intent.
 */
static struct buse_operations buseops = {
    .read = buse_read,
    .write = buse_write,
    .disc = buse_disc,
    .flush = buse_flush,
    .trim = buse_trim,
    .size = 0
};

/**
 * Updates the global merkle tree root hash.
 *
 * XXX: this function MUST be called before buselfs_state->merkle_tree_root_hash
 * is referenced!
 *
 * @param buselfs_state
 */
static void update_merkle_tree_root_hash(buselfs_state_t * buselfs_state)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(mt_get_root(buselfs_state->merkle_tree, buselfs_state->merkle_tree_root_hash) != MT_SUCCESS)
        Throw(EXCEPTION_MERKLE_TREE_ROOT_FAILURE);

    IFDEBUG(dzlog_debug("merkle tree root hash:"));
    IFDEBUG(hdzlog_debug(buselfs_state->merkle_tree_root_hash, BLFS_CRYPTO_BYTES_MTRH));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

static void commit_merkle_tree_root_hash(buselfs_state_t * buselfs_state)
{
    update_merkle_tree_root_hash(buselfs_state);

    blfs_header_t * mtrh_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_MTRH);
    memcpy(mtrh_header->data, buselfs_state->merkle_tree_root_hash, BLFS_HEAD_HEADER_BYTES_MTRH);
    blfs_commit_header(buselfs_state->backstore, mtrh_header);
}

/**
 * Add a leaf to the global merkle tree
 * 
 * @param data
 * @param length
 * @param buselfs_state
 */
static void add_to_merkle_tree(uint8_t * data, size_t length, buselfs_state_t * buselfs_state)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("length = %zu", length));
    IFDEBUG(dzlog_debug("data:"));
    IFDEBUG(hdzlog_debug(data, length));

    mt_error_t err = mt_add(buselfs_state->merkle_tree, data, length);

    if(err != MT_SUCCESS)
    {
        IFDEBUG(dzlog_fatal("MT ERROR: %i", err));
        Throw(EXCEPTION_MERKLE_TREE_ADD_FAILURE);
    }

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

/**
 * Update a leaf in the global merkle tree
 * 
 * @param data
 * @param length
 * @param index
 * @param buselfs_state
 */
static void update_in_merkle_tree(uint8_t * data, size_t length, uint32_t index, buselfs_state_t * buselfs_state)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("length = %zu", length));
    IFDEBUG(dzlog_debug("index = %u", index));
    IFDEBUG(dzlog_debug("data:"));
    IFDEBUG(hdzlog_debug(data, length));

    mt_error_t err = mt_update(buselfs_state->merkle_tree, data, length, index);

    if(err != MT_SUCCESS)
    {
        IFDEBUG(dzlog_fatal("MT ERROR: %i", err));
        Throw(EXCEPTION_MERKLE_TREE_UPDATE_FAILURE);
    }

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

/**
 * Verify a leaf in the global merkle tree
 * 
 * @param data
 * @param length
 * @param index
 * @param buselfs_state
 */
static void verify_in_merkle_tree(uint8_t * data, size_t length, uint32_t index, buselfs_state_t * buselfs_state)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("length = %zu", length));
    IFDEBUG(dzlog_debug("index = %u", index));
    IFDEBUG(dzlog_debug("data:"));
    IFDEBUG(hdzlog_debug(data, length));

    mt_error_t err = mt_verify(buselfs_state->merkle_tree, data, length, index);

    if(err != MT_SUCCESS)
    {
        IFDEBUG(dzlog_fatal("MT ERROR: %i", err));
        Throw(EXCEPTION_MERKLE_TREE_VERIFY_FAILURE);
    }

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

// TODO: retire journaled rekeying logic; to that end, rekeying should always be set to 0
static void populate_key_cache(buselfs_state_t * buselfs_state, int rekeying, uint32_t rekeying_nugget_index)
{
    assert(rekeying == 0);
    assert(rekeying_nugget_index == 0);

    //blfs_keycount_t rekeying_count;
    //blfs_tjournal_entry_t rekeying_entry;
    //uint8_t rekeying_nugget_data[buselfs_state->backstore->nugget_size_bytes];
    
    //blfs_fetch_journaled_data(buselfs_state->backstore, rekeying_nugget_index, &rekeying_count, &rekeying_entry, rekeying_nugget_data);

    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        dzlog_info("KEY CACHING DISABLED!");

    else
    {
        // First with nugget keys:
        // nugget_index => (nugget_key = master_secret+nugget_index)
        for(uint32_t nugget_index = 0; nugget_index < buselfs_state->backstore->num_nuggets; nugget_index++)
        {
            uint8_t * nugget_key = malloc(sizeof(*nugget_key) * BLFS_CRYPTO_BYTES_KDF_OUT);
            blfs_keycount_t * count;
            
            /*if(rekeying && rekeying_nugget_index == nugget_index)
            {
                IFDEBUG(dzlog_debug("rekeying detected! Using rekeying_nugget_index to grab count..."));
                count = &rekeying_count;
            }

            else*/
                count = blfs_open_keycount(buselfs_state->backstore, nugget_index);

            if(nugget_key == NULL)
                Throw(EXCEPTION_ALLOC_FAILURE);

            blfs_nugget_key_from_data(nugget_key, buselfs_state->backstore->master_secret, nugget_index);
            add_index_to_key_cache(buselfs_state, nugget_index, nugget_key);

            // Now with nugget keys:
            // nugget_index||flake_index||associated_keycount => master_secret+nugget_index+flake_index+associated_keycount
            for(uint32_t flake_index = 0; flake_index < buselfs_state->backstore->flakes_per_nugget; flake_index++)
            {
                uint8_t * flake_key = malloc(sizeof(*flake_key) * BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY);

                if(flake_key == NULL)
                    Throw(EXCEPTION_ALLOC_FAILURE);

                blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, count->keycount);
                add_keychain_to_key_cache(buselfs_state, nugget_index, flake_index, count->keycount, flake_key);
            }
        }
    }
}

// TODO: retire journaled rekeying logic; to that end, rekeying should always be set to 0
static void populate_mt(buselfs_state_t * buselfs_state, int rekeying, uint32_t rekeying_nugget_index)
{
    assert(rekeying == 0);
    assert(rekeying_nugget_index == 0);

    // blfs_keycount_t rekeying_count;
    // blfs_tjournal_entry_t rekeying_entry;
    // uint8_t rekeying_nugget_data[buselfs_state->backstore->nugget_size_bytes];

    uint32_t flakesize = buselfs_state->backstore->flake_size_bytes;
    uint32_t nugsize   = buselfs_state->backstore->nugget_size_bytes;

    uint32_t operations_completed = 0;
    IFNDEBUG(uint32_t operations_total = 1 + (BLFS_HEAD_NUM_HEADERS - 3)
             + buselfs_state->backstore->num_nuggets * 2
             + buselfs_state->backstore->num_nuggets * buselfs_state->backstore->flakes_per_nugget);
    
    //blfs_fetch_journaled_data(buselfs_state->backstore, rekeying_nugget_index, &rekeying_count, &rekeying_entry, rekeying_nugget_data);

    IFDEBUG(dzlog_debug("MERKLE TREE: adding TPMGV counter..."));
    IFDEBUG(dzlog_debug("MERKLE TREE: starting index %"PRIu32, operations_completed));

    IFNDEBUG(printf("Population progress: 0%%"));
    fflush(stdout);

    // First element in the merkle tree should be the TPM version counter
    blfs_header_t * tpmv_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
    add_to_merkle_tree(tpmv_header->data, tpmv_header->data_length, buselfs_state);
    IFDEBUG(verify_in_merkle_tree(tpmv_header->data, tpmv_header->data_length, 0, buselfs_state));
    operations_completed++;

    IFNDEBUG(interact_print_percent_done(operations_completed * 100 / operations_total));

    // Next, the headers (excluding TPMGV, INITIALIZED and MTRH)
    IFDEBUG(dzlog_debug("MERKLE TREE: adding headers..."));
    IFDEBUG(dzlog_debug("MERKLE TREE: starting index %"PRIu32, operations_completed));

    for(size_t i = 0; i < BLFS_HEAD_NUM_HEADERS; ++i)
    {
        uint32_t const_header_type = header_types_ordered[i][0];

        if(const_header_type == BLFS_HEAD_HEADER_TYPE_MTRH ||
           const_header_type == BLFS_HEAD_HEADER_TYPE_INITIALIZED ||
           const_header_type == BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER)
        {
            IFDEBUG(dzlog_debug("skipping header type %"PRIu32, const_header_type));
            continue;
        }

        blfs_header_t * header = blfs_open_header(buselfs_state->backstore, const_header_type);
        add_to_merkle_tree(header->data, header->data_length, buselfs_state);
        IFDEBUG(verify_in_merkle_tree(header->data, header->data_length, operations_completed, buselfs_state));
        operations_completed++;
        IFNDEBUG(interact_print_percent_done(operations_completed * 100 / operations_total));
    }

    // Next, the keycounts
    IFDEBUG(dzlog_debug("MERKLE TREE: adding keycounts..."));
    IFDEBUG(dzlog_debug("MERKLE TREE: starting index %"PRIu32, operations_completed));

    for(uint32_t nugget_index = 0; nugget_index < buselfs_state->backstore->num_nuggets; nugget_index++, operations_completed++)
    {
        blfs_keycount_t * count;

        /*if(rekeying && rekeying_nugget_index == nugget_index)
        {
            IFDEBUG(dzlog_debug("rekeying detected! Using rekeying_nugget_index to grab count..."));
            count = &rekeying_count;
        }

        else*/
            count = blfs_open_keycount(buselfs_state->backstore, nugget_index);

        add_to_merkle_tree((uint8_t *) &count->keycount, BLFS_HEAD_BYTES_KEYCOUNT, buselfs_state);
        IFDEBUG(verify_in_merkle_tree((uint8_t *) &count->keycount, BLFS_HEAD_BYTES_KEYCOUNT, operations_completed, buselfs_state));
        IFNDEBUG(interact_print_percent_done((operations_completed + 1) * 100 / operations_total));
    }
    
    // Next, the TJ entries
    IFDEBUG(dzlog_debug("MERKLE TREE: adding transaction journal entries..."));
    IFDEBUG(dzlog_debug("MERKLE TREE: starting index %"PRIu32, operations_completed));

    for(uint32_t nugget_index = 0; nugget_index < buselfs_state->backstore->num_nuggets; nugget_index++, operations_completed++)
    {
        blfs_tjournal_entry_t * entry;

        /*if(rekeying && rekeying_nugget_index == nugget_index)
        {
            IFDEBUG(dzlog_debug("rekeying detected! Using rekeying_nugget_index to grab entry..."));
            entry = &rekeying_entry;
        }

        else*/
            entry = blfs_open_tjournal_entry(buselfs_state->backstore, nugget_index);

        uint8_t hash[BLFS_CRYPTO_BYTES_TJ_HASH_OUT];
        blfs_chacha20_tj_hash(hash, entry->bitmask->mask, entry->bitmask->byte_length, buselfs_state->backstore->master_secret);
        add_to_merkle_tree(hash, BLFS_CRYPTO_BYTES_TJ_HASH_OUT, buselfs_state);
        IFDEBUG(verify_in_merkle_tree(hash, BLFS_CRYPTO_BYTES_TJ_HASH_OUT, operations_completed, buselfs_state));
        IFNDEBUG(interact_print_percent_done((operations_completed + 1) * 100 / operations_total));
    }
    
    // Finally, the flake tags
    IFDEBUG(dzlog_debug("MERKLE TREE: adding flake tags..."));
    IFDEBUG(dzlog_debug("MERKLE TREE: starting index %"PRIu32, operations_completed));

    for(uint32_t nugget_index = 0; nugget_index < buselfs_state->backstore->num_nuggets; nugget_index++)
    {
        uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };
        blfs_keycount_t * count;

        /*if(rekeying && rekeying_nugget_index == nugget_index)
        {
            IFDEBUG(dzlog_debug("rekeying detected! Using rekeying_nugget_index to work with count and nugget data..."));
            count = &rekeying_count;
            blfs_nugget_key_from_data(nugget_key, buselfs_state->backstore->master_secret, nugget_index);
        }

        else
        {*/
            count = blfs_open_keycount(buselfs_state->backstore, nugget_index);

            if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
                blfs_nugget_key_from_data(nugget_key, buselfs_state->backstore->master_secret, nugget_index);
        /*}*/

        for(uint32_t flake_index = 0; flake_index < buselfs_state->backstore->flakes_per_nugget; flake_index++, operations_completed++)
        {
            uint8_t flake_key[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0x00 };
            uint8_t * tag = malloc(sizeof(*tag) * BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT);
            uint8_t flake_data[flakesize];

            if(tag == NULL)
                Throw(EXCEPTION_ALLOC_FAILURE);

            /*if(rekeying && rekeying_nugget_index == nugget_index)
            {
                blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, count->keycount);
                memcpy(flake_data, rekeying_nugget_data + flake_index * flakesize, flakesize);
            }

            else
            {*/
                if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
                    blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, count->keycount);
                else
                    get_flake_key_using_keychain(flake_key, buselfs_state, nugget_index, flake_index, count->keycount);

                blfs_backstore_read_body(buselfs_state->backstore, flake_data, flakesize, nugget_index * nugsize + flake_index * flakesize);
            /*}*/
            
            blfs_poly1305_generate_tag(tag, flake_data, flakesize, flake_key);
            add_to_merkle_tree(tag, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT, buselfs_state);
            IFDEBUG(verify_in_merkle_tree(tag, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT, operations_completed, buselfs_state));
            IFNDEBUG(interact_print_percent_done((operations_completed + 1) * 100 / operations_total));
        }
    }

    IFDEBUG(dzlog_debug("MERKLE TREE: final index vs size (should be +1 diff) %"PRIu32" vs %"PRIu32, operations_completed, mt_get_size(buselfs_state->merkle_tree)));
    IFNDEBUG(printf("\n"));
}

void add_index_to_key_cache(buselfs_state_t * buselfs_state, uint32_t nugget_index, uint8_t * nugget_key)
{
    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        Throw(EXCEPTION_BAD_CACHE);

    char kh_nugget_key[BLFS_KHASH_NUGGET_KEY_SIZE_BYTES] = { 0x00 };

    sprintf(kh_nugget_key, "%"PRIu32, nugget_index);
    IFDEBUG(dzlog_debug("CACHE: adding KHASH nugget index key %s to cache...", kh_nugget_key));

    KHASH_CACHE_PUT_HEAP(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, kh_nugget_key, nugget_key);
}

void add_keychain_to_key_cache(buselfs_state_t * buselfs_state,
                                      uint32_t nugget_index,
                                      uint32_t flake_index,
                                      uint64_t keycount,
                                      uint8_t * flake_key)
{
    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        Throw(EXCEPTION_BAD_CACHE);

    char kh_flake_key[BLFS_KHASH_NUGGET_KEY_SIZE_BYTES] = { 0x00 };

    sprintf(kh_flake_key, "%"PRIu32"||%"PRIu32"||%"PRIu64, nugget_index, flake_index, keycount);
    IFDEBUG(dzlog_debug("CACHE: adding KHASH flake keychain key %s to cache...", kh_flake_key));

    KHASH_CACHE_PUT_HEAP(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, kh_flake_key, flake_key);
}

void get_nugget_key_using_index(uint8_t * nugget_key, buselfs_state_t * buselfs_state, uint32_t nugget_index)
{
    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        Throw(EXCEPTION_BAD_CACHE);

    char kh_nugget_key[BLFS_KHASH_NUGGET_KEY_SIZE_BYTES] = { 0x00 };
    uint8_t * ng;

    sprintf(kh_nugget_key, "%"PRIu32, nugget_index);
    IFDEBUG(dzlog_debug("CACHE: grabbing KHASH nugget index key %s from cache...", kh_nugget_key));

    ng = KHASH_CACHE_GET_WITH_KEY(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, kh_nugget_key);
    memcpy(nugget_key, ng, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY);
}

void get_flake_key_using_keychain(uint8_t * flake_key,
                                        buselfs_state_t * buselfs_state,
                                        uint32_t nugget_index,
                                        uint32_t flake_index,
                                        uint64_t keycount)
{
    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        Throw(EXCEPTION_BAD_CACHE);

    char kh_flake_key[BLFS_KHASH_NUGGET_KEY_SIZE_BYTES] = { 0x00 };
    uint8_t * fk;

    sprintf(kh_flake_key, "%"PRIu32"||%"PRIu32"||%"PRIu64, nugget_index, flake_index, keycount);
    IFDEBUG(dzlog_debug("CACHE: grabbing KHASH flake keychain key %s from cache...", kh_flake_key));

    fk = KHASH_CACHE_GET_WITH_KEY(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, kh_flake_key);
    memcpy(flake_key, fk, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY);
}

int buse_read(void * output_buffer, uint32_t length, uint64_t absolute_offset, void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint8_t * buffer = (uint8_t *) output_buffer;
    buselfs_state_t * buselfs_state = (buselfs_state_t *) userdata;
    uint_fast32_t size = length;

    IFENERGYMON(metrics_t metrics_init_start);
    IFENERGYMON(metrics_t metrics_init_end);
    IFENERGYMON(metrics_t metrics_read_loop_start);
    IFENERGYMON(metrics_t metrics_read_loop_end);
    IFENERGYMON(metrics_t metrics_integrity_loop_start);
    IFENERGYMON(metrics_t metrics_integrity_loop_end);

    IFENERGYMON(blfs_energymon_collect_metrics(&metrics_init_start, buselfs_state));

    IFDEBUG(dzlog_debug("output_buffer (ptr): %p", (void *) output_buffer));
    IFDEBUG(dzlog_debug("buffer (ptr): %p", (void *) buffer));
    IFDEBUG(dzlog_debug("length: %"PRIu32, length));
    IFDEBUG(dzlog_debug("absolute_offset: %"PRIu64, absolute_offset));
    IFDEBUG(dzlog_debug("userdata (ptr): %p", (void *) userdata));
    IFDEBUG(dzlog_debug("buselfs_state (ptr): %p", (void *) buselfs_state));

    uint_fast32_t nugget_size       = buselfs_state->backstore->nugget_size_bytes;
    uint_fast32_t flake_size        = buselfs_state->backstore->flake_size_bytes;
    uint_fast32_t num_nuggets       = buselfs_state->backstore->num_nuggets;
    uint_fast32_t flakes_per_nugget = buselfs_state->backstore->flakes_per_nugget;

    uint_fast32_t mt_offset = 2 * num_nuggets + 8;

    // XXX: For a bigger system, this cast could be a problem
    uint_fast32_t nugget_offset          = (uint_fast32_t) (absolute_offset / nugget_size); // nugget_index
    uint_fast32_t nugget_internal_offset = (uint_fast32_t) (absolute_offset % nugget_size); // internal point at which to start within nug

    IFDEBUG(dzlog_debug("nugget_size: %"PRIuFAST32, nugget_size));
    IFDEBUG(dzlog_debug("flake_size: %"PRIuFAST32, flake_size));
    IFDEBUG(dzlog_debug("num_nuggets: %"PRIuFAST32, num_nuggets));
    IFDEBUG(dzlog_debug("flakes_per_nugget: %"PRIuFAST32, flakes_per_nugget));
    IFDEBUG(dzlog_debug("mt_offset: %"PRIuFAST32, mt_offset));
    IFDEBUG(dzlog_debug("nugget_offset: %"PRIuFAST32, nugget_offset));
    IFDEBUG(dzlog_debug("nugget_internal_offset: %"PRIuFAST32, nugget_internal_offset));

    int first_nugget = TRUE;

    while(length != 0)
    {
        IFDEBUG(dzlog_debug("starting with length: %"PRIu32, length));

        IFENERGYMON(blfs_energymon_collect_metrics(&metrics_read_loop_start, buselfs_state));

        assert(length > 0 && length <= size);

        uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT];
        
        uint_fast32_t buffer_read_length = MIN(length, nugget_size - nugget_internal_offset); // nmlen
        uint_fast32_t assert_buffer_read_length = 0;
        uint_fast32_t first_affected_flake = nugget_internal_offset / flake_size;
        uint_fast32_t num_affected_flakes =
            CEIL((nugget_internal_offset + buffer_read_length), flake_size) - first_affected_flake;
        uint_fast32_t nugget_read_length = num_affected_flakes * flake_size;

        uint8_t nugget_data[nugget_read_length];

        int last_nugget = length - buffer_read_length == 0;

        IFDEBUG(dzlog_debug("first nugget: %s", first_nugget ? "YES" : "NO"));
        IFDEBUG(dzlog_debug("last nugget: %s", last_nugget ? "YES" : "NO"));

        IFDEBUG(dzlog_debug("buffer_read_length: %"PRIuFAST32, buffer_read_length));
        IFDEBUG(dzlog_debug("first_affected_flake: %"PRIuFAST32, first_affected_flake));
        IFDEBUG(dzlog_debug("num_affected_flakes: %"PRIuFAST32, num_affected_flakes));
        IFDEBUG(dzlog_debug("nugget_read_length: %"PRIuFAST32, nugget_read_length));
        
        IFDEBUG(dzlog_debug("blfs_backstore_read_body offset: %"PRIuFAST32,
                            nugget_offset * nugget_size + first_affected_flake * flake_size));

        blfs_backstore_read_body(buselfs_state->backstore,
                                 nugget_data,
                                 nugget_read_length,
                                 nugget_offset * nugget_size + first_affected_flake * flake_size);

        IFDEBUG(dzlog_debug("nugget_data (initial 64 bytes):"));
        IFDEBUG(hdzlog_debug(nugget_data, MIN(64U, nugget_read_length)));

        if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        {
            IFDEBUG(dzlog_debug("KEY CACHING DISABLED!"));
            blfs_nugget_key_from_data(nugget_key, buselfs_state->backstore->master_secret, nugget_offset);
        }

        else
        {
            IFDEBUG(dzlog_debug("KEY CACHING ENABLED!"));
            get_nugget_key_using_index(nugget_key, buselfs_state, nugget_offset);
        }

        IFDEBUG(dzlog_debug("nugget_key (initial 64 bytes):"));
        IFDEBUG(hdzlog_debug(nugget_key, MIN(64U, BLFS_CRYPTO_BYTES_KDF_OUT)));

        blfs_keycount_t * count = blfs_open_keycount(buselfs_state->backstore, nugget_offset);
        IFDEBUG(dzlog_debug("count->keycount: %"PRIu64, count->keycount));

        uint_fast32_t flake_index = first_affected_flake;
        uint_fast32_t flake_end = first_affected_flake + num_affected_flakes;

        if(!BLFS_NO_READ_INTEGRITY)
        {
            IFENERGYMON(blfs_energymon_collect_metrics(&metrics_integrity_loop_start, buselfs_state));

            for(uint_fast32_t i = 0; flake_index < flake_end; flake_index++, i++)
            {
                uint8_t flake_key[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY];
                uint8_t tag[BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT];

                if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
                {
                    IFDEBUG(dzlog_debug("KEY CACHING DISABLED!"));
                    blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, count->keycount);
                }

                else
                {
                    IFDEBUG(dzlog_debug("KEY CACHING ENABLED!"));
                    get_flake_key_using_keychain(flake_key, buselfs_state, nugget_offset, flake_index, count->keycount);
                }

                IFDEBUG(dzlog_debug("nugget index (offset): %"PRIuFAST32, nugget_offset));
                IFDEBUG(dzlog_debug("flake_index: %"PRIuFAST32" of %"PRIuFAST32, flake_index, flake_end-1));
                IFDEBUG(dzlog_debug("flake_key (initial 64 bytes):"));
                IFDEBUG(hdzlog_debug(flake_key, MIN(64U, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY)));

                IFDEBUG(dzlog_debug("blfs_poly1305_generate_tag calculated ptr: %p --[ + "
                                    "%"PRIuFAST32" * %"PRIuFAST32" => %"PRIuFAST32
                                    " ]> %p (gen tag for %"PRIuFAST32" bytes)",
                                    (void *) nugget_data,
                                    flake_index,
                                    flake_size,
                                    flake_index * flake_size,
                                    (void *) (nugget_data + (i * flake_size)),
                                    flake_size));

                blfs_poly1305_generate_tag(tag, nugget_data + (i * flake_size), flake_size, flake_key);

                IFDEBUG(dzlog_debug("tag (initial 64 bytes):"));
                IFDEBUG(hdzlog_debug(tag, MIN(64U, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT)));

                IFDEBUG(dzlog_debug("verify_in_merkle_tree calculated offset: %"PRIuFAST32,
                                    mt_offset + nugget_offset * flakes_per_nugget + flake_index));

                assert(mt_offset + nugget_offset * flakes_per_nugget + flake_index <=
                       2 * buselfs_state->backstore->num_nuggets + 7 + buselfs_state->backstore->num_nuggets * buselfs_state->backstore->flakes_per_nugget);

                verify_in_merkle_tree(tag, sizeof tag, mt_offset + nugget_offset * flakes_per_nugget + flake_index, buselfs_state);

                if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
                {
                    uint8_t flake_plaintext[flake_size];
                    uint32_t first_flake_internal_offset = nugget_internal_offset - first_affected_flake * flake_size;

                    blfs_aesxts_decrypt(flake_plaintext,
                                        nugget_data + (i * flake_size),
                                        flake_size,
                                        flake_key,
                                        nugget_offset * flakes_per_nugget + flake_index);

                    if(first_nugget && flake_index == first_affected_flake)
                    {
                        uint32_t flake_internal_length = MIN(buffer_read_length, flake_size - first_flake_internal_offset);

                        assert(first_flake_internal_offset + flake_internal_length <= flake_size);
                        memcpy(buffer, flake_plaintext + first_flake_internal_offset, flake_internal_length);

                        buffer += flake_internal_length;
                        assert_buffer_read_length += flake_internal_length;
                    }

                    else if(last_nugget && flake_index == flake_end - 1)
                    {
                        uint32_t flake_internal_end_length = buffer_read_length - (i * flake_size - (first_nugget ? first_flake_internal_offset : 0));

                        assert(flake_internal_end_length <= flake_size);
                        assert(flake_internal_end_length > 0);
                        memcpy(buffer, flake_plaintext, flake_internal_end_length);

                        buffer += flake_internal_end_length;
                        assert_buffer_read_length += flake_internal_end_length;
                    }

                    else
                    {
                        memcpy(buffer, flake_plaintext, flake_size);

                        buffer += flake_size;
                        assert_buffer_read_length += flake_size;
                    }
                }
            }

            IFENERGYMON(blfs_energymon_collect_metrics(&metrics_integrity_loop_end, buselfs_state));
            IFENERGYMON(blfs_energymon_writeout_metrics_simple("buse_read.integ_loop", &metrics_integrity_loop_start, &metrics_integrity_loop_end));
        }

        if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
            assert(buffer_read_length == assert_buffer_read_length);

        else
        {
            IFDEBUG(dzlog_debug("blfs_crypt calculated ptr: %p --[ + "
                                "%"PRIuFAST32" - %"PRIuFAST32" * %"PRIuFAST32" => %"PRIuFAST32
                                " ]> %p (crypting %"PRIuFAST32" bytes)",
                                (void *) nugget_data,
                                nugget_internal_offset,
                                first_affected_flake,
                                flake_size,
                                nugget_internal_offset - first_affected_flake * flake_size,
                                (void *) (nugget_data + (nugget_internal_offset - first_affected_flake * flake_size)),
                                buffer_read_length));

            buselfs_state->default_crypt_context(buffer,
                                nugget_data + (nugget_internal_offset - first_affected_flake * flake_size),
                                buffer_read_length,
                                nugget_key,
                                count->keycount,
                                nugget_internal_offset);
        }

        IFDEBUG(dzlog_debug("output_buffer final contents (initial 64 bytes):"));
        IFDEBUG(hdzlog_debug(output_buffer, MIN(64U, size)));

        if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
            buffer += buffer_read_length;

        length -= buffer_read_length;
        nugget_internal_offset = 0;
        nugget_offset++;

        IFDEBUG(dzlog_debug("END (next nugget):"));
        IFDEBUG(dzlog_debug("buffer: %p", (void *) buffer));
        IFDEBUG(dzlog_debug("length: %"PRIu32, length));
        IFDEBUG(dzlog_debug("nugget_internal_offset: %"PRIuFAST32, nugget_internal_offset));
        IFDEBUG(dzlog_debug("nugget_offset: %"PRIuFAST32, nugget_offset));

        first_nugget = FALSE;

        IFENERGYMON(blfs_energymon_collect_metrics(&metrics_read_loop_end, buselfs_state));
        IFENERGYMON(blfs_energymon_writeout_metrics_simple("buse_read.read_loop", &metrics_read_loop_start, &metrics_read_loop_end));
    }

    IFENERGYMON(blfs_energymon_collect_metrics(&metrics_init_end, buselfs_state));
    IFENERGYMON(blfs_energymon_writeout_metrics_simple("buse_read", &metrics_init_start, &metrics_init_end));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return 0;
}

int buse_write(const void * input_buffer, uint32_t length, uint64_t absolute_offset, void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFENERGYMON(metrics_t metrics_init_start);
    IFENERGYMON(metrics_t metrics_init_end);
    IFENERGYMON(metrics_t metrics_outer_write_loop_start);
    IFENERGYMON(metrics_t metrics_outer_write_loop_end);
    IFENERGYMON(metrics_t metrics_inner_write_loop_start);
    IFENERGYMON(metrics_t metrics_inner_write_loop_end);
    IFENERGYMON(metrics_t metrics_rekey_start);
    IFENERGYMON(metrics_t metrics_rekey_end);

    const uint8_t * buffer = (const uint8_t *) input_buffer;
    buselfs_state_t * buselfs_state = (buselfs_state_t *) userdata;
    uint_fast32_t size = length;

    IFENERGYMON(blfs_energymon_collect_metrics(&metrics_init_start, buselfs_state));

    IFDEBUG(dzlog_debug("input_buffer (ptr): %p", (void *) input_buffer));
    IFDEBUG(dzlog_debug("buffer (ptr): %p", (void *) buffer));
    IFDEBUG(dzlog_debug("length: %"PRIu32, length));
    IFDEBUG(dzlog_debug("absolute_offset: %"PRIu64, absolute_offset));
    IFDEBUG(dzlog_debug("userdata (ptr): %p", (void *) userdata));
    IFDEBUG(dzlog_debug("buselfs_state (ptr): %p", (void *) buselfs_state));

    uint_fast32_t nugget_size       = buselfs_state->backstore->nugget_size_bytes;
    uint_fast32_t flake_size        = buselfs_state->backstore->flake_size_bytes;
    uint_fast32_t num_nuggets       = buselfs_state->backstore->num_nuggets;
    uint_fast32_t flakes_per_nugget = buselfs_state->backstore->flakes_per_nugget;

    uint_fast32_t mt_offset = 2 * num_nuggets + 8;

    // XXX: For a bigger system, this cast could be a problem
    uint_fast32_t nugget_offset          = (uint_fast32_t) (absolute_offset / nugget_size); // nugget_index
    uint_fast32_t nugget_internal_offset = (uint_fast32_t) (absolute_offset % nugget_size); // internal point at which to start within nug

    IFDEBUG(dzlog_debug("nugget_size: %"PRIuFAST32, nugget_size));
    IFDEBUG(dzlog_debug("flake_size: %"PRIuFAST32, flake_size));
    IFDEBUG(dzlog_debug("num_nuggets: %"PRIuFAST32, num_nuggets));
    IFDEBUG(dzlog_debug("flakes_per_nugget: %"PRIuFAST32, flakes_per_nugget));
    IFDEBUG(dzlog_debug("mt_offset: %"PRIuFAST32, mt_offset));
    IFDEBUG(dzlog_debug("nugget_offset: %"PRIuFAST32, nugget_offset));
    IFDEBUG(dzlog_debug("nugget_internal_offset: %"PRIuFAST32, nugget_internal_offset));

    IFDEBUG(dzlog_debug("buffer to write (initial 64 bytes):"));
    IFDEBUG(hdzlog_debug(input_buffer, /*MIN(64U, */size/*)*/));

    blfs_header_t * tpmv_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
    uint64_t tpmv_value = *(uint64_t *) tpmv_header->data;

    IFDEBUG(dzlog_debug("tpmv_header->data:"));
    IFDEBUG(dzlog_debug("was %"PRIu64, tpmv_value));

    tpmv_value++;

    IFDEBUG(dzlog_debug("now %"PRIu64, tpmv_value));

    memcpy(tpmv_header->data, (uint8_t *) &tpmv_value, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER);

    blfs_globalversion_commit(buselfs_state->rpmb_secure_index, tpmv_value); // TODO: needs to be guaranteed monotonic, not based on header

    while(length != 0)
    {
        IFDEBUG(dzlog_debug("starting with length: %"PRIu32, length));

        IFENERGYMON(blfs_energymon_collect_metrics(&metrics_outer_write_loop_start, buselfs_state));

        assert(length > 0 && length <= size);

        uint_fast32_t buffer_write_length = MIN(length, nugget_size - nugget_internal_offset); // nmlen
        uint_fast32_t first_affected_flake = nugget_internal_offset / flake_size;
        uint_fast32_t num_affected_flakes =
            CEIL((nugget_internal_offset + buffer_write_length), flake_size) - first_affected_flake;

        IFDEBUG(dzlog_debug("buffer_write_length: %"PRIuFAST32, buffer_write_length));
        IFDEBUG(dzlog_debug("first_affected_flake: %"PRIuFAST32, first_affected_flake));
        IFDEBUG(dzlog_debug("num_affected_flakes: %"PRIuFAST32, num_affected_flakes));

        // First, check if this constitutes an overwrite...
        blfs_tjournal_entry_t * entry = blfs_open_tjournal_entry(buselfs_state->backstore, nugget_offset);

        IFDEBUG(dzlog_debug("entry->bitmask (pre-update):"));
        IFDEBUG(hdzlog_debug(entry->bitmask->mask, entry->bitmask->byte_length));

        if(bitmask_any_bits_set(entry->bitmask, first_affected_flake, num_affected_flakes))
        {
            IFENERGYMON(blfs_energymon_collect_metrics(&metrics_rekey_start, buselfs_state));

            IFDEBUG(dzlog_notice("OVERWRITE DETECTED! PERFORMING IN-PLACE JOURNALED REKEYING + WRITE (l=%"PRIuFAST32")", buffer_write_length));
            blfs_rekey_nugget_journaled_with_write(buselfs_state, nugget_offset, buffer, buffer_write_length, nugget_internal_offset);

            IFENERGYMON(blfs_energymon_collect_metrics(&metrics_rekey_end, buselfs_state));
            IFENERGYMON(blfs_energymon_writeout_metrics_simple("buse_write.outer_write_loop.rekey", &metrics_rekey_start, &metrics_rekey_end));

            buffer += buffer_write_length;
        }

        else
        {
            uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT];

            // XXX: Maybe update and commit the MTRH here first and again later?

            if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
            {
                IFDEBUG(dzlog_debug("KEY CACHING DISABLED!"));
                blfs_nugget_key_from_data(nugget_key, buselfs_state->backstore->master_secret, nugget_offset);
            }

            else
            {
                IFDEBUG(dzlog_debug("KEY CACHING ENABLED!"));
                get_nugget_key_using_index(nugget_key, buselfs_state, nugget_offset);
            }

            IFDEBUG(dzlog_debug("nugget_key (initial 64 bytes):"));
            IFDEBUG(hdzlog_debug(nugget_key, MIN(64U, BLFS_CRYPTO_BYTES_KDF_OUT)));

            blfs_keycount_t * count = blfs_open_keycount(buselfs_state->backstore, nugget_offset);
            IFDEBUG(dzlog_debug("count->keycount: %"PRIu64, count->keycount));

            uint_fast32_t flake_internal_offset = nugget_internal_offset % flake_size;
            uint_fast32_t flake_total_bytes_to_write = buffer_write_length;
            
            IFDEBUG(dzlog_debug("buffer_write_length: %"PRIuFAST32, buffer_write_length));
            IFDEBUG(dzlog_debug("nugget_internal_offset: %"PRIuFAST32, nugget_internal_offset));
            IFDEBUG(dzlog_debug("flake_size: %"PRIuFAST32, flake_size));
            IFDEBUG(dzlog_debug("flake_internal_offset: %"PRIuFAST32, flake_internal_offset));

            // XXX: Packing it like this might actually be a security
            // vulnerability. Need to just read in and verify the entire flake
            // instead? Can't trust data from disk.
            uint_fast32_t flake_index = first_affected_flake;
            uint_fast32_t flake_end = first_affected_flake + num_affected_flakes;


            for(uint_fast32_t i = 0; flake_index < flake_end; flake_index++, i++)
            {
                IFENERGYMON(blfs_energymon_collect_metrics(&metrics_inner_write_loop_start, buselfs_state));

                uint_fast32_t flake_write_length = MIN(flake_total_bytes_to_write, flake_size - flake_internal_offset);

                IFDEBUG(dzlog_debug("flake_write_length: %"PRIuFAST32, flake_write_length));
                IFDEBUG(dzlog_debug("flake_index: %"PRIuFAST32, flake_index));
                IFDEBUG(dzlog_debug("flake_end: %"PRIuFAST32, flake_end));

                uint8_t flake_data[flake_size];
                IFDEBUG(memset(flake_data, 0, flake_size));

                // XXX: Data to write isn't aligned and/or is smaller than
                // flake_size, so we need to verify its integrity
                if(flake_internal_offset != 0 || flake_internal_offset + flake_write_length < flake_size)
                {
                    IFDEBUG(dzlog_debug("UNALIGNED! Write flake requires verification"));

                    // Read in the entire flake
                    blfs_backstore_read_body(buselfs_state->backstore,
                                             flake_data,
                                             flake_size,
                                             nugget_offset * nugget_size + flake_index * flake_size);

                    // Generate a local flake key
                    uint8_t local_flake_key[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY];
                    uint8_t local_tag[BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT];

                    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
                    {
                        IFDEBUG(dzlog_debug("KEY CACHING DISABLED!"));
                        blfs_poly1305_key_from_data(local_flake_key, nugget_key, flake_index, count->keycount);
                    }

                    else
                    {
                        IFDEBUG(dzlog_debug("KEY CACHING ENABLED!"));
                        get_flake_key_using_keychain(local_flake_key, buselfs_state, nugget_offset, flake_index, count->keycount);
                    }

                    // Generate tag
                    blfs_poly1305_generate_tag(local_tag, flake_data, flake_size, local_flake_key);

                    // Check tag in Merkle Tree
                    verify_in_merkle_tree(local_tag, sizeof local_tag, mt_offset + nugget_offset * flakes_per_nugget + flake_index, buselfs_state);
                }

                if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
                {
                    IFDEBUG(dzlog_debug("INCOMPLETE flake_data (initial 64 bytes):"));
                    IFDEBUG(hdzlog_debug(flake_data, MIN(64U, flake_size)));

                    IFDEBUG(dzlog_debug("buffer at this point (initial 64 bytes):"));
                    IFDEBUG(hdzlog_debug(buffer, MIN(64U, length)));

                    IFDEBUG(dzlog_debug("blfs_crypt calculated src length: %"PRIuFAST32, flake_write_length));

                    IFDEBUG(dzlog_debug("blfs_crypt calculated dest offset: %"PRIuFAST32,
                                    i * flake_size));

                    IFDEBUG(dzlog_debug("blfs_crypt calculated nio: %"PRIuFAST32,
                                    flake_index * flake_size + flake_internal_offset));

                    buselfs_state->default_crypt_context(flake_data + flake_internal_offset,
                                        buffer,
                                        flake_write_length,
                                        nugget_key,
                                        count->keycount,
                                        flake_index * flake_size + flake_internal_offset);
                }

                IFDEBUG(dzlog_debug("*complete* flake_data (initial 64 bytes):"));
                IFDEBUG(hdzlog_debug(flake_data, MIN(64U, flake_size)));

                uint8_t flake_key[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY];
                uint8_t tag[BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT];

                if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
                {
                    IFDEBUG(dzlog_debug("KEY CACHING DISABLED!"));
                    blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, count->keycount);
                }

                else
                {
                    IFDEBUG(dzlog_debug("KEY CACHING ENABLED!"));
                    get_flake_key_using_keychain(flake_key, buselfs_state, nugget_offset, flake_index, count->keycount);
                }

                if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
                {
                    if(flake_internal_offset != 0 || flake_internal_offset + flake_write_length < flake_size)
                    {
                        blfs_aesxts_decrypt(flake_data,
                                            flake_data,
                                            flake_size,
                                            flake_key,
                                            nugget_offset * flakes_per_nugget + flake_index);
                    }

                    IFDEBUG(dzlog_debug("flake_write_length: %"PRIuFAST32, flake_write_length));
                    memcpy(flake_data + flake_internal_offset, buffer, flake_write_length);

                    blfs_aesxts_encrypt(flake_data,
                                        flake_data,
                                        flake_size,
                                        flake_key,
                                        nugget_offset * flakes_per_nugget + flake_index);
                }

                blfs_poly1305_generate_tag(tag, flake_data, flake_size, flake_key);

                IFDEBUG(dzlog_debug("flake_key (initial 64 bytes):"));
                IFDEBUG(hdzlog_debug(flake_key, MIN(64U, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY)));

                IFDEBUG(dzlog_debug("tag (initial 64 bytes):"));
                IFDEBUG(hdzlog_debug(tag, MIN(64U, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT)));

                IFDEBUG(dzlog_debug("update_in_merkle_tree calculated offset: %"PRIuFAST32,
                                    mt_offset + nugget_offset * flakes_per_nugget + flake_index));

                update_in_merkle_tree(tag, sizeof tag, mt_offset + nugget_offset * flakes_per_nugget + flake_index, buselfs_state);

                if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
                {
                    IFDEBUG(dzlog_debug("blfs_backstore_write_body offset: %"PRIuFAST32,
                                        nugget_offset * nugget_size + flake_index * flake_size + flake_internal_offset));
                    
                    blfs_backstore_write_body(buselfs_state->backstore,
                                             flake_data + flake_internal_offset,
                                             flake_write_length,
                                             nugget_offset * nugget_size + flake_index * flake_size + flake_internal_offset);

                    IFDEBUG(dzlog_debug("blfs_backstore_write_body input (initial 64 bytes):"));
                    IFDEBUG(hdzlog_debug(flake_data + flake_internal_offset, MIN(64U, flake_write_length)));
                }

                else
                {
                    blfs_backstore_write_body(buselfs_state->backstore,
                                             flake_data,
                                             flake_size,
                                             nugget_offset * nugget_size + flake_index * flake_size);

                    IFDEBUG(dzlog_debug("blfs_backstore_write_body input (initial 64 bytes):"));
                    IFDEBUG(hdzlog_debug(flake_data, MIN(64U, flake_size)));
                }

                flake_internal_offset = 0;

                assert(flake_total_bytes_to_write > flake_total_bytes_to_write - flake_write_length);
                
                flake_total_bytes_to_write -= flake_write_length;
                buffer += flake_write_length;

                IFENERGYMON(blfs_energymon_collect_metrics(&metrics_inner_write_loop_end, buselfs_state));
                IFENERGYMON(blfs_energymon_writeout_metrics_simple("buse_write.inner_write_loop",
                                                                   &metrics_inner_write_loop_start,
                                                                   &metrics_inner_write_loop_end));
            }

            assert(flake_total_bytes_to_write == 0);
        }

        bitmask_set_bits(entry->bitmask, first_affected_flake, num_affected_flakes);
        blfs_commit_tjournal_entry(buselfs_state->backstore, entry);
        IFDEBUG(dzlog_debug("entry->bitmask (post-update):"));
        IFDEBUG(hdzlog_debug(entry->bitmask->mask, entry->bitmask->byte_length));

        IFDEBUG(dzlog_debug("MERKLE TREE: update TJ entry"));
        update_in_merkle_tree(entry->bitmask->mask, entry->bitmask->byte_length, num_nuggets + 8 + nugget_offset, buselfs_state);

        length -= buffer_write_length;
        nugget_internal_offset = 0;
        nugget_offset++;

        IFDEBUG(dzlog_debug("END (next nugget):"));
        IFDEBUG(dzlog_debug("buffer: %p", (void *) buffer));
        IFDEBUG(dzlog_debug("length: %"PRIu32, length));
        IFDEBUG(dzlog_debug("nugget_internal_offset: %"PRIuFAST32, nugget_internal_offset));
        IFDEBUG(dzlog_debug("nugget_offset: %"PRIuFAST32, nugget_offset));

        IFENERGYMON(blfs_energymon_collect_metrics(&metrics_outer_write_loop_end, buselfs_state));
        IFENERGYMON(blfs_energymon_writeout_metrics_simple("buse_write.outer_write_loop",
                                                           &metrics_outer_write_loop_start,
                                                           &metrics_outer_write_loop_end));
    }

    blfs_commit_header(buselfs_state->backstore, tpmv_header);

    IFDEBUG(dzlog_debug("MERKLE TREE: update TPM header"));
    update_in_merkle_tree(tpmv_header->data, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER, 0, buselfs_state);

    commit_merkle_tree_root_hash(buselfs_state);

    IFENERGYMON(blfs_energymon_collect_metrics(&metrics_init_end, buselfs_state));
    IFENERGYMON(blfs_energymon_writeout_metrics_simple("buse_write", &metrics_init_start, &metrics_init_end));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return 0;
}

void blfs_rekey_nugget_journaled_with_write(buselfs_state_t * buselfs_state,
                                  uint32_t rekeying_nugget_index,
                                  const void * buffer,
                                  uint32_t length,
                                  uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    // XXX: Might want to switch up the ordering of these operations

    // Set REKEYING header to rekeying_nugget_index in order to recover using
    // journal later if necessary
    blfs_header_t * rekeying_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_REKEYING);
    memcpy(rekeying_header->data, &rekeying_nugget_index, BLFS_HEAD_HEADER_BYTES_REKEYING);
    blfs_commit_header(buselfs_state->backstore, rekeying_header);

    // XXX: hardcoded index
    update_in_merkle_tree(rekeying_header->data, BLFS_HEAD_HEADER_BYTES_REKEYING, 7, buselfs_state);
    IFDEBUG(verify_in_merkle_tree(rekeying_header->data, BLFS_HEAD_HEADER_BYTES_REKEYING, 7, buselfs_state));

    commit_merkle_tree_root_hash(buselfs_state);

    blfs_keycount_t * jcount = blfs_open_keycount(buselfs_state->backstore, rekeying_nugget_index);
    blfs_tjournal_entry_t * jentry = blfs_open_tjournal_entry(buselfs_state->backstore, rekeying_nugget_index);

    uint8_t rekeying_nugget_data[buselfs_state->backstore->nugget_size_bytes];
    uint8_t new_nugget_data[buselfs_state->backstore->nugget_size_bytes];
    uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };
    
    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        blfs_nugget_key_from_data(nugget_key, buselfs_state->backstore->master_secret, rekeying_nugget_index);

    if(jcount == NULL || jentry == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    // Read in *and verify* nugget FIRST
    buse_read(rekeying_nugget_data,
              buselfs_state->backstore->nugget_size_bytes,
              rekeying_nugget_index * buselfs_state->backstore->nugget_size_bytes,
              (void *) buselfs_state);

    // Now we'll commit everything to the journal before proceeding
    
    uint8_t journaled_data_ciphertext[buselfs_state->backstore->nugget_size_bytes];
    blfs_backstore_read_body(buselfs_state->backstore,
                             journaled_data_ciphertext,
                             buselfs_state->backstore->nugget_size_bytes,
                             rekeying_nugget_index * buselfs_state->backstore->nugget_size_bytes);

    // TODO: retire rekeying journaling in favor of buselfs_state->crash_recovery
    // Write nugget ciphertext and metadata to journal
    blfs_backstore_write(buselfs_state->backstore,
                         journaled_data_ciphertext,
                         buselfs_state->backstore->nugget_size_bytes,
                         buselfs_state->backstore->nugget_journaled_offset);

    blfs_backstore_write(buselfs_state->backstore,
                         (uint8_t *) &jcount->keycount,
                         jcount->data_length,
                         buselfs_state->backstore->kcs_journaled_offset);

    blfs_backstore_write(buselfs_state->backstore,
                         jentry->bitmask->mask,
                         jentry->data_length,
                         buselfs_state->backstore->tj_journaled_offset);

    memcpy(rekeying_nugget_data + nugget_internal_offset, buffer, length);

    // XXX: if we're in crash recovery mode, the very next keycount might be
    // burned, so we must take that possibility into account when rekeying.
    jcount->keycount = jcount->keycount + (buselfs_state->crash_recovery ? 2 : 1);
    
    if(!BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        buselfs_state->default_crypt_context(new_nugget_data,
                            rekeying_nugget_data,
                            buselfs_state->backstore->nugget_size_bytes,
                            nugget_key,
                            jcount->keycount,
                            0);

        blfs_backstore_write_body(buselfs_state->backstore,
                            new_nugget_data,
                            buselfs_state->backstore->nugget_size_bytes,
                            rekeying_nugget_index * buselfs_state->backstore->nugget_size_bytes);
    }

    uint32_t flake_size = buselfs_state->backstore->flake_size_bytes;

    // Update the merkle tree
    for(uint32_t flake_index = 0; flake_index < buselfs_state->backstore->flakes_per_nugget; flake_index++)
    {
        uint8_t flake_key[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0x00 };
        uint8_t * tag = malloc(sizeof(*tag) * BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT);
        uint8_t flake_data[flake_size];
        uint32_t mt_offset = 2 * buselfs_state->backstore->num_nuggets
                             + 8
                             + rekeying_nugget_index * buselfs_state->backstore->flakes_per_nugget
                             + flake_index;

        if(tag == NULL)
            Throw(EXCEPTION_ALLOC_FAILURE);

        blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, jcount->keycount);

        if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
        {
            blfs_aesxts_encrypt(flake_data,
                                rekeying_nugget_data + flake_index * flake_size,
                                flake_size,
                                flake_key,
                                rekeying_nugget_index * buselfs_state->backstore->flakes_per_nugget + flake_index);

            blfs_backstore_write_body(buselfs_state->backstore,
                            flake_data,
                            flake_size,
                            rekeying_nugget_index * buselfs_state->backstore->nugget_size_bytes + flake_index * flake_size);
        }

        else
            memcpy(flake_data, new_nugget_data + flake_index * flake_size, flake_size);

        if(!BLFS_DEFAULT_DISABLE_KEY_CACHING)
        {
            // FIXME: update the key cache: clear out old keychain, insert new one
        }
        
        blfs_poly1305_generate_tag(tag, flake_data, flake_size, flake_key);
        update_in_merkle_tree(tag, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT, mt_offset, buselfs_state);
        IFDEBUG(verify_in_merkle_tree(tag, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT, mt_offset, buselfs_state));
    }

    // Set REKEYING header back to 0xFF
    memset(rekeying_header->data, 0xFF, BLFS_HEAD_HEADER_BYTES_REKEYING);

    blfs_commit_keycount(buselfs_state->backstore, jcount);
    update_in_merkle_tree((uint8_t *) &jcount->keycount, BLFS_HEAD_BYTES_KEYCOUNT, 8 + rekeying_nugget_index, buselfs_state);

    uint_fast32_t first_affected_flake = nugget_internal_offset / flake_size;
    uint_fast32_t num_affected_flakes = CEIL((nugget_internal_offset + length), flake_size) - first_affected_flake;

    bitmask_set_bits(jentry->bitmask, first_affected_flake, num_affected_flakes);
    blfs_commit_tjournal_entry(buselfs_state->backstore, jentry);

    // XXX: hardcoded index!
    update_in_merkle_tree(rekeying_header->data, BLFS_HEAD_HEADER_BYTES_REKEYING, 7, buselfs_state);
    IFDEBUG(verify_in_merkle_tree(rekeying_header->data, BLFS_HEAD_HEADER_BYTES_REKEYING, 7, buselfs_state));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

// TODO: retire this outdated recovery logic in favor of buselfs_state->crash_recovery
void blfs_rekey_nugget_journaled(buselfs_state_t * buselfs_state, uint32_t rekeying_nugget_index)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("beginning rekeying process..."));

    (void) buselfs_state;
    (void) rekeying_nugget_index;

    // Set REKEYING header to rekeying_nugget_index

    Throw(EXCEPTION_MUST_HALT); // XXX: Not implemented!

    // FIXME: crash recovery during rekeying. Implement me sometime!
    
    // Re-encrypts a nugget with an entirely different key and updates the cache accordingly.
    // Do updates in the merkle tree. Deletes in the cache MUST take into account the strduping!
    
    // Set REKEYING header to 0

    // Copy the nugget, the kcs, and the keycount at rekeying_nugget_index

    // Update the REKEYING header with the nugget_index

    // Delete (AND FREE) and reinsert the nugget key and ALL THE keychains for
    // rekeying_nugget_index

    // Update the merkle tree entries

    // Decrypt, increment keycount (and commit), wipe tj (and commit), increment
    // GV (and commit), reencrypt and store nugget data
    
    // Wipe journal space and set rekeying header to 0xFF
    /*update_in_merkle_tree(rekeying_header->data, BLFS_HEAD_HEADER_BYTES_REKEYING, 7, buselfs_state);
    IFDEBUG(verify_in_merkle_tree(rekeying_header->data, BLFS_HEAD_HEADER_BYTES_REKEYING, 7, buselfs_state));*/

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

// FIXME: mismatch between create and open; needs a fix! Though the recovery code is working, don't try the open command
// just yet...
void blfs_soft_open(buselfs_state_t * buselfs_state, uint8_t cin_allow_insecure_start)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    char passwd[BLFS_PASSWORD_BUF_SIZE] = { 0x00 };

    if(buselfs_state->default_password != NULL)
    {
        IFDEBUG(dzlog_warn("Using default password! This is not secure!"));
        memcpy(passwd, buselfs_state->default_password, MIN(strlen(buselfs_state->default_password), sizeof passwd));
    }

    else
        interact_prompt_user("Enter your password: ", passwd, sizeof passwd);

    IFDEBUG(dzlog_debug("passwd = %s", passwd));

    // Are we initialized?
    blfs_header_t * init_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_INITIALIZED);
    
    if(init_header->data[0] != BLFS_HEAD_IS_INITIALIZED_VALUE && init_header->data[0] != BLFS_HEAD_WAS_WIPED_VALUE)
        Throw(EXCEPTION_BACKSTORE_NOT_INITIALIZED);

    // Get salt
    blfs_header_t * salt_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_SALT);

    // Derive master secret, cache it
    blfs_password_to_secret(buselfs_state->backstore->master_secret, passwd, strlen(passwd), salt_header->data);
    IFDEBUG(dzlog_debug("buselfs_state->backstore->master_secret:"));
    IFDEBUG(hdzlog_debug(buselfs_state->backstore->master_secret, BLFS_CRYPTO_BYTES_KDF_OUT));
    
    // Use chacha20 with master secret to check verification header
    blfs_header_t * verf_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);
    uint8_t verify_pwd[BLFS_HEAD_HEADER_BYTES_VERIFICATION] = { 0x00 };

    blfs_chacha20_verif(verify_pwd, buselfs_state->backstore->master_secret);

    IFDEBUG(dzlog_debug("verf_header->data:"));
    IFDEBUG(hdzlog_debug(verf_header->data, BLFS_HEAD_HEADER_BYTES_VERIFICATION));
    IFDEBUG(dzlog_debug("verify_pwd (should match above):"));
    IFDEBUG(hdzlog_debug(verify_pwd, BLFS_HEAD_HEADER_BYTES_VERIFICATION));

    if(memcmp(verf_header->data, verify_pwd, BLFS_HEAD_HEADER_BYTES_VERIFICATION) != 0)
        Throw(EXCEPTION_BAD_PASSWORD);

    // Verify global header and determine if recovery should be triggered
    blfs_header_t * tpmv_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
    uint64_t tpmv_value = *(uint64_t *) tpmv_header->data;

    IFDEBUG(dzlog_debug("tpmv_header->data: %"PRIu64, tpmv_value));

    int global_correctness = blfs_globalversion_verify(buselfs_state->rpmb_secure_index, tpmv_value);

    IFDEBUG(dzlog_debug("global_correctness: %i", global_correctness));
    
    if(global_correctness == BLFS_GLOBAL_CORRECTNESS_POTENTIAL_CRASH)
    {
        /* potential crash occurred; c == d + 1 */
        dzlog_error("Error: global version integrity failure occurred. Assessing...");
    }

    else if(global_correctness != BLFS_GLOBAL_CORRECTNESS_ALL_GOOD)
    {
        /* bad manipulation occurred; c < d or c > d + 1 */
        dzlog_fatal("!!!!!!! ERROR: FATAL BLOCK DEVICE BACKSTORE GLOBAL VERSION CHECK FAILURE !!!!!!!");
        Throw(EXCEPTION_GLOBAL_CORRECTNESS_FAILURE);
    }

    // XXX: retire this logic entirely in the future
    /*// Do we need to rekey?
    blfs_header_t * rekeying_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_REKEYING);
    uint8_t zero_rekeying[BLFS_HEAD_HEADER_BYTES_REKEYING];
    uint32_t rekeying_nugget_index = 0;

    memset(zero_rekeying, 0xFF, BLFS_HEAD_HEADER_BYTES_REKEYING);

    if(memcmp(rekeying_header->data, zero_rekeying, BLFS_HEAD_HEADER_BYTES_REKEYING) != 0)
    {
        IFDEBUG(dzlog_debug("rekeying header nugget id detected!"));

        rekeying = TRUE;
        rekeying_nugget_index = *(uint32_t *) rekeying_header->data;

        IFDEBUG(dzlog_debug("rekeying_nugget_index = %"PRIu32, rekeying_nugget_index));
    }*/

    dzlog_notice("Populating key cache...");

    populate_key_cache(buselfs_state, 0, 0);

    dzlog_notice("Populating merkle tree...");

    populate_mt(buselfs_state, 0, 0);

    dzlog_notice("Almost done...");

    // Update the global MTRH
    update_merkle_tree_root_hash(buselfs_state);

    IFDEBUG3(dzlog_debug("MERKLE TREE: debug print (at the bottom)"));
    IFDEBUG3(mt_print(buselfs_state->merkle_tree));

    IFDEBUG(dzlog_debug("MERKLE TREE: comparing MTRH to header"));

    blfs_header_t * mtrh_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_MTRH);

    IFDEBUG(dzlog_debug("mtrh_header->data:"));
    IFDEBUG(hdzlog_debug(mtrh_header->data, BLFS_HEAD_HEADER_BYTES_MTRH));
    IFDEBUG(dzlog_debug("computed MTRH:"));
    IFDEBUG(hdzlog_debug(buselfs_state->merkle_tree_root_hash, BLFS_HEAD_HEADER_BYTES_MTRH));

    if(memcmp(mtrh_header->data, buselfs_state->merkle_tree_root_hash, BLFS_HEAD_HEADER_BYTES_MTRH) != 0)
    {
        dzlog_fatal("!!!!!!! ERROR: FATAL BLOCK DEVICE BACKSTORE MT INTEGRITY CHECK FAILURE !!!!!!!");

        if(cin_allow_insecure_start)
            dzlog_warn("The allow-insecure-start flag detected. Forcing start anyway...");

        else
        {
            dzlog_warn("Use the allow-insecure-start flag to ignore integrity violation (at your own peril).");
            Throw(EXCEPTION_INTEGRITY_FAILURE);
        }
    }

    else if(global_correctness != BLFS_GLOBAL_CORRECTNESS_ALL_GOOD)
    {
        dzlog_warn("Integrity check passed, but the global version is off by one. A rollback (or crash) may have"
                   "occurred. Proceed with caution.");

        tpmv_value++;
        buselfs_state->crash_recovery = TRUE;

        memcpy(tpmv_header->data, (uint8_t *) &tpmv_value, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER);

        blfs_commit_header(buselfs_state->backstore, tpmv_header);

        IFDEBUG(dzlog_debug("MERKLE TREE: update TPM header"));
        update_in_merkle_tree(tpmv_header->data, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER, 0, buselfs_state);
    }

    commit_merkle_tree_root_hash(buselfs_state);

    // Retire this old logic in favor of the new logic
    //if(rekeying)
    //    blfs_rekey_nugget_journaled(buselfs_state, *(uint32_t *) rekeying_header->data);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_run_mode_create(const char * backstore_path,
                          uint64_t cin_backstore_size,
                          uint32_t cin_flake_size,
                          uint32_t cin_flakes_per_nugget,
                          buselfs_state_t * buselfs_state)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    volatile blfs_backstore_t * backstore_v;
    volatile uint8_t already_attempted_delete = 0;
    volatile CEXCEPTION_T e = EXCEPTION_NO_EXCEPTION;
    
    IFDEBUG(dzlog_debug("running in CREATE mode!"));

    Try
    {
        backstore_v = blfs_backstore_create(backstore_path, cin_backstore_size);

        // XXX: refs to memory allocated during blfs_backstore_create
        // will be lost during an exception. It's technically a memory
        // leak, but it's not so pressing an issue at the moment.
    }
    
    Catch(e)
    {
        if(e == EXCEPTION_FILE_ALREADY_EXISTS && !already_attempted_delete)
        {
            IFDEBUG(dzlog_debug("backstore file already exists, deleting and trying again..."));

            unlink(backstore_path);
            already_attempted_delete = 1;

            backstore_v = blfs_backstore_create(backstore_path, cin_backstore_size);
        }

        else
        {
            IFDEBUG(dzlog_debug("EXCEPTION: rethrowing exception (already_attempted_delete = %i) %"PRIu32,
                                already_attempted_delete, e));

            Throw(e);
        }
    }

    buselfs_state->backstore = (blfs_backstore_t *) backstore_v;

    char passwd[BLFS_PASSWORD_BUF_SIZE] = { 0x00 };
    char passck[BLFS_PASSWORD_BUF_SIZE];

    if(buselfs_state->default_password != NULL)
    {
        IFDEBUG(dzlog_warn("Using default password! This is not secure!"));
        memcpy(passwd, buselfs_state->default_password, MIN(strlen(buselfs_state->default_password), sizeof passwd));
    }

    else
    {
        interact_prompt_user("Enter your desired password (max "BLFS_PASSWORD_MAX_SIZE"): ", passwd, sizeof passwd);
        interact_prompt_user("Confirm your password: ", passck, sizeof passwd);
    }

    IFDEBUG(dzlog_debug("passwd = %s", passwd));
    IFDEBUG(dzlog_debug("passck = %s", passck));

    if(buselfs_state->default_password == NULL && strcmp(passwd, passck) != 0)
        Throw(EXCEPTION_PASSWORD_MISMATCH);

    // Ensure initialization header set to 0 and commit
    blfs_header_t * init_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_INITIALIZED);
    init_header->data[0] = 0x00;
    blfs_commit_header(buselfs_state->backstore, init_header);

    // Generate salt, set header
    blfs_header_t * salt_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_SALT);
    blfs_KDF_generate_salt(salt_header->data);

    // Derive master secret, cache it
    blfs_password_to_secret(buselfs_state->backstore->master_secret, passwd, strlen(passwd), salt_header->data);
    IFDEBUG(dzlog_debug("buselfs_state->backstore->master_secret:"));
    IFDEBUG(hdzlog_debug(buselfs_state->backstore->master_secret, BLFS_CRYPTO_BYTES_KDF_OUT));
    
    // Set global version header to 1
    blfs_header_t * tpmv_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
    tpmv_header->data[0] = 0x01;

    IFDEBUG(dzlog_debug("<< attempting to commit clean RPMB block >>"));
    
    uint8_t data_in[BLFS_CRYPTO_RPMB_BLOCK] = { 0x01 };
    e = EXCEPTION_NO_EXCEPTION;

    memset(data_in + 8, 0, sizeof(data_in) - 8);

    Try
    {
        rpmb_write_block(buselfs_state->rpmb_secure_index, data_in);
    }

    Catch(e)
    {
        if(e == EXCEPTION_RPMB_DOES_NOT_EXIST && BLFS_MANUAL_GV_FALLBACK != -1)
        {
            dzlog_warn("RPMB device is not able to be opened but BLFS_MANUAL_GV_FALLBACK (%i) is in effect; ignoring...",
                       BLFS_MANUAL_GV_FALLBACK);
        }

        else
            Throw(e);
    }

    IFDEBUG(dzlog_debug("<< resuming create routine >>"));

    // Use chacha20 with master secret to get verification header, set header
    blfs_header_t * verf_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);
    blfs_chacha20_verif(verf_header->data, buselfs_state->backstore->master_secret);

    IFDEBUG(dzlog_debug("verf_header->data:"));
    IFDEBUG(hdzlog_debug(verf_header->data, BLFS_HEAD_HEADER_BYTES_VERIFICATION));

    // Set the flakesize and fpn headers (XXX: this is DEFINITELY endian-sensitive!!!)
    blfs_header_t * flakesize_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES);
    blfs_header_t * fpn_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET);

    uint8_t * data_flakesize = (uint8_t *) &cin_flake_size;

    IFDEBUG(dzlog_debug("data_flakesize (cin_flake_size) = %"PRIu32, cin_flake_size));
    IFDEBUG(dzlog_debug("data_flakesize:"));
    IFDEBUG(hdzlog_debug(data_flakesize, BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES));

    uint8_t * data_fpn = (uint8_t *) &cin_flakes_per_nugget;

    IFDEBUG(dzlog_debug("data_fpn (cin_flakes_per_nugget) = %"PRIu32, cin_flakes_per_nugget));
    IFDEBUG(dzlog_debug("data_fpn:"));
    IFDEBUG(hdzlog_debug(data_fpn, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET));

    memcpy(flakesize_header->data, data_flakesize, BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES);
    memcpy(fpn_header->data, data_fpn, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET);

    // Calculate numnugget headers (head and body are packed together, bytes at the end are ignored)
    blfs_header_t * numnuggets_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_NUMNUGGETS);
    blfs_header_t * last_header = blfs_open_header(buselfs_state->backstore,
                                                   header_types_ordered[BLFS_HEAD_NUM_HEADERS - 1][0]);

    uint64_t headersize = last_header->data_offset + last_header->data_length;
    uint64_t nuggetsize = cin_flake_size * cin_flakes_per_nugget;
    uint64_t space_for_nug_kc_tje = nuggetsize + BLFS_HEAD_BYTES_KEYCOUNT + CEIL(cin_flakes_per_nugget, BITS_IN_A_BYTE);
    uint64_t journaled_region_size = space_for_nug_kc_tje;
    int64_t space_remaining = cin_backstore_size - headersize - journaled_region_size;
    int64_t num_nuggets_calculated_64 = 0;

    IFDEBUG(dzlog_debug("headersize = %"PRIu64, headersize));
    IFDEBUG(dzlog_debug("nuggetsize = %"PRIu64, nuggetsize));
    IFDEBUG(dzlog_debug("space_for_nug_kc_tje = %"PRIu64, space_for_nug_kc_tje));
    IFDEBUG(dzlog_debug("space_remaining = %"PRId64, space_remaining));

    while(space_remaining > 0 && (unsigned) space_remaining > space_for_nug_kc_tje)
    {
        num_nuggets_calculated_64 += 1;

        // Subtract the space required for a nugget, a keycount, and a TJ entry
        space_remaining -= space_for_nug_kc_tje;
    }

    IFDEBUG(dzlog_debug("num_nuggets_calculated_64 = %"PRId64, num_nuggets_calculated_64));
    IFDEBUG(dzlog_debug("space_remaining (final) = %"PRId64, space_remaining));

    if(num_nuggets_calculated_64 <= 0)
        Throw(EXCEPTION_BACKSTORE_SIZE_TOO_SMALL);

    // XXX: this is DEFINITELY endian-sensitive!!!
    uint32_t num_nuggets_calculated_32 = (uint32_t) num_nuggets_calculated_64;
    uint8_t * data_numnuggets = (uint8_t *) &num_nuggets_calculated_32;

    IFDEBUG(dzlog_debug("data_numnuggets (num_nuggets_calculated_32) = %"PRIu32, num_nuggets_calculated_32));
    IFDEBUG(dzlog_debug("data_numnuggets:"));
    IFDEBUG(hdzlog_debug(data_numnuggets, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET));

    memcpy(numnuggets_header->data, data_numnuggets, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET);

    // Do some intermediate number crunching
    blfs_backstore_setup_actual_post(buselfs_state->backstore);

    // Make sure keycounts and tj entries are in the internal cache
    for(uint32_t nugget_index = 0; nugget_index < num_nuggets_calculated_32; nugget_index++)
    {
        (void) blfs_create_keycount(buselfs_state->backstore, nugget_index);
        (void) blfs_create_tjournal_entry(buselfs_state->backstore, nugget_index);
    }

    dzlog_notice("Populating key cache...");

    populate_key_cache(buselfs_state, 0, 0);

    // Populate merkle tree with leaves, set header
    dzlog_notice("Populating merkle tree...");
    
    populate_mt(buselfs_state, 0, 0);

    // Update the global MTRH
    dzlog_notice("Almost done...");
    update_merkle_tree_root_hash(buselfs_state);

    IFDEBUG3(dzlog_debug("MERKLE TREE: debug print"));
    IFDEBUG3(mt_print(buselfs_state->merkle_tree));

    // Set initialization header to initialized and commit header
    init_header->data[0] = BLFS_HEAD_IS_INITIALIZED_VALUE;

    // Commit all headers
    blfs_commit_all_headers(buselfs_state->backstore);
    blfs_globalversion_commit(buselfs_state->rpmb_secure_index, *(uint64_t *) tpmv_header->data);
    commit_merkle_tree_root_hash(buselfs_state);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_run_mode_open(const char * backstore_path, uint8_t cin_allow_insecure_start, buselfs_state_t * buselfs_state)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));
    IFDEBUG(dzlog_debug("running in OPEN mode!"));

    buselfs_state->backstore = blfs_backstore_open(backstore_path);
    blfs_soft_open(buselfs_state, cin_allow_insecure_start);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

// TODO: retire and remove this start mode?
void blfs_run_mode_wipe(const char * backstore_path, uint8_t cin_allow_insecure_start, buselfs_state_t * buselfs_state)
{
    (void) backstore_path;
    (void) cin_allow_insecure_start;
    (void) buselfs_state;

    /*IFDEBUG(dzlog_debug(">>>> entering %s", __func__));
    IFDEBUG(dzlog_debug("running in WIPE mode!"));

    // XXX: In real life, some sort of "wipe" functionality for something like
    // this would not exist (it breaks security by allowing a bypassing of the
    // initial MTRH check by malicious header modification).
    //
    // It does here, however, because it makes this construction easier to test.
    // Maybe later, I'll include some compile flags to phase this "feature" out
    // in a production-type setting.

    buselfs_state->backstore = blfs_backstore_open(backstore_path);
    blfs_soft_open(buselfs_state, cin_allow_insecure_start);

    // Overwrite keycounts and transaction journal to 0
    uint64_t state_length = buselfs_state->backstore->body_real_offset - buselfs_state->backstore->kcs_real_offset;
    uint8_t * zeroed_state = calloc(state_length, sizeof(*zeroed_state));

    blfs_backstore_write(buselfs_state->backstore, zeroed_state, state_length, buselfs_state->backstore->kcs_real_offset);

    // Overwrite data to 0
    free(zeroed_state);

    uint64_t nugget_size_bytes = buselfs_state->backstore->nugget_size_bytes;
    uint32_t numnuggets = buselfs_state->backstore->num_nuggets;
    zeroed_state = calloc(nugget_size_bytes, sizeof(*zeroed_state));

    for(uint32_t nugget_index = 0; nugget_index < numnuggets; nugget_index++)
    {
        blfs_backstore_write_body(buselfs_state->backstore,
                                  zeroed_state,
                                  nugget_size_bytes,
                                  nugget_index * nugget_size_bytes);
    }
    
    // Reset necessary headers
    // BLFS_HEAD_HEADER_TYPE_MTRH, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER, BLFS_HEAD_HEADER_TYPE_REKEYING, BLFS_HEAD_HEADER_BYTES_INITIALIZED

    blfs_header_t * mtrh_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_MTRH);
    blfs_header_t * tpmgv_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
    blfs_header_t * rekeying_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_REKEYING);
    blfs_header_t * init_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_INITIALIZED);
    
    memset(mtrh_header->data, 0, BLFS_HEAD_HEADER_BYTES_MTRH);
    memset(tpmgv_header->data, 0, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER);
    memset(rekeying_header->data, 0xFF, BLFS_HEAD_HEADER_BYTES_REKEYING);
    init_header->data[0] = BLFS_HEAD_WAS_WIPED_VALUE;
    
    blfs_commit_header(buselfs_state->backstore, mtrh_header);
    blfs_commit_header(buselfs_state->backstore, tpmgv_header);
    blfs_commit_header(buselfs_state->backstore, rekeying_header);
    blfs_commit_header(buselfs_state->backstore, init_header);
    blfs_globalversion_commit(buselfs_state->rpmb_secure_index, 0);

    IFDEBUG(dzlog_debug("EXITING PROGRAM!"));
    Throw(EXCEPTION_MUST_HALT);*/
}

buselfs_state_t * buselfs_main_actual(int argc, char * argv[], char * blockdevice)
{
    IFDEBUG3(printf("<bare debug>: >>>> entering %s\n", __func__));

    char * cin_device_name;
    char backstore_path[BLFS_BACKSTORE_FILENAME_MAXLEN] = { 0x00 };

    // XXX: Not free()'d!
    buselfs_state_t * buselfs_state = malloc(sizeof(*buselfs_state));

    if(buselfs_state == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    buselfs_state->backstore = NULL;
    IFENERGYMON(buselfs_state->energymon_monitor = NULL);

    IFENERGYMON(blfs_energymon_init(buselfs_state));
    IFENERGYMON(dzlog_info("Energymon interface initialized!"));
    IFENERGYMON(IFDEBUG(dzlog_debug("Energymon output: %s", BLFS_ENERGYMON_OUTPUT_PATH)));

    IFENERGYMON(IFDEBUG(dzlog_debug("beginning startup energy monitoring...")));

    ENERGYMON_INIT_IFENERGYMON;
    ENERGYMON_START_IFENERGYMON;

    uint8_t  cin_allow_insecure_start       = FALSE;
    uint8_t  cin_use_default_password       = FALSE;
    stream_cipher_e cin_cipher              = sc_default;
    uint8_t  cin_backstore_mode             = BLFS_BACKSTORE_CREATE_MODE_UNKNOWN;
    uint64_t cin_backstore_size             = BLFS_DEFAULT_BYTES_BACKSTORE * BYTES_IN_A_MB;
    uint32_t cin_flake_size                 = BLFS_DEFAULT_BYTES_FLAKE;
    uint32_t cin_flakes_per_nugget          = BLFS_DEFAULT_FLAKES_PER_NUGGET;

    IFDEBUG3(printf("<bare debug>: argc: %i\n", argc));

    if(argc <= 1 || argc > MAX_NUM_ARGC)
    {
        printf(
        "\nUsage:\n"
        "  %s [--default-password][--backstore-size %"PRIu64"][--flake-size %"PRIu32"][--flakes-per-nugget %"PRIu32"][--cipher sc_default][--tpm-id %"PRIu32"] create nbd_device_name\n\n"
        "  %s [--default-password][--allow-insecure-start] open nbd_device_name\n\n"
        "  %s [--default-password][--allow-insecure-start] wipe nbd_device_name\n\n"

        "Note: nbd_device must always appear last and the desired command (open, wipe, etc) second to last.\n\n"

        "::create command::\n"
        "This command will create and load a brand new buselfs backstore. Note that this command will force overwrite a\n"
        " previous backstore made with the same nbd device name if it already exists.\n\n"
        "Example: %s --backstore-size 4096 create nbd4\n\n"
        ":options:\n"
        "- default-password  instead of asking you for a password, the password '"BLFS_DEFAULT_PASS"' will be used.\n"
        "- backstore-size    size of the backstore; must be in MEGABYTES.\n"
        "- flake-size        size of each individual flake; must be in BYTES\n"
        "- flakes-per-nugget number of flakes per nugget\n"
        "- cipher            chosen stream cipher for crypt (see constants.h for choices here)\n"
        "- tpm-id            internal index used by RPMB module\n\n"
        "Defaults are shown above. \n\n"
        
        "::open command::\n"
        "This command will open and load a preexisting buselfs backstore or fail if it does not exist.\n\n"
        "Example: %s --allow-insecure-start open nbd4\n\n"
        ":options:\n"
        "- default-password  instead of asking you for a password, the password '"BLFS_DEFAULT_PASS"' will be used.\n"
        "- allow-insecure-start ignores a MTRH failure (integrity issue) and loads the buselfs backstore anyway\n\n"

        "::wipe command::\n"
        "Will reset an already existing buselfs backstore to its initial state, as if it were newly created. It will not\n"
        " be automatically loaded and must be subsequently opened via the open command. Note that this command only works\n"
        " if the backstore in question is indeed a valid buselfs backstore.\n\n"
        "Example: %s wipe nbd4\n\n"
        ":options:\n"
        "- default-password  instead of asking you for a password, the password '"BLFS_DEFAULT_PASS"' will be used.\n"
        "- allow-insecure-start ignores a MTRH failure (integrity issue) and loads the buselfs backstore anyway\n\n"

        "To test for correctness, run `make pre && make check` from the /build directory. Check the README for more details.\n"
        "Don't forget to load nbd kernel module `modprobe nbd` and run as root!\n\n",
        argv[0], BLFS_DEFAULT_BYTES_BACKSTORE, BLFS_DEFAULT_BYTES_FLAKE, BLFS_DEFAULT_FLAKES_PER_NUGGET, BLFS_DEFAULT_TPM_ID,
        argv[0], argv[0], argv[0], argv[0], argv[0]);

        Throw(EXCEPTION_MUST_HALT);
    }

    buselfs_state->rpmb_secure_index = BLFS_DEFAULT_TPM_ID;

    /* Process arguments */
    cin_device_name = argv[--argc];

    if(strcmp(argv[--argc], "create") == 0)
        cin_backstore_mode = BLFS_BACKSTORE_CREATE_MODE_CREATE;

    else if(strcmp(argv[argc], "open") == 0)
        cin_backstore_mode = BLFS_BACKSTORE_CREATE_MODE_OPEN;

    else if(strcmp(argv[argc], "wipe") == 0)
        cin_backstore_mode = BLFS_BACKSTORE_CREATE_MODE_WIPE;

    else Throw(EXCEPTION_UNKNOWN_MODE);

    IFDEBUG3(printf("<bare debug>: cin_backstore_mode: %i\n", cin_backstore_mode));

    while(argc-- > 1)
    {
        errno = 0;

        if(strcmp(argv[argc], "--backstore-size") == 0)
        {
            int64_t cin_backstore_size_int = strtoll(argv[argc + 1], NULL, 0);
            cin_backstore_size = strtoll(argv[argc + 1], NULL, 0);

            if(cin_backstore_size_int < 0)
                Throw(EXCEPTION_INVALID_BACKSTORESIZE);

            IFDEBUG3(printf("<bare debug>: saw --backstore-size, got value: %"PRIu64"\n", cin_backstore_size));

            if(cin_backstore_size * BYTES_IN_A_MB < cin_backstore_size)
                Throw(EXCEPTION_INVALID_BACKSTORESIZE);

            cin_backstore_size *= BYTES_IN_A_MB;

            IFDEBUG3(printf("<bare debug>: real value: %"PRIu64"\n", cin_backstore_size));
        }

        else if(strcmp(argv[argc], "--flake-size") == 0)
        {
            int64_t cin_flake_size_int = strtoll(argv[argc + 1], NULL, 0);
            cin_flake_size = (uint32_t) cin_flake_size_int;

            if(cin_flake_size != cin_flake_size_int)
                Throw(EXCEPTION_INVALID_FLAKESIZE);

            IFDEBUG3(printf("<bare debug>: saw --flake-size = %"PRIu32"\n", cin_flake_size));
        }

        else if(strcmp(argv[argc], "--flakes-per-nugget") == 0)
        {
            int64_t cin_flakes_per_nugget_int = strtoll(argv[argc + 1], NULL, 0);
            cin_flakes_per_nugget = (uint32_t) cin_flakes_per_nugget_int;

            if(cin_flakes_per_nugget != cin_flakes_per_nugget_int)
                Throw(EXCEPTION_INVALID_FLAKES_PER_NUGGET);

            IFDEBUG3(printf("<bare debug>: saw --flakes-per-nugget = %"PRIu32"\n", cin_flakes_per_nugget));
        }

        else if(strcmp(argv[argc], "--allow-insecure-start") == 0)
        {
            cin_allow_insecure_start = TRUE;
            IFDEBUG3(printf("<bare debug>: saw --allow-insecure-start = %i\n", cin_allow_insecure_start));
        }

        else if(strcmp(argv[argc], "--default-password") == 0)
        {
            cin_use_default_password = TRUE;
            IFDEBUG3(printf("<bare debug>: saw --default-password = %i\n", cin_use_default_password));
        }

        else if(strcmp(argv[argc], "--cipher") == 0)
        {
            char * cin_cipher_str = argv[argc + 1];

            IFDEBUG3(printf("<bare debug>: saw --cipher = %s\n", cin_cipher_str));

            cin_cipher = stream_string_to_cipher(cin_cipher_str);

            IFDEBUG3(printf("<bare debug>: saw --cipher, got enum value: %d\n", cin_cipher));
        }

        else if(strcmp(argv[argc], "--tpm-id") == 0)
        {
            int64_t cin_tpm_id_int = strtoll(argv[argc + 1], NULL, 0);
            buselfs_state->rpmb_secure_index = strtoll(argv[argc + 1], NULL, 0);

            if(cin_tpm_id_int <= 0)
                Throw(EXCEPTION_INVALID_TPM_ID);

            IFDEBUG3(printf("<bare debug>: saw --tpm-id, got value: %"PRIu64"\n", buselfs_state->rpmb_secure_index));
        }

        IFDEBUG3(printf("<bare debug>: errno = %i\n", errno));

        if(errno == ERANGE)
        {
            IFDEBUG3(printf("<bare debug>: EXCEPTION: GOT ERANGE! BAD ARGS!\n"));
            Throw(EXCEPTION_BAD_ARGUMENT_FORM);
        }
    }

    IFDEBUG3(printf("<bare debug>: argument processing result:\n"));
    IFDEBUG3(printf("<bare debug>: cin_allow_insecure_start = %i\n", cin_allow_insecure_start));
    IFDEBUG3(printf("<bare debug>: cin_backstore_size = %"PRIu64"\n", cin_backstore_size));
    IFDEBUG3(printf("<bare debug>: cin_flake_size = %"PRIu32"\n", cin_flake_size));
    IFDEBUG3(printf("<bare debug>: cin_flakes_per_nugget = %"PRIu32"\n", cin_flakes_per_nugget));
    IFDEBUG3(printf("<bare debug>: cin_backstore_mode = %i\n", cin_backstore_mode));
    IFDEBUG3(printf("<bare debug>: rpmb_secure_index = %"PRIu64"\n", buselfs_state->rpmb_secure_index));
    IFDEBUG3(printf("<bare debug>: cin_cipher = %d\n", cin_cipher));

    IFDEBUG3(printf("<bare debug>: defaults:\n"));
    IFDEBUG3(printf("<bare debug>: default allow_insecure_start = 0\n"));
    IFDEBUG3(printf("<bare debug>: default force_overwrite_backstore = 0\n"));
    IFDEBUG3(printf("<bare debug>: default backstore_size (MB) = %"PRIu64"\n", BLFS_DEFAULT_BYTES_BACKSTORE));
    IFDEBUG3(printf("<bare debug>: default flake_size = %"PRIu32"\n", BLFS_DEFAULT_BYTES_FLAKE));
    IFDEBUG3(printf("<bare debug>: default flakes_per_nugget = %"PRIu32"\n", BLFS_DEFAULT_FLAKES_PER_NUGGET));
    IFDEBUG3(printf("<bare debug>: default cin_backstore_mode = %i\n", BLFS_BACKSTORE_CREATE_MODE_UNKNOWN));
    IFDEBUG3(printf("<bare debug>: default rpmb_secure_index = %i\n", BLFS_DEFAULT_TPM_ID));
    IFDEBUG3(printf("<bare debug>: default cin_cipher = %d\n", sc_default));

    IFDEBUG3(printf("<bare debug>: BLFS_BACKSTORE_CREATE_MAX_MODE_NUM = %i\n", BLFS_BACKSTORE_CREATE_MAX_MODE_NUM));

    if(cin_backstore_mode > BLFS_BACKSTORE_CREATE_MAX_MODE_NUM)
        Throw(EXCEPTION_BAD_ARGUMENT_FORM);

    errno = 0;

    if(!cin_backstore_size || cin_backstore_size > UINT_MAX)
        Throw(EXCEPTION_INVALID_BACKSTORESIZE);

    if(!cin_flake_size || cin_flake_size > UINT_MAX)
        Throw(EXCEPTION_INVALID_FLAKESIZE);

    if(!cin_flakes_per_nugget || cin_flakes_per_nugget > UINT_MAX)
        Throw(EXCEPTION_INVALID_FLAKES_PER_NUGGET);

    blfs_set_stream_context(buselfs_state, cin_cipher);

    /* Prepare to setup the backstore file */

    sprintf(backstore_path, BLFS_BACKSTORE_FILENAME, cin_device_name);
    IFDEBUG3(printf("<bare debug>: backstore_path = %s\n", backstore_path));

    IFDEBUG3(printf("<bare debug>: continuing pre-initialization step...\n"));

    /* Initialize libsodium */

    if(sodium_init() == -1)
        Throw(EXCEPTION_SODIUM_INIT_FAILURE);

    /* Initialize OpenSSL if we're going to be using AES-XTS emulation */

    if(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION)
    {
        dzlog_warn("WARNING: AES-XTS emulation is ON! It is NOT secure!");

        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        OPENSSL_config(NULL);
    }

    /* Initialize nugget key cache */

    if(!BLFS_DEFAULT_DISABLE_KEY_CACHING)
        buselfs_state->cache_nugget_keys = kh_init(BLFS_KHASH_NUGGET_KEY_CACHE_NAME);

    /* Initialize zlog */

    char buf[100] = { 0x00 };

    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), cin_device_name);
    IFDEBUG3(printf("<bare debug>: BLFS_CONFIG_ZLOG = %s\n", BLFS_CONFIG_ZLOG));
    IFDEBUG3(printf("<bare debug>: zlog buf = %s\n", buf));

    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
    {
        Throw(EXCEPTION_ZLOG_INIT_FAILURE);
    }

    IFDEBUG(dzlog_debug("switched over to zlog for logging"));
    IFDEBUG(dzlog_notice("Initializing, please wait..."));

    /* Initialize merkle tree */

    buselfs_state->merkle_tree = mt_create();

    /* Sanity/safety asserts */

    assert(crypto_stream_chacha20_KEYBYTES == BLFS_CRYPTO_BYTES_CHACHA_KEY);
    assert(crypto_stream_chacha20_NONCEBYTES == BLFS_CRYPTO_BYTES_CHACHA_NONCE);
    assert(crypto_box_SEEDBYTES == BLFS_CRYPTO_BYTES_KDF_OUT);
    assert(crypto_pwhash_SALTBYTES == BLFS_CRYPTO_BYTES_KDF_SALT);
    assert(crypto_onetimeauth_poly1305_BYTES == BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT);
    assert(crypto_onetimeauth_poly1305_KEYBYTES == BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY);
    assert(HASH_LENGTH == BLFS_CRYPTO_BYTES_MTRH);
    assert(!(BLFS_BADBADNOTGOOD_USE_AESXTS_EMULATION && BLFS_NO_READ_INTEGRITY) && "These two cannot be used together!");

    IFDEBUG(dzlog_debug("cin_flakes_per_nugget > BLFS_CRYPTO_BYTES_MTRH: (%"PRIu32" >? %"PRIu32")",
                        cin_flakes_per_nugget, BLFS_CRYPTO_BYTES_MTRH * 8));

    if(cin_flakes_per_nugget > BLFS_CRYPTO_BYTES_MTRH * 8)
    {
        IFDEBUG(dzlog_debug("EXCEPTION: too many flakes per nugget! (%"PRIu32">%"PRIu32")",
                            cin_flakes_per_nugget, BLFS_CRYPTO_BYTES_MTRH * 8));

        Throw(EXCEPTION_TOO_MANY_FLAKES_PER_NUGGET);
    }

    /* Setup backstore file access */

    buselfs_state->crash_recovery = FALSE;
    buselfs_state->default_password = cin_use_default_password ? BLFS_DEFAULT_PASS : NULL;

    if(cin_backstore_mode == BLFS_BACKSTORE_CREATE_MODE_CREATE)
        blfs_run_mode_create(backstore_path, cin_backstore_size, cin_flake_size, cin_flakes_per_nugget, buselfs_state);

    else if(cin_backstore_mode == BLFS_BACKSTORE_CREATE_MODE_OPEN)
        blfs_run_mode_open(backstore_path, cin_allow_insecure_start, buselfs_state);

    else if(cin_backstore_mode == BLFS_BACKSTORE_CREATE_MODE_WIPE)
        blfs_run_mode_wipe(backstore_path, cin_allow_insecure_start, buselfs_state);

    /* Finish up startup procedures */

    IFDEBUG(dzlog_info("Defined: BLFS_DEBUG_LEVEL = %i", BLFS_DEBUG_LEVEL));

    if(buselfs_state->backstore == NULL)
        Throw(EXCEPTION_ASSERT_FAILURE);

    buseops.size = buselfs_state->backstore->writeable_size_actual;

    IFDEBUG(dzlog_info("buseops.size = %"PRIu64, buseops.size));

    /* Let the show begin! */

    IFDEBUG(dzlog_info(">> buselfs backend was setup successfully! <<"));

    sprintf(blockdevice, BLFS_BACKSTORE_DEVICEPATH, cin_device_name);
    IFDEBUG(dzlog_debug("RETURN: blockdevice = %s", blockdevice));

    ENERGYMON_END_IFENERGYMON;
    ENERGYMON_OUTPUT_IFENERGYMON("blfs_startup");
    IFENERGYMON(blfs_energymon_fini(buselfs_state));
    
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));

    return buselfs_state;
}

int buselfs_main(int argc, char * argv[])
{
    char blockdevice[BLFS_BACKSTORE_FILENAME_MAXLEN] = { 0x00 };
    buselfs_state_t * buselfs_state;

    IFDEBUG(dzlog_debug("<< configuring global buselfs_state >>"));

    buselfs_state = buselfs_main_actual(argc, argv, blockdevice);

    IFDEBUG(dzlog_debug("<<<< handing control over to buse_main >>>>"));

    dzlog_notice("StrongBox is ready!\n");

    return buse_main(blockdevice, &buseops, (void *) buselfs_state);
}
