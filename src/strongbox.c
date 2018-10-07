/**
 * Backend virtual block device for any LFS using BUSE
 *
 * @author Bernard Dickens
 */

#include "strongbox.h"
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

// ! This must be changed/updated if we're adding new storage layers (e.g.
// ! the new "nugget metadata" layer)
uint32_t calculate_total_space_required_for_1nug(uint32_t nuggetsize, uint32_t flakes_per_nugget, uint32_t md_bytes_per_nugget)
{
    return nuggetsize // ? Space for 1 nugget
        + BLFS_HEAD_BYTES_KEYCOUNT // ? Space for 1 kcs
        + CEIL(flakes_per_nugget, BITS_IN_A_BYTE) // ? Space for 1 TJ entry
        + md_bytes_per_nugget; // ? Space for 1 nugget md
}

// ! This must be changed/updated if we're adding new storage layers (e.g.
// ! the new "nugget metadata" layer)
uint32_t mt_calculate_expected_size(uint32_t nugget_index, buselfs_state_t * buselfs_state)
{
    // ? 3*N+(BLFS_HEAD_NUM_HEADERS-3)+(nugget_index*fpn)+1
    // See the `merkle_tree` declaration in the `buselfs_state_t` definition in
    // `strongbox.h` for more details on this calculation.
    return 1
        + (BLFS_HEAD_NUM_HEADERS - 3)
        + buselfs_state->backstore->num_nuggets * 3
        + nugget_index * buselfs_state->backstore->flakes_per_nugget;
}

// ! This must be changed/updated if we're adding new storage layers (e.g.
// ! the new "nugget metadata" layer)
uint32_t mt_calculate_flake_offset(uint32_t jump_to_nugget_index, uint32_t flake_index, buselfs_state_t * buselfs_state)
{
    // ? Jump over indicies that aren't associated w/ this nug and land on the
    // ? flake that we're looking for (at an index contained in this nug)
    return mt_calculate_expected_size(jump_to_nugget_index, buselfs_state) + flake_index;
}

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
 * ! This function MUST be called before buselfs_state->merkle_tree_root_hash
 * ! is referenced!
 *
 * @param buselfs_state
 */
void update_merkle_tree_root_hash(buselfs_state_t * buselfs_state)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(mt_get_root(buselfs_state->merkle_tree, buselfs_state->merkle_tree_root_hash) != MT_SUCCESS)
        Throw(EXCEPTION_MERKLE_TREE_ROOT_FAILURE);

    IFDEBUG(dzlog_debug("merkle tree root hash:"));
    IFDEBUG(hdzlog_debug(buselfs_state->merkle_tree_root_hash, BLFS_CRYPTO_BYTES_MTRH));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void commit_merkle_tree_root_hash(buselfs_state_t * buselfs_state)
{
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
void add_to_merkle_tree(uint8_t * data, size_t length, const buselfs_state_t * buselfs_state)
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
void update_in_merkle_tree(uint8_t * data, size_t length, uint32_t index, const buselfs_state_t * buselfs_state)
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
void verify_in_merkle_tree(uint8_t * data, size_t length, uint32_t index, const buselfs_state_t * buselfs_state)
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

static void populate_key_cache(buselfs_state_t * buselfs_state)
{
    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        dzlog_info("KEY CACHING DISABLED!");

    else
    {
        // First with nugget keys:
        // nugget_index => (nugget_key = master_secret+nugget_index)
        for(uint32_t nugget_index = 0; nugget_index < buselfs_state->backstore->num_nuggets; nugget_index++)
        {
            uint8_t * nugget_key = malloc(BLFS_CRYPTO_BYTES_KDF_OUT * sizeof *nugget_key);
            blfs_keycount_t * count;

            count = blfs_open_keycount(buselfs_state->backstore, nugget_index);

            if(nugget_key == NULL)
                Throw(EXCEPTION_ALLOC_FAILURE);

            blfs_nugget_key_from_data(nugget_key, buselfs_state->backstore->master_secret, nugget_index);
            add_index_to_key_cache(buselfs_state, nugget_index, nugget_key);

            // Now with nugget keys:
            // nugget_index||flake_index||associated_keycount => master_secret+nugget_index+flake_index+associated_keycount
            for(uint32_t flake_index = 0; flake_index < buselfs_state->backstore->flakes_per_nugget; flake_index++)
            {
                uint8_t * flake_key = malloc(BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY * sizeof *flake_key);

                if(flake_key == NULL)
                    Throw(EXCEPTION_ALLOC_FAILURE);

                blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, count->keycount);
                add_keychain_to_key_cache(buselfs_state, nugget_index, flake_index, count->keycount, flake_key);
            }
        }
    }
}

static void populate_mt(buselfs_state_t * buselfs_state)
{
    uint32_t flakesize = buselfs_state->backstore->flake_size_bytes;
    uint32_t nugsize   = buselfs_state->backstore->nugget_size_bytes;

    uint32_t operations_completed = 0;
    IFNDEBUG(uint32_t operations_total = mt_calculate_expected_size(buselfs_state->backstore->num_nuggets, buselfs_state));

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
        blfs_keycount_t * count = blfs_open_keycount(buselfs_state->backstore, nugget_index);

        add_to_merkle_tree((uint8_t *) &(count->keycount), BLFS_HEAD_BYTES_KEYCOUNT, buselfs_state);
        IFDEBUG(verify_in_merkle_tree((uint8_t *) &(count->keycount), BLFS_HEAD_BYTES_KEYCOUNT, operations_completed, buselfs_state));
        IFNDEBUG(interact_print_percent_done((operations_completed + 1) * 100 / operations_total));
    }

    // Next, the TJ entries
    IFDEBUG(dzlog_debug("MERKLE TREE: adding transaction journal entries..."));
    IFDEBUG(dzlog_debug("MERKLE TREE: starting index %"PRIu32, operations_completed));

    for(uint32_t nugget_index = 0; nugget_index < buselfs_state->backstore->num_nuggets; nugget_index++, operations_completed++)
    {
        blfs_tjournal_entry_t * entry = blfs_open_tjournal_entry(buselfs_state->backstore, nugget_index);

        uint8_t hash[BLFS_CRYPTO_BYTES_STRUCT_HASH_OUT];

        blfs_chacha20_struct_hash(hash, entry->bitmask->mask, entry->bitmask->byte_length, buselfs_state->backstore->master_secret);
        add_to_merkle_tree(hash, BLFS_CRYPTO_BYTES_STRUCT_HASH_OUT, buselfs_state);
        IFDEBUG(verify_in_merkle_tree(hash, BLFS_CRYPTO_BYTES_STRUCT_HASH_OUT, operations_completed, buselfs_state));
        IFNDEBUG(interact_print_percent_done((operations_completed + 1) * 100 / operations_total));
    }

    // Next, the nugget metadata
    IFDEBUG(dzlog_debug("MERKLE TREE: adding nugget metadata..."));
    IFDEBUG(dzlog_debug("MERKLE TREE: starting index %"PRIu32, operations_completed));

    for(uint32_t nugget_index = 0; nugget_index < buselfs_state->backstore->num_nuggets; nugget_index++, operations_completed++)
    {
        blfs_nugget_metadata_t * meta = blfs_open_nugget_metadata(buselfs_state->backstore, nugget_index);

        uint8_t data[meta->data_length];
        uint8_t hash[BLFS_CRYPTO_BYTES_STRUCT_HASH_OUT];

        memcpy(data, &(meta->cipher_ident), 1);

        if(meta->metadata_length)
            memcpy(data + 1, meta->metadata, meta->metadata_length);

        blfs_chacha20_struct_hash(hash, data, meta->data_length, buselfs_state->backstore->master_secret);
        add_to_merkle_tree(hash, sizeof hash, buselfs_state);
        IFDEBUG(verify_in_merkle_tree(hash, BLFS_CRYPTO_BYTES_STRUCT_HASH_OUT, operations_completed, buselfs_state));
        IFNDEBUG(interact_print_percent_done((operations_completed + 1) * 100 / operations_total));
    }

    // Finally, the flake tags
    IFDEBUG(dzlog_debug("MERKLE TREE: adding flake tags..."));
    IFDEBUG(dzlog_debug("MERKLE TREE: starting index %"PRIu32, operations_completed));

    for(uint32_t nugget_index = 0; nugget_index < buselfs_state->backstore->num_nuggets; nugget_index++)
    {
        uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };
        blfs_keycount_t * count;

        count = blfs_open_keycount(buselfs_state->backstore, nugget_index);

        if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
            blfs_nugget_key_from_data(nugget_key, buselfs_state->backstore->master_secret, nugget_index);

        for(uint32_t flake_index = 0; flake_index < buselfs_state->backstore->flakes_per_nugget; flake_index++, operations_completed++)
        {
            uint8_t flake_key[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0x00 };
            uint8_t * tag = malloc(BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT * sizeof *tag);
            uint8_t flake_data[flakesize];

            if(tag == NULL)
                Throw(EXCEPTION_ALLOC_FAILURE);

            if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
                blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, count->keycount);

            else
                get_flake_key_using_keychain(flake_key, buselfs_state, nugget_index, flake_index, count->keycount);

            blfs_backstore_read_body(buselfs_state->backstore, flake_data, flakesize, nugget_index * nugsize + flake_index * flakesize);

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

void remove_keychain_from_key_cache(buselfs_state_t * buselfs_state,
                                      uint32_t nugget_index,
                                      uint32_t flake_index,
                                      uint64_t keycount)
{
    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        Throw(EXCEPTION_BAD_CACHE);

    char kh_flake_key[BLFS_KHASH_NUGGET_KEY_SIZE_BYTES] = { 0x00 };

    sprintf(kh_flake_key, "%"PRIu32"||%"PRIu32"||%"PRIu64, nugget_index, flake_index, keycount);
    IFDEBUG(dzlog_debug("CACHE: *removing* KHASH flake keychain key %s from cache...", kh_flake_key));

    KHASH_CACHE_DEL_WITH_KEY(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, kh_flake_key);
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
                                  const buselfs_state_t * buselfs_state,
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

blfs_backstore_t * blfs_backstore_open_with_ctx(const char * path, buselfs_state_t * buselfs_state)
{
    blfs_backstore_t * backstore = blfs_backstore_open(path);

    // TODO: choose the larger of the two requested sizes if cipher switching
    // ? +1 for the byte that holds the swappable_cipher_e identifier associated
    // ? with that nugget
    backstore->md_bytes_per_nugget = buselfs_state->active_cipher->requested_md_bytes_per_nugget + 1;

    IFDEBUG(dzlog_debug("cipher requested %"PRIu32" (additional) bytes of metadata per nugget",
        buselfs_state->active_cipher->requested_md_bytes_per_nugget
    ));

    IFDEBUG(dzlog_debug("decided to allocate %"PRIu32" bytes of metadata per nugget",
        backstore->md_bytes_per_nugget
    ));

    blfs_backstore_setup_actual_finish(backstore);

    return backstore;
}

int buse_read(void * output_buffer, uint32_t length, uint64_t absolute_offset, void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint8_t * buffer = (uint8_t *) output_buffer;
    buselfs_state_t * buselfs_state = (buselfs_state_t *) userdata;
    uint_fast32_t size = length;

    IFDEBUG(dzlog_debug("output_buffer (ptr): %p", (void *) output_buffer));
    IFDEBUG(dzlog_debug("buffer (ptr): %p", (void *) buffer));
    IFDEBUG(dzlog_debug("length: %"PRIu32, length));
    IFDEBUG(dzlog_debug("absolute_offset: %"PRIu64, absolute_offset));
    IFDEBUG(dzlog_debug("userdata (ptr): %p", (void *) userdata));
    IFDEBUG(dzlog_debug("buselfs_state (ptr): %p", (void *) buselfs_state));

    uint_fast32_t nugget_size       = buselfs_state->backstore->nugget_size_bytes;
    uint_fast32_t flake_size        = buselfs_state->backstore->flake_size_bytes;
    uint_fast32_t flakes_per_nugget = buselfs_state->backstore->flakes_per_nugget;
    uint_fast32_t num_nuggets = buselfs_state->backstore->num_nuggets;
    uint_fast32_t mt_offset = mt_calculate_expected_size(0, buselfs_state);

    (void) num_nuggets; // ? Even when not debugging, no warnings from compiler!

    // ! For a bigger system, this cast could be a problem
    uint_fast32_t nugget_offset          = (uint_fast32_t)(absolute_offset / nugget_size); // nugget_index
    uint_fast32_t nugget_internal_offset = (uint_fast32_t)(absolute_offset % nugget_size); // internal point at which to start within nug

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

        (void) size;
        IFDEBUG(assert(length > 0 && length <= size));

        uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT];

        uint_fast32_t buffer_read_length = MIN(length, nugget_size - nugget_internal_offset); // nmlen
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

        if(buselfs_state->active_cipher->read_handle)
        {
            buffer += buselfs_state->active_cipher->read_handle(
                buffer,
                buselfs_state,
                buffer_read_length,
                flake_index,
                flake_end,
                first_affected_flake,
                flake_size,
                flakes_per_nugget,
                mt_offset,
                nugget_data,
                nugget_key,
                nugget_offset,
                nugget_internal_offset,
                count,
                first_nugget,
                last_nugget
            );
        }

        else
        {
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

                verify_in_merkle_tree(tag, sizeof tag, mt_offset + nugget_offset * flakes_per_nugget + flake_index, buselfs_state);
            }

            IFDEBUG(dzlog_debug(
                "blfs_crypt calculated ptr: %p --[ + "
                "%"PRIuFAST32" - %"PRIuFAST32" * %"PRIuFAST32" => %"PRIuFAST32
                " ]> %p (crypting %"PRIuFAST32" bytes)",
                (void *) nugget_data,
                nugget_internal_offset,
                first_affected_flake,
                flake_size,
                nugget_internal_offset - first_affected_flake * flake_size,
                (void *) (nugget_data + (nugget_internal_offset - first_affected_flake * flake_size)),
                buffer_read_length
            ));

            blfs_swappable_crypt(
                buselfs_state->active_cipher,
                buffer,
                nugget_data + (nugget_internal_offset - first_affected_flake * flake_size),
                buffer_read_length,
                nugget_key,
                count->keycount,
                nugget_internal_offset
            );

            IFDEBUG(dzlog_debug("output_buffer final contents (initial 64 bytes):"));
            IFDEBUG(hdzlog_debug(output_buffer, MIN(64U, size)));

            buffer += buffer_read_length;
        }

        length -= buffer_read_length;
        nugget_internal_offset = 0;
        nugget_offset++;

        IFDEBUG(dzlog_debug("END (next nugget):"));
        IFDEBUG(dzlog_debug("buffer: %p", (void *) buffer));
        IFDEBUG(dzlog_debug("length: %"PRIu32, length));
        IFDEBUG(dzlog_debug("nugget_internal_offset: %"PRIuFAST32, nugget_internal_offset));
        IFDEBUG(dzlog_debug("nugget_offset: %"PRIuFAST32, nugget_offset));

        first_nugget = FALSE;
    }

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return 0;
}

int buse_write(const void * input_buffer, uint32_t length, uint64_t absolute_offset, void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    const uint8_t * buffer = (const uint8_t *) input_buffer;
    buselfs_state_t * buselfs_state = (buselfs_state_t *) userdata;
    uint_fast32_t size = length;

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

    uint_fast32_t mt_offset = mt_calculate_expected_size(0, buselfs_state);

    // ! For a bigger system, this cast could be a problem
    uint_fast32_t nugget_offset          = (uint_fast32_t)(absolute_offset / nugget_size); // nugget_index
    uint_fast32_t nugget_internal_offset = (uint_fast32_t)(absolute_offset % nugget_size); // internal point at which to start within nug

    IFDEBUG(dzlog_debug("nugget_size: %"PRIuFAST32, nugget_size));
    IFDEBUG(dzlog_debug("flake_size: %"PRIuFAST32, flake_size));
    IFDEBUG(dzlog_debug("num_nuggets: %"PRIuFAST32, num_nuggets));
    IFDEBUG(dzlog_debug("flakes_per_nugget: %"PRIuFAST32, flakes_per_nugget));
    IFDEBUG(dzlog_debug("mt_offset: %"PRIuFAST32, mt_offset));
    IFDEBUG(dzlog_debug("nugget_offset: %"PRIuFAST32, nugget_offset));
    IFDEBUG(dzlog_debug("nugget_internal_offset: %"PRIuFAST32, nugget_internal_offset));

    IFDEBUG(dzlog_debug("buffer to write (initial 64 bytes):"));
    IFDEBUG(hdzlog_debug(input_buffer, MIN(64U, size)));

    blfs_header_t * tpmv_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
    uint64_t tpmv_value = *(uint64_t *) tpmv_header->data;

    IFDEBUG(dzlog_debug("tpmv_header->data:"));
    IFDEBUG(dzlog_debug("was %"PRIu64, tpmv_value));

    tpmv_value++;

    IFDEBUG(dzlog_debug("now %"PRIu64, tpmv_value));

    memcpy(tpmv_header->data, (uint8_t *) &tpmv_value, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER);

    // ! Needs to be guaranteed monotonic in a real implementation, not based on header
    blfs_globalversion_commit(buselfs_state->rpmb_secure_index, tpmv_value);

    while(length != 0)
    {
        IFDEBUG(dzlog_debug("starting with length: %"PRIu32, length));

        (void) size;
        IFDEBUG(assert(length > 0 && length <= size));

        uint_fast32_t buffer_write_length = MIN(length, nugget_size - nugget_internal_offset); // nmlen
        uint_fast32_t first_affected_flake = nugget_internal_offset / flake_size;
        uint_fast32_t num_affected_flakes =
            CEIL((nugget_internal_offset + buffer_write_length), flake_size) - first_affected_flake;

        IFDEBUG(dzlog_debug("buffer_write_length: %"PRIuFAST32, buffer_write_length));
        IFDEBUG(dzlog_debug("first_affected_flake: %"PRIuFAST32, first_affected_flake));
        IFDEBUG(dzlog_debug("num_affected_flakes: %"PRIuFAST32, num_affected_flakes));

        uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT];

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

        uint_fast32_t flake_index = first_affected_flake;
        uint_fast32_t flake_end = first_affected_flake + num_affected_flakes;

        if(buselfs_state->active_cipher->write_handle)
        {
            buffer += buselfs_state->active_cipher->write_handle(
                buffer,
                buselfs_state,
                buffer_write_length,
                flake_index,
                flake_end,
                flake_size,
                flakes_per_nugget,
                flake_internal_offset,
                mt_offset,
                nugget_key,
                nugget_offset,
                count
            );
        }

        else
        {
            // First, check if this constitutes an overwrite...
            blfs_tjournal_entry_t * entry = blfs_open_tjournal_entry(buselfs_state->backstore, nugget_offset);

            IFDEBUG(dzlog_debug("entry->bitmask (pre-update):"));
            IFDEBUG(hdzlog_debug(entry->bitmask->mask, entry->bitmask->byte_length));

            if(bitmask_any_bits_set(entry->bitmask, first_affected_flake, num_affected_flakes))
            {
                IFDEBUG(dzlog_notice("OVERWRITE DETECTED! PERFORMING IN-PLACE JOURNALED REKEYING + WRITE (l=%"PRIuFAST32")", buffer_write_length));
                blfs_rekey_nugget_then_write(buselfs_state, nugget_offset, buffer, buffer_write_length, nugget_internal_offset);

                buffer += buffer_write_length;
            }

            else
            {
                // ! Maybe update and commit the MTRH here first and again later?

                for(uint_fast32_t i = 0; flake_index < flake_end; flake_index++, i++)
                {
                    uint_fast32_t flake_write_length = MIN(flake_total_bytes_to_write, flake_size - flake_internal_offset);

                    IFDEBUG(dzlog_debug("flake_write_length: %"PRIuFAST32, flake_write_length));
                    IFDEBUG(dzlog_debug("flake_index: %"PRIuFAST32, flake_index));
                    IFDEBUG(dzlog_debug("flake_end: %"PRIuFAST32, flake_end));

                    uint8_t flake_data[flake_size];
                    IFDEBUG(memset(flake_data, 0, flake_size));

                    // ! Data to write isn't aligned and/or is smaller than
                    // ! flake_size, so we need to verify its integrity
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

                    IFDEBUG(dzlog_debug("INCOMPLETE flake_data (initial 64 bytes):"));
                    IFDEBUG(hdzlog_debug(flake_data, MIN(64U, flake_size)));

                    IFDEBUG(dzlog_debug("buffer at this point (initial 64 bytes):"));
                    IFDEBUG(hdzlog_debug(buffer, MIN(64U, length)));

                    IFDEBUG(dzlog_debug("blfs_crypt calculated src length: %"PRIuFAST32, flake_write_length));

                    IFDEBUG(dzlog_debug("blfs_crypt calculated dest offset: %"PRIuFAST32,
                                    i * flake_size));

                    IFDEBUG(dzlog_debug("blfs_crypt calculated nio: %"PRIuFAST32,
                                    flake_index * flake_size + flake_internal_offset));

                    blfs_swappable_crypt(
                        buselfs_state->active_cipher,
                        flake_data + flake_internal_offset,
                        buffer,
                        flake_write_length,
                        nugget_key,
                        count->keycount,
                        flake_index * flake_size + flake_internal_offset
                    );

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

                    blfs_poly1305_generate_tag(tag, flake_data, flake_size, flake_key);

                    IFDEBUG(dzlog_debug("flake_key (initial 64 bytes):"));
                    IFDEBUG(hdzlog_debug(flake_key, MIN(64U, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY)));

                    IFDEBUG(dzlog_debug("tag (initial 64 bytes):"));
                    IFDEBUG(hdzlog_debug(tag, MIN(64U, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT)));

                    IFDEBUG(dzlog_debug("update_in_merkle_tree calculated offset: %"PRIuFAST32,
                                        mt_offset + nugget_offset * flakes_per_nugget + flake_index));

                    update_in_merkle_tree(tag, sizeof tag, mt_offset + nugget_offset * flakes_per_nugget + flake_index, buselfs_state);

                    IFDEBUG(dzlog_debug("blfs_backstore_write_body offset: %"PRIuFAST32,
                                        nugget_offset * nugget_size + flake_index * flake_size + flake_internal_offset));

                    blfs_backstore_write_body(buselfs_state->backstore,
                                            flake_data + flake_internal_offset,
                                            flake_write_length,
                                            nugget_offset * nugget_size + flake_index * flake_size + flake_internal_offset);

                    IFDEBUG(dzlog_debug("blfs_backstore_write_body input (initial 64 bytes):"));
                    IFDEBUG(hdzlog_debug(flake_data + flake_internal_offset, MIN(64U, flake_write_length)));

                    flake_internal_offset = 0;

                    IFDEBUG(assert(flake_total_bytes_to_write > flake_total_bytes_to_write - flake_write_length));

                    flake_total_bytes_to_write -= flake_write_length;
                    buffer += flake_write_length;

                }

                IFDEBUG(assert(flake_total_bytes_to_write == 0));
            }

            bitmask_set_bits(entry->bitmask, first_affected_flake, num_affected_flakes);
            blfs_commit_tjournal_entry(buselfs_state->backstore, entry);
            IFDEBUG(dzlog_debug("entry->bitmask (post-update):"));
            IFDEBUG(hdzlog_debug(entry->bitmask->mask, entry->bitmask->byte_length));

            IFDEBUG(dzlog_debug("MERKLE TREE: update TJ entry"));

            uint8_t hash[BLFS_CRYPTO_BYTES_STRUCT_HASH_OUT];

            blfs_chacha20_struct_hash(hash, entry->bitmask->mask, entry->bitmask->byte_length, buselfs_state->backstore->master_secret);
            update_in_merkle_tree(
                hash,
                sizeof hash,
                num_nuggets + (BLFS_HEAD_NUM_HEADERS - 3) + nugget_offset,
                buselfs_state
            );
        }

        length -= buffer_write_length;
        nugget_internal_offset = 0;
        nugget_offset++;

        IFDEBUG(dzlog_debug("END (next nugget):"));
        IFDEBUG(dzlog_debug("buffer: %p", (void *) buffer));
        IFDEBUG(dzlog_debug("length: %"PRIu32, length));
        IFDEBUG(dzlog_debug("nugget_internal_offset: %"PRIuFAST32, nugget_internal_offset));
        IFDEBUG(dzlog_debug("nugget_offset: %"PRIuFAST32, nugget_offset));
    }

    blfs_commit_header(buselfs_state->backstore, tpmv_header);

    IFDEBUG(dzlog_debug("MERKLE TREE: update TPM header"));
    update_in_merkle_tree(tpmv_header->data, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER, 0, buselfs_state);

    commit_merkle_tree_root_hash(buselfs_state);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return 0;
}

void blfs_rekey_nugget_then_write(buselfs_state_t * buselfs_state,
                                  uint32_t rekeying_nugget_index,
                                  const uint8_t * buffer,
                                  uint32_t length,
                                  uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    // ! Might want to switch up the ordering of these operations

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

    memcpy(rekeying_nugget_data + nugget_internal_offset, buffer, length);

    // ! If we're in crash recovery mode, the very next keycount might be
    // ! burned, so we must take that possibility into account when rekeying.
    jcount->keycount = jcount->keycount + (buselfs_state->crash_recovery ? 2 : 1);

    blfs_swappable_crypt(
        buselfs_state->active_cipher,
        new_nugget_data,
        rekeying_nugget_data,
        buselfs_state->backstore->nugget_size_bytes,
        nugget_key,
        jcount->keycount,
        0
    );

    blfs_backstore_write_body(
        buselfs_state->backstore,
        new_nugget_data,
        buselfs_state->backstore->nugget_size_bytes,
        rekeying_nugget_index * buselfs_state->backstore->nugget_size_bytes
    );

    uint32_t flake_size = buselfs_state->backstore->flake_size_bytes;

    // Update the merkle tree
    for(uint32_t flake_index = 0; flake_index < buselfs_state->backstore->flakes_per_nugget; flake_index++)
    {
        uint8_t flake_key[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0x00 };
        uint8_t * tag = malloc(BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT * sizeof *tag);
        uint8_t flake_data[flake_size];
        uint32_t mt_offset = mt_calculate_flake_offset(rekeying_nugget_index, flake_index, buselfs_state);

        if(tag == NULL)
            Throw(EXCEPTION_ALLOC_FAILURE);

        blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, jcount->keycount);

        memcpy(flake_data, new_nugget_data + flake_index * flake_size, flake_size);

        if(!BLFS_DEFAULT_DISABLE_KEY_CACHING)
            remove_keychain_from_key_cache(buselfs_state, rekeying_nugget_index, flake_index, jcount->keycount);

        blfs_poly1305_generate_tag(tag, flake_data, flake_size, flake_key);
        update_in_merkle_tree(tag, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT, mt_offset, buselfs_state);
        IFDEBUG(verify_in_merkle_tree(tag, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT, mt_offset, buselfs_state));
    }

    blfs_commit_keycount(buselfs_state->backstore, jcount);

    update_in_merkle_tree((uint8_t *) &jcount->keycount,
        BLFS_HEAD_BYTES_KEYCOUNT,
        (BLFS_HEAD_NUM_HEADERS - 3) + rekeying_nugget_index,
        buselfs_state
    );

    uint_fast32_t first_affected_flake = nugget_internal_offset / flake_size;
    uint_fast32_t num_affected_flakes = CEIL((nugget_internal_offset + length), flake_size) - first_affected_flake;

    bitmask_set_bits(jentry->bitmask, first_affected_flake, num_affected_flakes);
    blfs_commit_tjournal_entry(buselfs_state->backstore, jentry);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

// TODO: mismatch between create and open; needs a fix! Though the recovery code was working for experimental purposes,
// TODO: don't try the open command until this is fixed.
void blfs_soft_open(buselfs_state_t * buselfs_state, uint8_t cin_allow_insecure_start)
{
    (void) buselfs_state;
    (void) cin_allow_insecure_start;

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
        // ? potential crash occurred; c == d + 1
        dzlog_error("Error: global version integrity failure occurred. Assessing...");
    }

    else if(global_correctness != BLFS_GLOBAL_CORRECTNESS_ALL_GOOD)
    {
        // ? bad manipulation occurred; c < d or c > d + 1
        dzlog_fatal("!!!!!!! ERROR: FATAL BLOCK DEVICE BACKSTORE GLOBAL VERSION CHECK FAILURE !!!!!!!");
        Throw(EXCEPTION_GLOBAL_CORRECTNESS_FAILURE);
    }

    dzlog_notice("Populating key cache...");

    populate_key_cache(buselfs_state);

    dzlog_notice("Populating merkle tree...");

    populate_mt(buselfs_state);

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
            dzlog_warn("`allow-insecure-start` flag detected. Forcing start anyway...");

        else
        {
            dzlog_warn("Use the allow-insecure-start flag to ignore integrity violation (at your own peril).");
            IFDEBUG(dzlog_info("Header MTRH (first) vs calculated MTRH (second):"));
            IFDEBUG(hdzlog_info(mtrh_header->data, BLFS_HEAD_HEADER_BYTES_MTRH));
            IFDEBUG(hdzlog_info(buselfs_state->merkle_tree_root_hash, BLFS_HEAD_HEADER_BYTES_MTRH));

            IFDEBUG(hdzlog_debug(buselfs_state->merkle_tree_root_hash, BLFS_HEAD_HEADER_BYTES_MTRH));
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

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

// TODO: DRY this function and the *soft_open and *wipe versions of this
// TODO: function waaaay out! This includes the cache population steps that are
// TODO: duped. Also, mode_open is lacking many of mode_create's new features!
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

        // ! refs to memory allocated during blfs_backstore_create
        // ! will be lost during an exception. It's technically a memory
        // ! leak, but it's not so pressing an issue at the moment.
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

    // Set the flakesize and fpn headers
    // ! this is DEFINITELY endian-sensitive!!!
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

    // TODO: choose the larger of the two requested sizes if cipher switching
    // ? +1 for the byte that holds the swappable_cipher_e identifier associated
    // ? with that nugget
    buselfs_state->backstore->md_bytes_per_nugget = buselfs_state->active_cipher->requested_md_bytes_per_nugget + 1;

    IFDEBUG(dzlog_debug("cipher requested %"PRIu32" (additional) bytes of metadata per nugget",
        buselfs_state->active_cipher->requested_md_bytes_per_nugget
    ));

    IFDEBUG(dzlog_debug("decided to allocate %"PRIu32" bytes of metadata per nugget",
        buselfs_state->backstore->md_bytes_per_nugget
    ));

    IFDEBUG(dzlog_debug("calculated md_bytes_per_nugget = %"PRIu32, buselfs_state->backstore->md_bytes_per_nugget));

    // Calculate numnugget headers (head and body are packed together; bytes at the end are ignored)
    blfs_header_t * numnuggets_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_NUMNUGGETS);
    blfs_header_t * last_header = blfs_open_header(buselfs_state->backstore,
                                                   header_types_ordered[BLFS_HEAD_NUM_HEADERS - 1][0]);

    uint64_t headersize = last_header->data_offset + last_header->data_length;
    int64_t nuggetsize = cin_flake_size * cin_flakes_per_nugget;
    int64_t space_remaining = cin_backstore_size - headersize;
    int64_t num_nuggets_calculated_64 = 0;

    uint64_t total_space_req_for_one_nug = calculate_total_space_required_for_1nug(
        nuggetsize,
        cin_flakes_per_nugget,
        buselfs_state->backstore->md_bytes_per_nugget
    );

    IFDEBUG(dzlog_debug("headersize = %"PRIu64, headersize));
    IFDEBUG(dzlog_debug("nuggetsize = %"PRIu64, nuggetsize));
    IFDEBUG(dzlog_debug("total_space_req_for_one_nug = %"PRIu64, total_space_req_for_one_nug));
    IFDEBUG(dzlog_debug("space_remaining = %"PRId64, space_remaining));

    while(space_remaining > 0 && (unsigned) space_remaining > total_space_req_for_one_nug)
    {
        num_nuggets_calculated_64 += 1;

        // Subtract the space required for a nugget, a keycount, a TJ entry, and a metadata struct
        space_remaining -= total_space_req_for_one_nug;
    }

    IFDEBUG(dzlog_debug("num_nuggets_calculated_64 = %"PRId64, num_nuggets_calculated_64));
    IFDEBUG(dzlog_debug("space_remaining (final) = %"PRId64, space_remaining));

    if(num_nuggets_calculated_64 <= 0)
        Throw(EXCEPTION_BACKSTORE_SIZE_TOO_SMALL);

    // ! this is DEFINITELY endian-sensitive!!!
    uint32_t num_nuggets_calculated_32 = (uint32_t) num_nuggets_calculated_64;
    uint8_t * data_numnuggets = (uint8_t *) &num_nuggets_calculated_32;

    IFDEBUG(dzlog_debug("data_numnuggets (num_nuggets_calculated_32) = %"PRIu32, num_nuggets_calculated_32));
    IFDEBUG(dzlog_debug("data_numnuggets:"));
    IFDEBUG(hdzlog_debug(data_numnuggets, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET));

    memcpy(numnuggets_header->data, data_numnuggets, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET);

    // Do some intermediate number crunching
    blfs_backstore_setup_actual_post(buselfs_state->backstore);
    blfs_backstore_setup_actual_finish(buselfs_state->backstore);

    dzlog_notice("Prefetching data caches...");

    // Make sure keycounts, tj entries, and nugget metadata are cached (prefetched)
    for(uint32_t nugget_index = 0; nugget_index < num_nuggets_calculated_32; nugget_index++)
    {
        (void) blfs_create_keycount(buselfs_state->backstore, nugget_index);
        (void) blfs_create_tjournal_entry(buselfs_state->backstore, nugget_index);
        (void) blfs_create_nugget_metadata(buselfs_state->backstore, nugget_index);
    }

    dzlog_notice("Populating key cache...");

    populate_key_cache(buselfs_state);

    // Populate merkle tree with leaves, set header
    dzlog_notice("Populating merkle tree...");

    populate_mt(buselfs_state);

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

    buselfs_state->backstore = blfs_backstore_open_with_ctx(backstore_path, buselfs_state);
    blfs_soft_open(buselfs_state, cin_allow_insecure_start);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_run_mode_wipe(const char * backstore_path, uint8_t cin_allow_insecure_start, buselfs_state_t * buselfs_state)
{
    (void) backstore_path;
    (void) cin_allow_insecure_start;
    (void) buselfs_state;

    // TODO: implement this start mode
}

buselfs_state_t * strongbox_main_actual(int argc, char * argv[], char * blockdevice)
{
    IFDEBUG3(printf("<bare debug>: >>>> entering %s\n", __func__));

    char * cin_device_name;
    char backstore_path[BLFS_BACKSTORE_FILENAME_MAXLEN] = { 0x00 };

    // ! Not free()'d!
    buselfs_state_t * buselfs_state = malloc(sizeof *buselfs_state);

    if(buselfs_state == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    buselfs_state->backstore = NULL;

    uint8_t  cin_allow_insecure_start       = FALSE;
    uint8_t  cin_use_default_password       = FALSE;
    swappable_cipher_e cin_cipher              = sc_default;
    uint8_t  cin_backstore_mode             = BLFS_BACKSTORE_CREATE_MODE_UNKNOWN;
    uint64_t cin_backstore_size             = BLFS_DEFAULT_BYTES_BACKSTORE * BYTES_IN_A_MB;
    uint32_t cin_flake_size                 = BLFS_DEFAULT_BYTES_FLAKE;
    uint32_t cin_flakes_per_nugget          = BLFS_DEFAULT_FLAKES_PER_NUGGET;

    IFDEBUG3(printf("<bare debug>: argc: %i\n", argc));

    if(argc <= 1 || argc > MAX_NUM_ARGC)
    {
        printf(
        "\nUsage:\n"
        "  %s [--default-password][--backstore-size %"PRIu32"][--flake-size %"PRIu32"][--flakes-per-nugget %"PRIu32"][--cipher sc_default][--swap-cipher sc_default][--swap-strategy swap_default][--support-uc uc_default][--tpm-id %"PRIu32"] create nbd_device_name\n\n"
        "  %s [--default-password][--allow-insecure-start] open nbd_device_name\n\n"
        "  %s [--default-password][--allow-insecure-start] wipe nbd_device_name\n\n"

        "Defaults are shown above. See README.md or constants.h for more details. Also note: nbd_device must always\n"
        "appear last and the desired command (open, wipe, etc) second to last.\n\n"

        "::create command::\n"
        "This command will create and load a brand new StrongBox backstore. Note that this command will force overwrite a\n"
        " previous backstore made with the same nbd device name if it already exists.\n\n"
        "Example: %s --backstore-size 4096 create nbd4\n\n"
        ":options:\n"
        "- default-password  instead of asking you for a password, the password '"BLFS_DEFAULT_PASS"' will be used.\n"
        "- backstore-size    size of the backstore; must be in MEGABYTES.\n"
        "- flake-size        size of each individual flake; must be in BYTES\n"
        "- flakes-per-nugget number of flakes per nugget\n"
        "- cipher            chosen cipher for crypt (see README for choices here)\n"
        "- swap-cipher       chosen cipher for use with swap strategies (same choices as cipher)\n"
        "- swap-strategy     chosen swap strategy (see README for choices here)\n"
        "- support-uc        chosen cipher for crypt (see README for choices here)\n"
        "- tpm-id            internal index used by RPMB module\n\n"

        "::open command::\n"
        "This command will open and load a preexisting StrongBox backstore or fail if it does not exist.\n\n"
        "Example: %s --allow-insecure-start open nbd4\n\n"
        ":options:\n"
        "- default-password  instead of asking you for a password, the password '"BLFS_DEFAULT_PASS"' will be used.\n"
        "- allow-insecure-start ignores a MTRH failure (integrity issue) and loads the StrongBox backstore anyway\n\n"

        "::wipe command::\n"
        "Will reset an already existing StrongBox backstore to its initial state, as if it were newly created. It will not\n"
        " be automatically loaded and must be subsequently opened via the open command. Note that this command only works\n"
        " if the backstore in question is indeed a valid StrongBox backstore.\n\n"
        "Example: %s wipe nbd4\n\n"
        ":options:\n"
        "- default-password  instead of asking you for a password, the password '"BLFS_DEFAULT_PASS"' will be used.\n"
        "- allow-insecure-start ignores a MTRH failure (integrity issue) and loads the StrongBox backstore anyway\n\n"

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

            cin_cipher = blfs_ident_string_to_cipher(cin_cipher_str);

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

    if(cin_flake_size > BLFS_HEAD_MAX_FLAKESIZE_BYTES)
        Throw(EXCEPTION_FLAKESIZE_TOO_LARGE);

    if(cin_flake_size < BLFS_HEAD_MIN_FLAKESIZE_BYTES)
        Throw(EXCEPTION_FLAKESIZE_TOO_SMALL);

    if(cin_flakes_per_nugget > BLFS_HEAD_MAX_FLAKESPERNUGGET)
        Throw(EXCEPTION_TOO_MANY_FLAKES_PER_NUGGET);

    if(cin_flakes_per_nugget < BLFS_HEAD_MIN_FLAKESPERNUGGET)
        Throw(EXCEPTION_TOO_FEW_FLAKES_PER_NUGGET);

    /* Cipher selection and initialization */
    buselfs_state->active_cipher = malloc(sizeof *buselfs_state->active_cipher);

    sc_set_cipher_ctx(buselfs_state->active_cipher, cin_cipher);
    sc_calculate_cipher_bytes_per_nugget(
        buselfs_state->active_cipher,
        cin_flakes_per_nugget,
        cin_flake_size,
        buselfs_state->active_cipher->output_size_bytes
    );

    /* Prepare to setup the backstore file */

    sprintf(backstore_path, BLFS_BACKSTORE_FILENAME, cin_device_name);
    IFDEBUG3(printf("<bare debug>: backstore_path = %s\n", backstore_path));

    IFDEBUG3(printf("<bare debug>: continuing pre-initialization step...\n"));

    /* Initialize libsodium */

    if(sodium_init() == -1)
        Throw(EXCEPTION_SODIUM_INIT_FAILURE);

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

    IFDEBUG(assert(crypto_stream_chacha20_KEYBYTES == BLFS_CRYPTO_BYTES_CHACHA20_KEY));
    IFDEBUG(assert(crypto_stream_chacha20_NONCEBYTES == BLFS_CRYPTO_BYTES_CHACHA20_NONCE));
    IFDEBUG(assert(crypto_box_SEEDBYTES == BLFS_CRYPTO_BYTES_KDF_OUT));
    IFDEBUG(assert(crypto_pwhash_SALTBYTES == BLFS_CRYPTO_BYTES_KDF_SALT));
    IFDEBUG(assert(crypto_onetimeauth_poly1305_BYTES == BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT));
    IFDEBUG(assert(crypto_onetimeauth_poly1305_KEYBYTES == BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY));
    IFDEBUG(assert(HASH_LENGTH == BLFS_CRYPTO_BYTES_MTRH));

    IFDEBUG(dzlog_debug("cin_flakes_per_nugget >? BLFS_CRYPTO_BYTES_MTRH: (%"PRIu32" >? %"PRIu32")",
                        cin_flakes_per_nugget, BLFS_CRYPTO_BYTES_MTRH * BITS_IN_A_BYTE));

    if(cin_flakes_per_nugget > BLFS_CRYPTO_BYTES_MTRH * BITS_IN_A_BYTE)
    {
        IFDEBUG(dzlog_debug("EXCEPTION: too many flakes per nugget! (%"PRIu32">%"PRIu32")",
                            cin_flakes_per_nugget,
                            BLFS_CRYPTO_BYTES_MTRH * BITS_IN_A_BYTE
        ));

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

    IFDEBUG(dzlog_info(">> StrongBox backend was setup successfully! <<"));

    sprintf(blockdevice, BLFS_BACKSTORE_DEVICEPATH, cin_device_name);
    IFDEBUG(dzlog_debug("RETURN: blockdevice = %s", blockdevice));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));

    return buselfs_state;
}

int strongbox_main(int argc, char * argv[])
{
    char blockdevice[BLFS_BACKSTORE_FILENAME_MAXLEN] = { 0x00 };
    buselfs_state_t * buselfs_state;

    IFDEBUG(dzlog_debug("<< configuring global buselfs_state >>"));

    buselfs_state = strongbox_main_actual(argc, argv, blockdevice);

    IFDEBUG(dzlog_debug("<<<< handing control over to buse_main >>>>"));

    dzlog_notice("StrongBox is ready!\n");

    return buse_main(blockdevice, &buseops, (void *) buselfs_state);
}
