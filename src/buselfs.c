/*
 * Backend virtual block device for any LFS using BUSE
 *
 * @author Bernard Dickens
 */

#include "buselfs.h"
#include "bitmask.h"
#include "crypto.h"
#include "interact.h"
#include "buse.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>

/**
 * Unimplemented BUSE internal function.
 */
static void buse_disc(void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) userdata;

    IFDEBUG(dzlog_info("Received a disconnect request (not implemented).\n"));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

/**
 * Unimplemented BUSE internal function.
 */
static int buse_flush(void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) userdata;

    IFDEBUG(dzlog_info("Received a flush request (not implemented).\n"));

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

    IFDEBUG(dzlog_info("Received a trim request (not implemented)\n"));

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

    blfs_header_t * mtrh_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_MTRH);
    memcpy(mtrh_header->data, buselfs_state->merkle_tree_root_hash, BLFS_HEAD_HEADER_BYTES_MTRH);

    IFDEBUG(dzlog_info("merkle tree root hash:"));
    IFDEBUG(mt_print_hash(buselfs_state->merkle_tree_root_hash));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
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

    if(mt_add(buselfs_state->merkle_tree, data, length) != MT_SUCCESS)
        Throw(EXCEPTION_MERKLE_TREE_ADD_FAILURE);

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

    if(mt_update(buselfs_state->merkle_tree, data, length, index) != MT_SUCCESS)
        Throw(EXCEPTION_MERKLE_TREE_UPDATE_FAILURE);

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

    if(mt_verify(buselfs_state->merkle_tree, data, length, index) != MT_SUCCESS)
        Throw(EXCEPTION_MERKLE_TREE_VERIFY_FAILURE);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void add_index_to_key_cache(buselfs_state_t * buselfs_state, uint32_t nugget_index, uint8_t * nugget_key)
{
    if(!BLFS_DEFAULT_DISABLE_KEY_CACHING)
    {
        char kh_nugget_key[BLFS_KHASH_NUGGET_KEY_SIZE_BYTES] = { 0x00 };

        sprintf(kh_nugget_key, "%"PRIu32, nugget_index);
        IFDEBUG(dzlog_debug("CACHE: adding KHASH nugget index key %s to cache...", kh_nugget_key));

        KHASH_CACHE_PUT_HEAP(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, kh_nugget_key, nugget_key);
    }
}

void add_keychain_to_key_cache(buselfs_state_t * buselfs_state,
                                      uint32_t nugget_index,
                                      uint32_t flake_index,
                                      uint64_t keycount,
                                      uint8_t * flake_key)
{
    if(!BLFS_DEFAULT_DISABLE_KEY_CACHING)
    {
        char kh_flake_key[BLFS_KHASH_NUGGET_KEY_SIZE_BYTES] = { 0x00 };

        sprintf(kh_flake_key, "%"PRIu32"||%"PRIu32"||"PRIu64, nugget_index, flake_index, keycount);
        IFDEBUG(dzlog_debug("CACHE: adding KHASH flake keychain key %s to cache...", kh_flake_key));

        KHASH_CACHE_PUT_HEAP(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, kh_flake_key, flake_key);
    }
}

void get_nugget_key_using_index(uint8_t * nugget_key, buselfs_state_t * buselfs_state, uint32_t nugget_index)
{
    char kh_nugget_key[BLFS_KHASH_NUGGET_KEY_SIZE_BYTES] = { 0x00 };
    uint8_t * ng;

    sprintf(kh_nugget_key, "%"PRIu32, nugget_index);
    IFDEBUG(dzlog_debug("CACHE: grabbing KHASH flake keychain key %s from cache...", kh_nugget_key));

    ng = KHASH_CACHE_GET_WITH_KEY(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, kh_nugget_key);
    memcpy(nugget_key, ng, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY);
}

void get_flake_key_using_keychain(uint8_t * flake_key,
                                        buselfs_state_t * buselfs_state,
                                        uint32_t nugget_index,
                                        uint32_t flake_index,
                                        uint64_t keycount)
{
    char kh_flake_key[BLFS_KHASH_NUGGET_KEY_SIZE_BYTES] = { 0x00 };
    uint8_t * fk;

    sprintf(kh_flake_key, "%"PRIu32"||%"PRIu32"||"PRIu64, nugget_index, flake_index, keycount);
    IFDEBUG(dzlog_debug("CACHE: grabbing KHASH flake keychain key %s from cache...", kh_flake_key));

    fk = KHASH_CACHE_GET_WITH_KEY(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, kh_flake_key);
    memcpy(flake_key, fk, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY);
}

int buse_read(void * buffer, uint32_t len, uint64_t offset, void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    buselfs_state_t * buselfs_state = (buselfs_state_t *) userdata;

    (void) buffer;
    (void) len;
    (void) offset;
    (void) buselfs_state;

    // FIXME: Handle reads and deal with caching

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return 0;
}

int buse_write(const void * buffer, uint32_t len, uint64_t offset, void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    buselfs_state_t * buselfs_state = (buselfs_state_t *) userdata;

    (void) buffer;
    (void) len;
    (void) offset;
    (void) buselfs_state;

    if(buselfs_state->journaling_is_enabled)
    {
        // FIXME: Handle journaling
    }

    // FIXME: Handle writes and deal with caching

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return 0;
}

void blfs_rekey_nugget_journaled(buselfs_state_t * buselfs_state, uint32_t rekeying_nugget_id)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    IFDEBUG(dzlog_debug("beginning rekeying process..."));

    (void) buselfs_state;
    (void) rekeying_nugget_id;

    // FIXME: implement me! Re-encrypts a nugget with an entirely different key and updates the cache accordingly.
    // Do updates in the merkle tree. Deletes in the cache MUST take into account the strduping!

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_soft_open(buselfs_state_t * buselfs_state, uint8_t cin_allow_insecure_start)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    int rekeying = FALSE;
    char passwd[1025] = { 0x00 };

    interact_prompt_user("Enter your password: ", passwd, 1025);

    IFDEBUG(dzlog_debug("passwd = %s", passwd));

    // Are we initialized?
    blfs_header_t * init_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_INITIALIZED);
    
    if(init_header->data[0] != BLFS_HEAD_IS_INITIALIZED_VALUE)
        Throw(EXCEPTION_BACKSTORE_NOT_INITIALIZED);

    // Get salt
    blfs_header_t * salt_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_SALT);

    // Derive master secret, cache it
    blfs_password_to_secret(buselfs_state->backstore->master_secret, passwd, strlen(passwd), salt_header->data);
    IFDEBUG(dzlog_debug("buselfs_state->backstore->master_secret:"));
    IFDEBUG(hdzlog_debug(buselfs_state->backstore->master_secret, BLFS_CRYPTO_BYTES_KDF_OUT));
    
    // Verify global header
    blfs_header_t * tpmv_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
    IFDEBUG(dzlog_debug("tpmv_header->data: %"PRIu64, *(uint64_t *) tpmv_header->data));
    blfs_globalversion_verify(BLFS_TPM_ID, *(uint64_t *) tpmv_header->data);
    
    // Use chacha20 with master secret to check verification header
    blfs_header_t * verf_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);
    uint8_t verify_pwd[BLFS_HEAD_HEADER_BYTES_VERIFICATION];

    blfs_chacha20_128(verify_pwd, buselfs_state->backstore->master_secret);

    IFDEBUG(dzlog_debug("verf_header->data:"));
    IFDEBUG(hdzlog_debug(verf_header->data, BLFS_HEAD_HEADER_BYTES_VERIFICATION));
    IFDEBUG(dzlog_debug("verify_pwd (should match above):"));
    IFDEBUG(hdzlog_debug(verf_header->data, BLFS_HEAD_HEADER_BYTES_VERIFICATION));

    if(memcmp(verf_header->data, verify_pwd, BLFS_HEAD_HEADER_BYTES_VERIFICATION) != 0)
        Throw(EXCEPTION_BAD_PASSWORD);

    // Get the numnuggets, flakesize, and fpn headers (XXX: this is DEFINITELY endian-sensitive!!!)
    blfs_header_t * numnuggets_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_NUMNUGGETS);
    blfs_header_t * flakesize_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES);
    blfs_header_t * fpn_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET);

    uint32_t flakesize = *(uint32_t *) flakesize_header->data;
    uint32_t flakespnug = *(uint32_t *) fpn_header->data;
    uint32_t numnuggets = *(uint32_t *) numnuggets_header->data;

    IFDEBUG(dzlog_debug("flakesize = %"PRIu32, flakesize));
    IFDEBUG(dzlog_debug("flakespnug = %"PRIu32, flakespnug));
    IFDEBUG(dzlog_debug("numnuggets = %"PRIu32, numnuggets));

    // Do we need to rekey?
    blfs_header_t * rekeying_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_REKEYING);
    uint8_t zero_rekeying[BLFS_HEAD_HEADER_BYTES_REKEYING] = { 0x00 };

    if(memcmp(rekeying_header->data, zero_rekeying, BLFS_HEAD_HEADER_BYTES_REKEYING) != 0)
    {
        IFDEBUG(dzlog_debug("rekeying header nugget id detected!"));
        rekeying = TRUE;
    }

    // Populate key cache (XXX: IRL, this might not be done on init/mount)
    IFDEBUG(dzlog_debug("populating key cache..."));

    // First with nugget keys:
    // nugget_index => (nugget_key = master_secret+nugget_index)
    for(uint32_t nugget_index = 0; nugget_index < numnuggets; nugget_index++)
    {
        char kh_nugget_key[BLFS_KHASH_NUGGET_KEY_SIZE_BYTES] = { 0x00 };
        uint8_t * nugget_key = malloc(sizeof(*nugget_key) * BLFS_CRYPTO_BYTES_KDF_OUT);

        blfs_keycount_t * count = blfs_open_keycount(backstore, nugget_index);

        if(nugget_key == NULL)
            Throw(EXCEPTION_ALLOC_FAILURE);

        blfs_nugget_key_from_data(nugget_key, buselfs_state->backstore->master_secret, nugget_index);
        add_index_to_key_cache(buselfs_state, nugget_index, nugget_key);

        // Now with nugget keys:
        // nugget_index||associated_keycount||flake_id => master_secret+nugget_index+flake_id+associated_keycount
        for(uint32_t flake_index = 0; flake_index < flakespnug; flake_index++)
        {
            char kh_flake_key[BLFS_KHASH_NUGGET_KEY_SIZE_BYTES] = { 0x00 };
            uint8_t * flake_key = malloc(sizeof(*flake_key) * BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY);

            if(flake_key == NULL)
                Throw(EXCEPTION_ALLOC_FAILURE);

            blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, count->keycount);
            add_keychain_to_key_cache(buselfs_state, nugget_index, flake_index, count->keycount, flake_key);
        }
    }

    // Populate merkle tree with leaves, set header
    IFDEBUG(dzlog_debug("MERKLE TREE: adding TPMGV counter..."));

    // First element in the merkle tree should be the TPM version counter
    add_to_merkle_tree(tpmv_header->data, tpmv_header->data_length, buselfs_state);

    // Next, the headers (excluding TPMGV, INITIALIZED and MTRH)
    IFDEBUG(dzlog_debug("MERKLE TREE: adding headers..."));
    for(size_t i = 0; i < BLFS_HEAD_NUM_HEADERS; ++i)
    {
        uint32_t const_header_type = header_types_ordered[i][0];

        if(const_header_type == BLFS_HEAD_HEADER_TYPE_MTRH ||
           const_header_type == BLFS_HEAD_HEADER_TYPE_INITIALIZED ||
           const_header_type == BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER)
        {
            continue;
        }

        blfs_header_t * header = blfs_open_header(buselfs_state->backstore, const_header_type);
        add_to_merkle_tree(header->data, header->data_length, buselfs_state);
    }

    // Next, the keycounts
    IFDEBUG(dzlog_debug("MERKLE TREE: adding keycounts..."));

    // FIXME: substitute rekey kcs in merkle tree for verification
    for(uint32_t nugget_index = 0; nugget_index < numnuggets; nugget_index++)
    {
        blfs_keycount_t * count = blfs_open_keycount(backstore, nugget_index);
        add_to_merkle_tree((uint8_t *) &count->keycount, BLFS_HEAD_BYTES_KEYCOUNT, buselfs_state);
    }
    
    // Next, the TJ entries
    IFDEBUG(dzlog_debug("MERKLE TREE: adding transaction journal entries..."));
    // FIXME: substitute rekey tj in merkle tree for verification
    for(uint32_t nugget_index = 0; nugget_index < numnuggets; nugget_index++)
    {
        blfs_tjournal_entry_t * entry = blfs_open_tjournal_entry(backstore, nugget_index);
        add_to_merkle_tree(entry->bitmask->mask, entry->bitmask->byte_length, buselfs_state);
    }
    
    // Finally, the flake tags
    IFDEBUG(dzlog_debug("MERKLE TREE: adding flake tags..."));

    // FIXME: substitute rekey flakes in merkle tree for verification
    for(uint32_t nugget_index = 0; nugget_index < numnuggets; nugget_index++)
    {
        uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };
        blfs_keycount_t * count = blfs_open_keycount(backstore, nugget_index);

        if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
            blfs_nugget_key_from_data(nugget_key, buselfs_state->backstore->master_secret, nugget_index);

        for(uint32_t flake_index = 0; flake_index < flakespnug; flake_index++)
        {
            uint8_t flake_key[BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT] = { 0x00 };
            uint8_t * tag = malloc(sizeof(*tag) * BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT);

            if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
                blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, count->keycount);
            else
                get_flake_key_using_keychain(flake_key, buselfs_state, nugget_index, flake_index, count->keycount);

            uint8_t * flake_data = malloc(flakesize * sizeof(*flake_data));

            if(flake_data == NULL)
                Throw(EXCEPTION_ALLOC_FAILURE);

            blfs_backstore_read_body(backstore, flake_data, flakesize, flake_index * flakesize);
            blfs_poly1305_generate_tag(tag, flake_data, flakesize, flake_key);
            add_to_merkle_tree(tag, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT, buselfs_state);
        }
    }

    // Update the global MTRH
    update_merkle_tree_root_hash(buselfs_state);

    IFDEBUG(dzlog_debug("MERKLE TREE: comparing MTRH to header"));

    blfs_header_t * mtrh_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_MTRH);

    IFDEBUG(dzlog_debug("mtrh_header->data:"));
    IFDEBUG(hdzlog_debug(mtrh_header->data, BLFS_HEAD_HEADER_BYTES_MTRH));
    IFDEBUG(dzlog_debug("computed MTRH:"));
    IFDEBUG(hdzlog_debug(buselfs_state->merkle_tree_root_hash, BLFS_HEAD_HEADER_BYTES_MTRH));

    if(memcmp(mtrh_header->data, buselfs_state->merkle_tree_root_hash, BLFS_HEAD_HEADER_BYTES_MTRH) != 0)
    {
        dzlog_fatal("!!!!!!! WARNING: BLOCK DEVICE BACKSTORE INTEGRITY CHECK FAILED !!!!!!!");

        if(cin_allow_insecure_start)
            dzlog_warn("allow-insecure-start flag detected. Forcing start anyway...");

        else
            Throw(EXCEPTION_INTEGRITY_FAILURE);
    }

    // Finish up
    blfs_backstore_setup_actual_post(buselfs_state->backstore);

    if(rekeying)
        blfs_rekey_nugget_journaled(buselfs_state, *(uint32_t *) rekeying_header->data);

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

    char passwd[1025] = { 0x00 };
    char passck[1025] = { 0x00 };

    interact_prompt_user("Enter your desired password (max 1024): ", passwd, 1025);
    interact_prompt_user("Confirm your password: ", passck, 1025);

    IFDEBUG(dzlog_debug("passwd = %s", passwd));
    IFDEBUG(dzlog_debug("passck = %s", passck));

    if(strcmp(passwd, passck) != 0)
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

    // Use chacha20 with master secret to get verification header, set header
    blfs_header_t * verf_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);
    blfs_chacha20_128(verf_header->data, buselfs_state->backstore->master_secret);

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
    IFDEBUG(dzlog_debug("space_remaining = %"PRId64, space_remaining));
    IFDEBUG(dzlog_debug("space_for_nug_kc_tje = %"PRIu64, space_for_nug_kc_tje));

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

    // Populate key cache (XXX: IRL, this might not be done on init/mount)
    IFDEBUG(dzlog_debug("populating key cache..."));

    // First with nugget keys:
    // nugget_index => (nugget_key = master_secret+nugget_index)
    for(uint32_t nugget_index = 0; nugget_index < num_nuggets_calculated_32; nugget_index++)
    {
        uint8_t * nugget_key = malloc(sizeof(*nugget_key) * BLFS_CRYPTO_BYTES_KDF_OUT);

        if(nugget_key == NULL)
            Throw(EXCEPTION_ALLOC_FAILURE);

        blfs_nugget_key_from_data(nugget_key, buselfs_state->backstore->master_secret, nugget_index);
        add_index_to_key_cache(buselfs_state, nugget_index, nugget_key);

        // Now with nugget keys:
        // nugget_index||associated_keycount||flake_id => master_secret+nugget_index+flake_id+associated_keycount
        for(uint32_t flake_index = 0; flake_index < cin_flakes_per_nugget; flake_index++)
        {
            uint8_t * flake_key = malloc(sizeof(*flake_key) * BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY);

            if(flake_key == NULL)
                Throw(EXCEPTION_ALLOC_FAILURE);

            // Initially, keycount is always 0
            blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, 0);
            add_keychain_to_key_cache(buselfs_state, nugget_index, flake_index, 0, flake_key);
        }
    }

    // Populate merkle tree with leaves, set header
    IFDEBUG(dzlog_debug("MERKLE TREE: adding TPMGV counter..."));

    // First element in the merkle tree should be the TPM version counter
    add_to_merkle_tree(tpmv_header->data, tpmv_header->data_length, buselfs_state);

    IFDEBUG(dzlog_debug("MERKLE TREE: adding other headers..."));

    // Next, the headers (excluding TPMGV, INITIALIZED and MTRH)
    for(size_t i = 0; i < BLFS_HEAD_NUM_HEADERS; ++i)
    {
        uint32_t const_header_type = header_types_ordered[i][0];

        if(const_header_type == BLFS_HEAD_HEADER_TYPE_MTRH ||
           const_header_type == BLFS_HEAD_HEADER_TYPE_INITIALIZED ||
           const_header_type == BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER)
        {
            continue;
        }

        blfs_header_t * header = blfs_open_header(buselfs_state->backstore, const_header_type);
        add_to_merkle_tree(header->data, header->data_length, buselfs_state);
    }

    // Next, the keycounts
    uint64_t a_zero = 0;
    IFDEBUG(dzlog_debug("MERKLE TREE: adding keycounts..."));

    for(uint32_t nugget_index = 0; nugget_index < num_nuggets_calculated_32; nugget_index++)
        add_to_merkle_tree((uint8_t *) &a_zero, BLFS_HEAD_BYTES_KEYCOUNT, buselfs_state);
    
    // Next, the TJ entries
    bitmask_t * zero_mask = bitmask_init(NULL, cin_flakes_per_nugget);
    IFDEBUG(dzlog_debug("MERKLE TREE: adding transaction journal entries..."));

    for(uint32_t nugget_index = 0; nugget_index < num_nuggets_calculated_32; nugget_index++)
        add_to_merkle_tree(zero_mask->mask, zero_mask->byte_length, buselfs_state);
    
    // Finally, the flake tags
    uint8_t * zeroed_flake = calloc(cin_flake_size, sizeof(*zeroed_flake));
    IFDEBUG(dzlog_debug("MERKLE TREE: adding flake tags..."));

    if(zeroed_flake == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    for(uint32_t nugget_index = 0; nugget_index < num_nuggets_calculated_32; nugget_index++)
    {
        uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };

        if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
            blfs_nugget_key_from_data(nugget_key, buselfs_state->backstore->master_secret, nugget_index);

        for(uint32_t flake_index = 0; flake_index < cin_flakes_per_nugget; flake_index++)
        {
            uint8_t flake_key[BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT] = { 0x00 };
            uint8_t * tag = malloc(sizeof(*tag) * BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT);

            if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
                blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, 0);
            else
                get_flake_key_using_keychain(flake_key, buselfs_state, nugget_index, flake_index, 0);

            blfs_poly1305_generate_tag(tag, zeroed_flake, cin_flake_size, flake_key);
            add_to_merkle_tree(tag, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT, buselfs_state);
        }
    }

    // Update the global MTRH
    update_merkle_tree_root_hash(buselfs_state);

    // Set initialization header to initialized and commit header
    init_header->data[0] = BLFS_HEAD_IS_INITIALIZED_VALUE;

    // Commit all headers
    blfs_commit_all_headers(buselfs_state->backstore);
    blfs_globalversion_commit(BLFS_TPM_ID, *(uint64_t *) tpmv_header->data);

    // Finish up
    blfs_backstore_setup_actual_post(buselfs_state->backstore);

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

void blfs_run_mode_wipe(const char * backstore_path, uint8_t cin_allow_insecure_start, buselfs_state_t * buselfs_state)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));
    IFDEBUG(dzlog_debug("running in WIPE mode!"));

    buselfs_state->backstore = blfs_backstore_open(backstore_path);
    blfs_soft_open(buselfs_state, cin_allow_insecure_start);

    // FIXME: wipe

    IFDEBUG(dzlog_debug("EXITING PROGRAM!"));
    exit(BLFS_EXIT_STATUS_WIPED_SUCCESS);
}

buselfs_state_t * buselfs_main_actual(int argc, char * argv[], char * blockdevice)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    char * cin_device_name;
    char backstore_path[BLFS_BACKSTORE_FILENAME_MAXLEN] = { 0x00 };

    // XXX: Not free'd!
    buselfs_state_t * buselfs_state = malloc(sizeof(*buselfs_state));

    if(buselfs_state == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    buselfs_state->journaling_is_enabled = FALSE;
    buselfs_state->backstore = NULL;

    uint8_t  cin_allow_insecure_start       = FALSE;
    uint8_t  cin_journaling_enabled         = FALSE;
    uint8_t  cin_backstore_mode             = BLFS_BACKSTORE_CREATE_MODE_UNKNOWN;
    uint64_t cin_backstore_size             = BLFS_DEFAULT_BYTES_BACKSTORE;
    uint32_t cin_flake_size                 = BLFS_DEFAULT_BYTES_FLAKE;
    uint32_t cin_flakes_per_nugget          = BLFS_DEFAULT_FLAKES_PER_NUGGET;

    IFDEBUG(dzlog_debug("argc: %i", argc));

    if(argc <= 1 || argc > 7)
    {
        fprintf(stderr,
        "\nUsage:\n"
        "  %s [--enable-journaling][--backstore-size %"PRIu64"][--flake-size %"PRIu32"][--flakes-per-nugget %"PRIu32"]"
        " create nbd_device_name\n\n"
        "  %s [--enable-journaling][--allow-insecure-start] open nbd_device_name\n\n"
        "  %s wipe nbd_device_name\n\n"

        "Note: nbd_device must always appear last and the desired command (open, wipe, etc) second to last.\n\n"

        "::create command::\n"
        "This command will create and load a brand new buselfs backstore. Note that this command will force overwrite a\n"
        " previous backstore made with the same nbd device name if it already exists.\n\n"
        "Example: %s --backstore-size 4096 create nbd4\n\n"
        ":options:\n"
        "- backstore-size    size of the backstore; must be in MEGABYTES.\n"
        "- flake-size        size of each individual flake; must be in BYTES\n"
        "- flakes-per-nugget number of flakes per nugget\n\n"
        "Defaults are shown above. \n\n"
        
        "::open command::\n"
        "This command will open and load a preexisting buselfs backstore or fail if it does not exist.\n\n"
        "Example: %s --allow-insecure-start open nbd4\n\n"
        ":options:\n"
        "- allow-insecure-start ignores a MTRH failure (integrity issue) and loads the buselfs backstore anyway\n\n"

        "::wipe command::\n"
        "Will reset an already existing buselfs backstore to its initial state, as if it were newly created. It will not\n"
        " be automatically loaded and must be subsequently opened via the open command. Note that this command only works\n"
        " if the backstore in question is indeed a valid buselfs backstore.\n\n"
        "Example: %s wipe nbd4\n\n"
        ":options:\n"
        "(none)\n\n"

        "To test for correctness, run `make pre && make check` from the /build directory. Check the README for more details.\n"
        "Don't forget to load nbd kernel module `modprobe nbd` and run as root!\n\n",
        argv[0], BLFS_DEFAULT_BYTES_BACKSTORE, BLFS_DEFAULT_BYTES_FLAKE, BLFS_DEFAULT_FLAKES_PER_NUGGET,
        argv[0], argv[0], argv[0], argv[0], argv[0]);

        exit(BLFS_EXIT_STATUS_HELP_TEXT);
    }

    /* Process arguments */

    cin_device_name = argv[--argc];

    if(strcmp(argv[--argc], "create") == 0)
        cin_backstore_mode = BLFS_BACKSTORE_CREATE_MODE_CREATE;

    else if(strcmp(argv[argc], "open") == 0)
        cin_backstore_mode = BLFS_BACKSTORE_CREATE_MODE_OPEN;

    else if(strcmp(argv[argc], "wipe") == 0)
        cin_backstore_mode = BLFS_BACKSTORE_CREATE_MODE_WIPE;

    else Throw(EXCEPTION_UNKNOWN_MODE);

    IFDEBUG(dzlog_debug("cin_backstore_mode: %i", cin_backstore_mode));

    while(argc-- > 1)
    {
        if(strcmp(argv[argc], "--backstore-size") == 0)
        {
            cin_backstore_size = strtoll(argv[argc + 1], NULL, 0);
            IFDEBUG(dzlog_debug("saw --backstore-size, got value: %"PRIu64, cin_backstore_size));
        }

        else if(strcmp(argv[argc], "--flake-size") == 0)
        {
            cin_flake_size = strtoll(argv[argc + 1], NULL, 0);
            IFDEBUG(dzlog_debug("saw --flake-size = %"PRIu32, cin_flake_size));
        }

        else if(strcmp(argv[argc], "--flakes-per-nugget") == 0)
        {
            cin_flakes_per_nugget = strtoll(argv[argc + 1], NULL, 0);
            IFDEBUG(dzlog_debug("saw --flakes-per-nugget = %"PRIu32, cin_flakes_per_nugget));
        }

        else if(strcmp(argv[argc], "--allow-insecure-start") == 0)
        {
            cin_allow_insecure_start = TRUE;
            IFDEBUG(dzlog_debug("saw --allow-insecure-start = %i", cin_allow_insecure_start));
        }

        else if(strcmp(argv[argc], "--enable-journaling") == 0)
        {
            cin_journaling_enabled = TRUE;
            IFDEBUG(dzlog_debug("saw --enable-journaling = %i", cin_journaling_enabled));
        }
    }

    IFDEBUG(dzlog_debug("argument processing result:"));
    IFDEBUG(dzlog_debug("cin_allow_insecure_start = %i", cin_allow_insecure_start));
    IFDEBUG(dzlog_debug("cin_backstore_size = %"PRIu64, cin_backstore_size));
    IFDEBUG(dzlog_debug("cin_flake_size = %"PRIu32, cin_flake_size));
    IFDEBUG(dzlog_debug("cin_flakes_per_nugget = %"PRIu32, cin_flakes_per_nugget));
    IFDEBUG(dzlog_debug("cin_backstore_mode = %i", cin_backstore_mode));

    IFDEBUG(dzlog_debug("defaults:"));
    IFDEBUG(dzlog_debug("default allow_insecure_start = 0"));
    IFDEBUG(dzlog_debug("default force_overwrite_backstore = 0"));
    IFDEBUG(dzlog_debug("default backstore_size = %"PRIu64, BLFS_DEFAULT_BYTES_BACKSTORE));
    IFDEBUG(dzlog_debug("default flake_size = %"PRIu32, BLFS_DEFAULT_BYTES_FLAKE));
    IFDEBUG(dzlog_debug("default flakes_per_nugget = %"PRIu32, BLFS_DEFAULT_FLAKES_PER_NUGGET));
    IFDEBUG(dzlog_debug("cin_backstore_mode = %i", BLFS_BACKSTORE_CREATE_MODE_UNKNOWN));

    if(errno == ERANGE || cin_backstore_mode > BLFS_BACKSTORE_CREATE_MAX_MODE_NUM)
        Throw(EXCEPTION_BAD_ARGUMENT_FORM);

    errno = 0;

    if(cin_backstore_size > UINT_MAX || cin_backstore_size <= 0)
        Throw(EXCEPTION_INVALID_BACKSTORESIZE);

    if(cin_flake_size > UINT_MAX || cin_flake_size <= 0)
        Throw(EXCEPTION_INVALID_FLAKESIZE);

    if(cin_flakes_per_nugget > UINT_MAX || cin_flakes_per_nugget <= 0)
        Throw(EXCEPTION_INVALID_FLAKES_PER_NUGGET);

    /* Prepare to setup the backstore file */

    sprintf(backstore_path, BLFS_BACKSTORE_FILENAME, cin_device_name);
    IFDEBUG(dzlog_debug("backstore_path = %s", backstore_path));

    /* Initialize libsodium */

    if(sodium_init() == -1)
        Throw(EXCEPTION_SODIUM_INIT_FAILURE);

    /* Initialize nugget key cache */

    if(!BLFS_DEFAULT_DISABLE_KEY_CACHING)
        buselfs_state->cache_nugget_keys = kh_init(BLFS_KHASH_NUGGET_KEY_CACHE_NAME);

    /* Initialize zlog */

    char buf[100] = { 0x00 };

    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), cin_device_name);
    IFDEBUG(dzlog_debug("BLFS_CONFIG_ZLOG = %s", BLFS_CONFIG_ZLOG));
    IFDEBUG(dzlog_debug("zlog buf = %s", buf));

    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        Throw(EXCEPTION_ZLOG_INIT_FAILURE);

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

    IFDEBUG(dzlog_debug("cin_flakes_per_nugget > BLFS_CRYPTO_BYTES_MTRH: (%"PRIu32" > %"PRIu32")",
                        cin_flakes_per_nugget, BLFS_CRYPTO_BYTES_MTRH * 8));

    if(cin_flakes_per_nugget > BLFS_CRYPTO_BYTES_MTRH * 8)
    {
        IFDEBUG(dzlog_debug("EXCEPTION: too many flakes per nugget! (%"PRIu32">%"PRIu32")",
                            cin_flakes_per_nugget, BLFS_CRYPTO_BYTES_MTRH * 8));

        Throw(EXCEPTION_TOO_MANY_FLAKES_PER_NUGGET);
    }

    /* Setup backstore file access */

    if(cin_backstore_mode == BLFS_BACKSTORE_CREATE_MODE_CREATE)
        blfs_run_mode_create(backstore_path, cin_backstore_size, cin_flake_size, cin_flakes_per_nugget, buselfs_state);

    else if(cin_backstore_mode == BLFS_BACKSTORE_CREATE_MODE_OPEN)
        blfs_run_mode_open(backstore_path, cin_allow_insecure_start, buselfs_state);

    else if(cin_backstore_mode == BLFS_BACKSTORE_CREATE_MODE_WIPE)
        blfs_run_mode_wipe(backstore_path, cin_allow_insecure_start, buselfs_state);

    /* Finish up startup procedures */

    IFDEBUG(dzlog_info("Defined: BLFS_DEBUG_LEVEL = %i", BLFS_DEBUG_LEVEL));

    IFDEBUG3(dzlog_debug("merkle tree debug print:\n\n\n"));
    IFDEBUG3(mt_print(buselfs_state->merkle_tree));
    IFDEBUG3(dzlog_debug("\n\n\n"));

    if(buselfs_state->backstore == NULL)
        Throw(EXCEPTION_BACKSTORE_NOT_INITIALIZED);

    buseops.size = buselfs_state->backstore->writeable_size_actual;
    buselfs_state->journaling_is_enabled = cin_journaling_enabled;

    IFDEBUG(dzlog_info("buseops.size = %"PRIu64, buseops.size));
    IFDEBUG(dzlog_info("buselfs_state->journaling_is_enabled = %s",
                       buselfs_state->journaling_is_enabled ? "TRUE" : "FALSE"));

    /* Let the show begin! */

    IFDEBUG(dzlog_info(">> buselfs backend was setup successfully! <<"));

    sprintf(blockdevice, BLFS_BACKSTORE_DEVICEPATH, cin_device_name);
    IFDEBUG(dzlog_debug("RETURN: blockdevice = %s", blockdevice));
    
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));

    return buselfs_state;
}

int buselfs_main(int argc, char * argv[])
{
    char blockdevice[BLFS_BACKSTORE_FILENAME_MAXLEN] = { 0x00 };
    buselfs_state_t * buselfs_state;

    buselfs_state = buselfs_main_actual(argc, argv, blockdevice);

    IFDEBUG(dzlog_debug("<<<< handing control over to buse_main >>>>"));

    return buse_main(blockdevice, &buseops, (void *) buselfs_state);
}
