#ifndef BLFS_BACKSTORE_H_
#define BLFS_BACKSTORE_H_

#include "constants.h"
#include "khash.h"
#include "bitmask.h"

//////////////////////////
// Static HEAD ordering //
//////////////////////////

// XXX: Be sure any updates result in changes to both header_types_ordered and
// header_types_named!

static const uint32_t header_types_ordered[BLFS_HEAD_NUM_HEADERS][2] = {
    { BLFS_HEAD_HEADER_TYPE_VERSION, BLFS_HEAD_HEADER_BYTES_VERSION },
    { BLFS_HEAD_HEADER_TYPE_SALT, BLFS_HEAD_HEADER_BYTES_SALT },
    { BLFS_HEAD_HEADER_TYPE_MTRH, BLFS_HEAD_HEADER_BYTES_MTRH },
    { BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER },
    { BLFS_HEAD_HEADER_TYPE_VERIFICATION, BLFS_HEAD_HEADER_BYTES_VERIFICATION },
    { BLFS_HEAD_HEADER_TYPE_NUMNUGGETS, BLFS_HEAD_HEADER_BYTES_NUMNUGGETS },
    { BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET },
    { BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES, BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES },
    { BLFS_HEAD_HEADER_TYPE_INITIALIZED, BLFS_HEAD_HEADER_BYTES_INITIALIZED },
    { BLFS_HEAD_HEADER_TYPE_REKEYING, BLFS_HEAD_HEADER_BYTES_REKEYING },
};

static const char * const header_types_named[BLFS_HEAD_NUM_HEADERS] = {
    "VERSION",
    "SALT",
    "MTRH",
    "TPMGLOBALVER",
    "VERIFICATION",
    "NUMNUGGETS",
    "FLAKESPERNUGGET",
    "FLAKESIZE_BYTES",
    "INITIALIZED",
    "REKEYING",
};

//////////////////////
// Typedefs/structs //
//////////////////////

/**
 * The HEAD region (as opposed to the BODY region) of the backstore consists of
 * several headers containing pertinent and often times constant data that is
 * of interest at various points during buselfs's execution.
 *
 * This struct represents a generic HEAD section header.
 *
 * @type            BLFS_HEAD_HEADER_TYPE_*
 * @name            @type as a string with common prefix removed
 * @data_offset     data offset in the backstore
 * @data_length     total length of the header data in bytes
 * @data            header value data (in bytes, not synced)
 */
typedef struct blfs_header_t
{
    uint32_t type;
    const char * name;

    uint64_t data_offset;
    uint64_t data_length;

    uint8_t * data;
} blfs_header_t;

/**
 * Keycount Store entries consist of 64-bit unsigned integer nonces (keycounts)
 * used per nugget to help encrypt that nugget's flakes with Chacha20. When the
 * nugget is rekeyed, what actually happens is that this nonce is incremented
 * and Chacha20 begins outputting bits from a different stream.
 *
 * The Keycount Store is also referred to as KCS.
 *
 * @nugget_index    the index of the nugget that this struct corresponds to
 * @data_offset     data offset in the backstore
 * @data_length     total length of the keycount data in bytes; always 8
 * @keycount        the keycount value in the keystore (not synced)
 */
typedef struct blfs_keycount_t
{
    uint32_t nugget_index;
    uint64_t data_offset;
    uint64_t data_length;

    uint64_t keycount;
} blfs_keycount_t;

/**
 * Transaction Journal entries consist of bitmasks (bitvectors) that correspond
 * to the status of flakes within corresponding nuggets. There is one bit per
 * flake, and one Transaction Journal (TJ) entry per nugget. A high bit
 * corresponds to a dirty flake, while a low bit corresponds to a clean one.
 *
 * @nugget_index    the index of the nugget that this struct corresponds to
 * @data_offset     data offset in the backstore
 * @data_length     total length of the journal entry in bytes; constant per run
 * @mask            bitmask data representing flake states (not synced)
 */
typedef struct blfs_tjournal_entry_t
{
    uint32_t nugget_index;
    uint64_t data_offset;
    uint64_t data_length;

    bitmask_t * bitmask;
} blfs_tjournal_entry_t;

///////////////////////////
// Cache initializations //
///////////////////////////

KHASH_MAP_INIT_INT64(BLFS_KHASH_HEADERS_CACHE_NAME, blfs_header_t*)

KHASH_MAP_INIT_INT64(BLFS_KHASH_KCS_CACHE_NAME, blfs_keycount_t*)

KHASH_MAP_INIT_INT64(BLFS_KHASH_TJ_CACHE_NAME, blfs_tjournal_entry_t*)

/**
 * This struct and its related functions (in io.h) abstract away a lot of the
 * underlying interactions and I/O between buselfs and the underlying filesystem
 * housing the backstore file container.
 *
 * Note that there is reserved space for a single journaled nugget, keycount,
 * and transaction journal. When rekeying happens in journaled mode, this is
 * where it gets written to. Otherwise, all data starts at the "real" offsets.
 *
 * @file_path               backstore file path including the filename
 * @file_name               backstore file name (limited to 16 characters)
 * @read_fd                 read-only descriptor pointing to backstore file
 * @write_fd                read-write descriptor pointing to backstore file
 * @kcs_real_offset         integer offset to where the keycount store begins
 * @tj_real_offset          integer offset to where the transaction journal begins
 * @body_real_offset        integer offset to where the data BODY (nuggets) begins
 * @kcs_journaled_offset    integer offset to where the journaled keycount goes
 * @tj_journaled_offset     integer offset to where the journaled TJ goes
 * @nugget_journaled_offset integer offset to where the single journaled nugget goes
 * @nugget_size_bytes       how big of a region a nugget represents
 * @writeable_size_actual   the actual number of writable bytes (real BODY size)
 * @master_secret           cached secret from KDF, size BLFS_CRYPTO_BYTES_KDF_OUT
 * @cache_headers           cached headers
 * @cache_kcs_counts        cached keycounts
 * @blfs_tjournal_entry_t   cached journal entries
 */
typedef struct blfs_backstore_t
{
    const char * file_path;
    const char * file_name;

    int io_fd;

    uint64_t kcs_real_offset;
    uint64_t tj_real_offset;
    uint64_t body_real_offset;

    uint64_t kcs_journaled_offset;
    uint64_t tj_journaled_offset;
    uint64_t nugget_journaled_offset;

    uint32_t nugget_size_bytes;
    uint32_t flake_size_bytes;
    uint64_t writeable_size_actual;
    uint64_t file_size_actual;

    uint32_t num_nuggets;
    uint32_t flakes_per_nugget;

    uint8_t master_secret[BLFS_CRYPTO_BYTES_KDF_OUT];

    khash_t(BLFS_KHASH_HEADERS_CACHE_NAME)  * cache_headers;
    khash_t(BLFS_KHASH_KCS_CACHE_NAME)      * cache_kcs_counts;
    khash_t(BLFS_KHASH_TJ_CACHE_NAME)       * cache_tj_entries;
} blfs_backstore_t;

/////////////////////////
// Function Prototypes //
/////////////////////////

/**
 * Creates the specified header from scratch and adds it to the cache. Throws
 * an error upon failure.
 *
 * @param  backstore
 * @param  header_type
 * @param  data
 *
 * @return            blfs_header_t
 */
blfs_header_t * blfs_create_header(blfs_backstore_t * backstore, uint32_t header_type, uint8_t * data);

/**
 * Reads in the specified header from the specified backstore. Throws an error
 * upon failure.
 *
 * @param backstore
 * @param header_type
 * @param header
 *
 * @return            blfs_header_t
 */
blfs_header_t * blfs_open_header(blfs_backstore_t * backstore, uint32_t header_type);

/**
 * Immediately writes the specified header to the specified backstore. Throws
 * an error upon failure.
 *
 * @param backstore
 * @param header
 */
void blfs_commit_header(blfs_backstore_t * backstore, const blfs_header_t * header);

/**
 * The specified header is free()'d. Be careful calling this. It should only be
 * with one-time-use headers or at the end of the program.
 *
 * @param backstore
 * @param header
 */
void blfs_close_header(blfs_backstore_t * backstore, blfs_header_t * header);

/**
 * Same as blfs_commit_header except applied to every registered header in
 * the backstore. Note that BLFS_HEAD_HEADER_TYPE_INITIALIZED will be committed
 * last.
 * 
 * @param backstore
 */
void blfs_commit_all_headers(blfs_backstore_t * backstore);

/**
 * Creates the specified keycount from the specified backstore. Throws an error
 * upon failure.
 *
 * Note that this function requires the BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET
 * header to be set properly (either in cache or committed) or this function's
 * behavior is undefined.
 *
 * @param  backstore
 * @param  nugget_index
 *
 * @return              blfs_keycount_t
 */
blfs_keycount_t * blfs_create_keycount(blfs_backstore_t * backstore, uint64_t nugget_index);

/**
 * Reads in the specified keycount from the specified backstore. Throws an error
 * upon failure.
 *
 * @param  backstore
 * @param  nugget_index
 *
 * @return              blfs_keycount_t
 */
blfs_keycount_t * blfs_open_keycount(blfs_backstore_t * backstore, uint64_t nugget_index);

/**
 * Immediately writes the specified keycount to the specified backstore. Throws
 * an error upon failure.
 *
 * @param backstore
 * @param count
 */
void blfs_commit_keycount(blfs_backstore_t * backstore, const blfs_keycount_t * count);

/**
 * The specified keycount is free()'d. Be careful calling this. It should rarely
 * be used.
 *
 * @param backstore
 * @param count
 */
void blfs_close_keycount(blfs_backstore_t * backstore, blfs_keycount_t * count);

/**
 * Creates the specified TJ entry from the specified backstore. Throws an error
 * upon failure.
 *
 * @param  backstore    [description]
 * @param  nugget_index [description]
 *
 * @return              [description]
 */
blfs_tjournal_entry_t * blfs_create_tjournal_entry(blfs_backstore_t * backstore, uint64_t nugget_index);

/**
 * Reads in the specified TJ entry from the specified backstore. Throws an error
 * upon failure.
 *
 * @param  backstore
 * @param  nugget_index
 *
 * @return              blfs_tjournal_entry_t
 */
blfs_tjournal_entry_t * blfs_open_tjournal_entry(blfs_backstore_t * backstore, uint64_t nugget_index);

/**
 * Immediately writes the specified TJ entry to the specified backstore. Throws
 * an error upon failure.
 *
 * @param backstore
 * @param entry
 */
void blfs_commit_tjournal_entry(blfs_backstore_t * backstore, const blfs_tjournal_entry_t * entry);

/**
 * The specified TJ entry is free()'d. Be careful calling this. It should rarely
 * be used.
 *
 * @param backstore
 * @param entry
 */
void blfs_close_tjournal_entry(blfs_backstore_t * backstore, blfs_tjournal_entry_t * entry);

/**
 * Reads in the journaled keycount store, transaction journal, and nugget data.
 * This data is memcpy'd into the corresponding passed pointer arguments.
 *
 * The data is not cached. DO NOT call the various *_close_* functions on the
 * keycounts and tj entries returned by this function!
 *
 * XXX: maybe in the future the data should be cached?
 *
 * @param backstore
 * @param rekeying_nugget_index
 * @param rekeying_count
 * @param rekeying_entry
 * @param rekeying_nugget_data
 */
void blfs_fetch_journaled_data(blfs_backstore_t * backstore,
                               uint64_t rekeying_nugget_index,
                               blfs_keycount_t * rekeying_count,
                               blfs_tjournal_entry_t * rekeying_entry,
                               uint8_t * rekeying_nugget_data);

#endif /* BLFS_BACKSTORE_H_ */
