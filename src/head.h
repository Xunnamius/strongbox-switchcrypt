#ifndef BLFS_HEAD_H
#define BLFS_HEAD_H

#include <stdint.h>

#include "constants.h"
#include "bitmask.h"
#include "io.h"

/**
 * The HEAD region (as opposed to the BODY region) of the backstore consists of
 * several headers containing pertinent and often times constant data that is
 * of interest at various points during buselfs's execution.
 *
 * This struct represents a generic HEAD section header.
 *
 * @type            BLFS_HEAD_HEADER_TYPE_*
 * @data_offset     data offset in the backstore
 * @data_length     total length of the header data in bytes
 * @data            header value data (in bytes, not synced)
 */
typedef struct blfs_header_t
{
    uint32_t type;

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

    bitmask_t * mask;
} blfs_tjournal_entry_t;

/**
 * Reads in the specified header from the specified backstore unless its already
 * cached. Throws an error upon failure.
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
 * Evicts the specified header from any internal cache and free()s the struct.
 * Be careful calling this. It should only be with one-time-use headers
 * or at the end of the program.
 *
 * @param backstore
 * @param header
 */
void blfs_close_header(blfs_backstore_t * backstore, blfs_header_t * header);

/**
 * Reads in the specified keycount from the specified backstore unless its already
 * cached. Throws an error upon failure.
 *
 * @param  backstore
 * @param  nugget_index
 *
 * @return              blfs_keycount_t
 */
blfs_keycount_t * blfs_open_keycount(blfs_backstore_t * backstore, uint32_t nugget_index);

/**
 * Immediately writes the specified keycount to the specified backstore. Throws
 * an error upon failure.
 *
 * @param backstore
 * @param count
 */
void blfs_commit_keycount(blfs_backstore_t * backstore, const blfs_keycount_t * count);

/**
 * Evicts the specified keycount from any internal cache and free()s the struct.
 * Be careful calling this. It should rarely be used.
 *
 * @param backstore
 * @param count
 */
void blfs_close_keycount(blfs_backstore_t * backstore, blfs_keycount_t * count);

/**
 * Reads in the specified TJ entry from the specified backstore unless its already
 * cached. Throws an error upon failure.
 *
 * @param  backstore
 * @param  nugget_index
 *
 * @return              blfs_tjournal_entry_t
 */
blfs_tjournal_entry_t * blfs_open_journal_entry(blfs_backstore_t * backstore, uint32_t nugget_index);

/**
 * Immediately writes the specified TJ entry to the specified backstore. Throws
 * an error upon failure.
 *
 * @param backstore
 * @param entry
 */
void blfs_commit_journal_entry(blfs_backstore_t * backstore, const blfs_tjournal_entry_t * entry);

/**
 * Evicts the specified TJ entry from any internal cache and free()s the struct.
 * Be careful calling this. It should rarely be used.
 *
 * @param backstore
 * @param entry
 */
void blfs_close_journal_entry(blfs_backstore_t * backstore, blfs_tjournal_entry_t * entry);

#endif /* BLFS_HEAD_H */
