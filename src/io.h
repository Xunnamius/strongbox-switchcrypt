#ifndef BLFS_IO_H
#define BLFS_IO_H

#include <stdint.h>
#include <sys/types.h>

#include "constants.h"

/**
 * This struct and its related functions abstract away a lot of the underlying
 * interactions and I/O between buselfs and the underlying filesystem housing
 * the backstore file container.
 *
 * @file_path           backstore file path
 * @file_name           backstore file name
 * @read_fd             read-only descriptor pointing to backstore file
 * @write_fd            read-write descriptor pointing to backstore file
 * @keystore_offset     integer offset to where the keycount store begins
 * @journal_offset      integer offset to where the transaction journal begins
 * @body_offset         integer offset to where the data BODY (nuggets) begins
 * @master_secret       cached secret from KDF, size BLFS_CRYPTO_BYTES_KDF_OUT
 * @header_cache        cached headers
 * @kcs_cache           cached keycounts
 * @tj_cache            cached journal entries
 * @chacha_key_cache    cached chacha20 encryption keys (used by nuggets)
 */
typedef struct blfs_backstore_t
{
    char * file_path;
    char * file_name;

    int read_fd;
    int write_fd;

    uint64_t kcs_offset;
    uint64_t tj_offset;
    uint64_t body_offset;

    uint8_t * master_secret;

    uint8_t * header_cache;
    uint8_t * kcs_cache;
    uint8_t * tj_cache;
    uint8_t * chacha_key_cache;
} blfs_backstore_t;

/**
 * Read data from the backstore file. Throws an error upon failure.
 *
 * @param  backstore    Buselfs_backstore instance
 * @param  buffer       Buffer that data will be copied into
 * @param  len          Number of bytes that will be read into the buffer
 * @param  offset       The read operation will begin at this offset in the backstore
 */
void blfs_backstore_read(blfs_backstore_t * backstore, uint8_t * buffer, uint32_t len, uint64_t offset);

/**
 * Write data into the backstore file. Throws an error upon failure.
 *
 * @param  backstore    blfs_backstore_t instance
 * @param  buffer       Buffer that data will be copied into
 * @param  len          Number of bytes that will be written from the buffer
 * @param  offset       The write operation will begin at this offset in the backstore
 */
void blfs_backstore_write(blfs_backstore_t * backstore, const uint8_t * buffer, uint32_t len, uint64_t offset);

/**
 * Initialize a blfs_backstore_t object and create the appropriate backstore
 * file descriptors to the path specified. Throws an error if a file already
 * exists at the given path.
 *
 * @param  path      Backstore file path
 */
blfs_backstore_t * blfs_backstore_create(const char * path);

/**
 * Initialize a blfs_backstore_t object and open the appropriate backstore file
 * descriptors to the path specified. Throws an error if no file exists at the
 * given path.
 *
 * @param  path      Backstore file path
 */
blfs_backstore_t * blfs_backstore_open(const char * path);

/**
 * Deinitialize a blfs_backstore_t instance, close all relevant file
 * descriptors, and free all relevant pointers and internal caches. There should
 * not really be a reason to call this.
 *
 * @param  backstore Buselfs_backstore instance
 */
void blfs_backstore_close(blfs_backstore_t * backstore);

#endif /* BLFS_IO_H */
