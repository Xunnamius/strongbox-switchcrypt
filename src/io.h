#ifndef BLFS_IO_H_
#define BLFS_IO_H_

#include "constants.h"
#include "backstore.h"

/**
 * Finish initializing a blfs_backstore_t object.
 * 
 * This should only be called after first using blfs_backstore_create() and
 * further initializing the backstore and its dependencies.
 *
 * @param  backstore
 */
void blfs_backstore_setup_actual_post(blfs_backstore_t * backstore);

/**
 * Initialize a blfs_backstore_t object and create the appropriate backstore
 * file descriptors to the path specified. Throws an error if a file already
 * exists at the given path.
 *
 * @param  path                 Backstore file path
 * @param  file_size_bytes      The size of the backstore file in bytes (real size on disk)
 */
blfs_backstore_t * blfs_backstore_create(const char * path, uint64_t file_size_bytes);

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
 * Note that file_path and file_name will not be free'd for you.
 *
 * @param  backstore Buselfs_backstore instance
 */
void blfs_backstore_close(blfs_backstore_t * backstore);

/**
 * Read data from the backstore file. Throws an error upon failure.
 *
 * @param  backstore    Buselfs_backstore instance
 * @param  buffer       Buffer that data will be copied into
 * @param  length          Number of bytes that will be read into the buffer
 * @param  offset       The read operation will begin at this offset in the backstore
 */
void blfs_backstore_read(blfs_backstore_t * backstore, uint8_t * buffer, uint32_t length, uint64_t offset);

/**
 * Write data into the backstore file. Throws an error upon failure.
 *
 * @param  backstore    blfs_backstore_t instance
 * @param  buffer       Buffer that data will be copied into
 * @param  length          Number of bytes that will be written from the buffer
 * @param  offset       The write operation will begin at this offset in the backstore
 */
void blfs_backstore_write(blfs_backstore_t * backstore, const uint8_t * buffer, uint32_t length, uint64_t offset);

/**
 * Read data from the backstore file's body section. Throws an error upon failure.
 *
 * @param  backstore    Buselfs_backstore instance
 * @param  buffer       Buffer that data will be copied into
 * @param  length       Number of bytes that will be read into the buffer
 * @param  offset       The read operation will begin at this offset in the backstore (relative to beginning of body)
 */
void blfs_backstore_read_body(blfs_backstore_t * backstore, uint8_t * buffer, uint32_t length, uint64_t offset);

/**
 * Write data into the backstore file's body section. Throws an error upon failure.
 *
 * @param  backstore    blfs_backstore_t instance
 * @param  buffer       Buffer that data will be copied into
 * @param  length          Number of bytes that will be written from the buffer
 * @param  offset       The write operation will begin at this offset in the backstore (relative to beginning of body)
 */
void blfs_backstore_write_body(blfs_backstore_t * backstore, const uint8_t * buffer, uint32_t length, uint64_t offset);

#endif /* BLFS_IO_H_ */
