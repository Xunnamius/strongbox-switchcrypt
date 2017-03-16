#ifndef BLFS_IO_H_
#define BLFS_IO_H_

#include "constants.h"
#include "backstore.h"

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
 * Read data from the backstore file's head section. Throws an error upon failure.
 *
 * @param  backstore    Buselfs_backstore instance
 * @param  buffer       Buffer that data will be copied into
 * @param  len          Number of bytes that will be read into the buffer
 * @param  offset       The read operation will begin at this offset in the backstore (relative to beginning of head)
 */
void blfs_backstore_read_head(blfs_backstore_t * backstore, uint8_t * buffer, uint32_t len, uint64_t offset);

/**
 * Read data from the backstore file's body section. Throws an error upon failure.
 *
 * @param  backstore    Buselfs_backstore instance
 * @param  buffer       Buffer that data will be copied into
 * @param  len          Number of bytes that will be read into the buffer
 * @param  offset       The read operation will begin at this offset in the backstore (relative to beginning of body)
 */
void blfs_backstore_read_body(blfs_backstore_t * backstore, uint8_t * buffer, uint32_t len, uint64_t offset);

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
 * Write data into the backstore file's head section. Throws an error upon failure.
 *
 * @param  backstore    blfs_backstore_t instance
 * @param  buffer       Buffer that data will be copied into
 * @param  len          Number of bytes that will be written from the buffer
 * @param  offset       The write operation will begin at this offset in the backstore (relative to beginning of head)
 */
void blfs_backstore_write_head(blfs_backstore_t * backstore, const uint8_t * buffer, uint32_t len, uint64_t offset);

/**
 * Write data into the backstore file's body section. Throws an error upon failure.
 *
 * @param  backstore    blfs_backstore_t instance
 * @param  buffer       Buffer that data will be copied into
 * @param  len          Number of bytes that will be written from the buffer
 * @param  offset       The write operation will begin at this offset in the backstore (relative to beginning of body)
 */
void blfs_backstore_write_body(blfs_backstore_t * backstore, const uint8_t * buffer, uint32_t len, uint64_t offset);

#endif /* BLFS_IO_H_ */
