/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include "io.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>

void blfs_backstore_read(blfs_backstore_t * backstore, uint8_t * buffer, uint32_t length, uint64_t offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    int bytes_read;
    uint32_t size = length;
    uint8_t * temp_buffer = malloc(sizeof(uint8_t) * length);
    uint8_t * original_buffer = temp_buffer;

    IFDEBUG(dzlog_info("incoming read request for data of length %"PRIu32" from offset %"PRIu64" to %"PRIu64,
                        length, offset, offset + length - 1));

    lseek64(backstore->read_fd, offset, SEEK_SET);

    while(length > 0)
    {
        bytes_read = read(backstore->read_fd, temp_buffer, length);
        assert(bytes_read > 0);
        length -= bytes_read;
        temp_buffer += bytes_read;
    }

    memcpy(buffer, original_buffer, size);

    IFDEBUG(dzlog_info("first 64 bytes:"));
    IFDEBUG(hdzlog_debug(buffer, MIN(64U, size)));

    free(original_buffer);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_backstore_write(blfs_backstore_t * backstore, const uint8_t * buffer, uint32_t length, uint64_t offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    int bytes_written;
    uint8_t * temp_buffer = malloc(sizeof(uint8_t) * length);
    uint8_t * original_buffer = temp_buffer;

    IFDEBUG(dzlog_info("incoming write request for data of length %"PRIu32" from offset %"PRIu64" to %"PRIu64,
                        length, offset, offset + length - 1));

    IFDEBUG(dzlog_info("first 64 bytes:"));
    IFDEBUG(hdzlog_debug(buffer, MIN(64U, length)));

    memcpy(temp_buffer, buffer, length);
    lseek64(backstore->write_fd, offset, SEEK_SET);

    while(length > 0)
    {
        bytes_written = write(backstore->write_fd, temp_buffer, length);
        assert(bytes_written > 0);
        length -= bytes_written;
        temp_buffer += bytes_written;
    }

    free(original_buffer);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_backstore_read_body(blfs_backstore_t * backstore, uint8_t * buffer, uint32_t length, uint64_t offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    blfs_backstore_read(backstore, buffer, length, backstore->body_real_offset + offset);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_backstore_write_body(blfs_backstore_t * backstore, const uint8_t * buffer, uint32_t len, uint64_t offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    blfs_backstore_write(backstore, buffer, len, backstore->body_real_offset + offset);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
