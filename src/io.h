#ifndef IO_H
#define IO_H

#include <sys/types.h>
#include "constants.h"
#include "cexception_configured.h"

/**
 * struct buselfs_backstore
 *
 * @path                backstore file path
 * @name                backstore file name
 * @read_fd             read-only descriptor pointing to backstore file
 * @write_fd            read-write descriptor pointing to backstore file
 * @keystore_offset     integer offset to where the count store begins
 * @journal_offset      integer offset to where the journal begins
 * @body_offset         integer offset to where the data body (nuggets) begins
 * @is_open             if this struct has had its members free()'d (0 = yes)
 */
typedef struct buselfs_backstore
{
    char * path;
    char * name;

    int read_fd;
    int write_fd;

    uint64_t keystore_offset;
    uint64_t journal_offset;
    uint64_t body_offset;

    char * secret[HEAD_BUFFER_BITLENGTH_SECRET];

    char is_open;
} buselfs_backstore;

/**
 * Read data from the backstore file.
 *
 * @param  backstore    Buselfs_backstore instance
 * @param  buffer       Buffer that data will be copied into
 * @param  len          Number of bytes that will be read into the buffer
 * @param  offset       The read operation will begin at this offset in the backstore
 *
 * @return              0 on success, -1 on failure
 */
int buselfs_backstore_read(buselfs_backstore * backstore, char * buffer, u_int32_t len, uint64_t offset);

/**
 * Write data into the backstore file.
 *
 * @param  backstore    buselfs_backstore instance
 * @param  buffer       Buffer that data will be copied into
 * @param  len          Number of bytes that will be written from the buffer
 * @param  offset       The write operation will begin at this offset in the backstore
 *
 * @return              0 on success, -1 on failure
 */
int buselfs_backstore_write(buselfs_backstore * backstore, const char * buffer, u_int32_t len, uint64_t offset);

/**
 * Initialize a buselfs_backstore object and open/create the appropriate
 * backstore file descriptors at the path specified.
 *
 * @param  path      Backstore file path
 * @param  secret    Argon2-derived secret of size HEAD_BUFFER_BITLENGTH_SECRET
 * @param  backstore The new buselfs_backstore instance pointer
 *
 * @return           0 on success, -1 on failure
 */
int buselfs_backstore_open(const char * path, const char * secret, buselfs_backstore * backstore);

/**
 * Deinitialize a buselfs_backstore instance, close all relevant file
 * descriptors, and free all relevant pointers.
 *
 * @param  backstore Buselfs_backstore instance
 *
 * @return           0 on success, -1 on failure
 */
int buselfs_backstore_close(buselfs_backstore * backstore);

/**
 * Get a filename from a path. After `maxlen` characters are encountered,
 * this function will return.
 *
 * @param  path   File path
 * @param  maxlen Maximum filename length
 *
 * @return        Pointer pointing at the filename string
 */
const char * buselfs_get_filename_from_path(const char * path, int maxlen);

#endif /* IO_H */
