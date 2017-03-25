/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include "io.h"

#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

/**
 * Get a filename from a path.
 *
 * @param  path       Path string to search
 * @param  max_length Maximum length of returned string
 *
 * @return A pointer pointing to the filename
 */
static const char * get_filename_from_path(const char * path, int max_length)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    const char * p = path;
    int count = 0;

    while(*p != '\0')
    {
        count++;
        p++;
    }

    count++;

    while(*p != '/' && count-- && max_length--)
        p--;

    p++;

    IFDEBUG(dzlog_debug("RETURN: filename = %s", p));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return p;
}

/**
 * Actually does the creating and initializing of a backstore struct instance.
 *
 * @param  path
 */
static blfs_backstore_t * backstore_setup_actual_pre(const char * path)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));
    IFDEBUG(dzlog_debug("creating new blfs_backstore_t backstore object"));

    char * fpath = malloc((strlen(path) + 1) * sizeof(*fpath));

    if(fpath == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    memcpy(fpath, path, strlen(path) + 1);

    blfs_backstore_t init = {
        .file_path        = fpath,
        .file_name        = get_filename_from_path(fpath, BLFS_BACKSTORE_FILENAME_MAXLEN),
        .cache_headers    = kh_init(BLFS_KHASH_HEADERS_CACHE_NAME),
        .cache_kcs_counts = kh_init(BLFS_KHASH_KCS_CACHE_NAME),
        .cache_tj_entries = kh_init(BLFS_KHASH_TJ_CACHE_NAME)
    };
    
    IFDEBUG(dzlog_debug("init->file_path = %s", init.file_path));
    IFDEBUG(dzlog_debug("init->file_name = %s", init.file_name));

    blfs_backstore_t * backstore = malloc(sizeof(blfs_backstore_t));

    if(backstore == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    memcpy(backstore, &init, sizeof(blfs_backstore_t));
    
    backstore->io_fd  = open(backstore->file_path, O_CREAT | O_RDWR, BLFS_DEFAULT_BACKSTORE_FILE_PERMS);

    if(backstore->io_fd < 0)
        Throw(EXCEPTION_OPEN_FAILURE);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));

    return backstore;
}

void blfs_backstore_setup_actual_post(blfs_backstore_t * backstore)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    // XXX: get the last item in the header (before the start of the kcs) and
    // use its offset + length to determine the true length of the HEAD header
    blfs_header_t * header_last = blfs_open_header(backstore, header_types_ordered[BLFS_HEAD_NUM_HEADERS - 1][0]);

    // We need to know the number of nuggets to calculate the other offsets
    blfs_header_t * header_numnuggets = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_NUMNUGGETS);
    uint32_t num_nuggets = *((uint32_t *) header_numnuggets->data);

    IFDEBUG(dzlog_debug("num_nuggets = %"PRIu32, num_nuggets));

    // We also need to know the number of flakes per nugget
    blfs_header_t * header_flakespernugget = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET);
    uint32_t flakes_per_nugget = *((uint32_t *) header_flakespernugget->data);

    IFDEBUG(dzlog_debug("flakes_per_nugget = %"PRIu32, flakes_per_nugget));

    // And finally, we need the individual byte size of each flake
    blfs_header_t * header_flakesizebytes = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES);
    uint32_t flake_size_bytes = *((uint32_t *) header_flakesizebytes->data);

    IFDEBUG(dzlog_debug("flake_size_bytes = %"PRIu32, flake_size_bytes));

    // We also need the backstore file size
    off_t backstore_size_actual = lseek64(backstore->io_fd, 0, SEEK_END);

    IFDEBUG(dzlog_debug("backstore_size_actual = %"PRIu64, backstore_size_actual));
    IFDEBUG(dzlog_debug("header_last->data_length = %"PRIu64, header_last->data_length));

    if(backstore_size_actual <= 0)
        Throw(EXCEPTION_BACKSTORE_SIZE_TOO_SMALL);

    // XXX: Maybe I should add some overflow protection here and elsewhere... maybe later

    backstore->kcs_real_offset = header_last->data_offset + header_last->data_length;
    backstore->tj_real_offset  = backstore->kcs_real_offset + num_nuggets * BLFS_HEAD_BYTES_KEYCOUNT;

    IFDEBUG(dzlog_debug("backstore->kcs_real_offset = %"PRIu64, backstore->kcs_real_offset));
    IFDEBUG(dzlog_debug("backstore->tj_real_offset = %"PRIu64, backstore->tj_real_offset));

    backstore->kcs_journaled_offset    = backstore->tj_real_offset + num_nuggets * CEIL(flakes_per_nugget, BITS_IN_A_BYTE);
    backstore->tj_journaled_offset     = backstore->kcs_journaled_offset + BLFS_HEAD_BYTES_KEYCOUNT;
    backstore->nugget_journaled_offset = backstore->tj_journaled_offset + CEIL(flakes_per_nugget, BITS_IN_A_BYTE);

    IFDEBUG(dzlog_debug("backstore->kcs_journaled_offset = %"PRIu64, backstore->kcs_journaled_offset));
    IFDEBUG(dzlog_debug("backstore->tj_journaled_offset = %"PRIu64, backstore->tj_journaled_offset));
    IFDEBUG(dzlog_debug("backstore->nugget_journaled_offset = %"PRIu64, backstore->nugget_journaled_offset));

    backstore->nugget_size_bytes = flakes_per_nugget * flake_size_bytes;
    IFDEBUG(dzlog_debug("backstore->nugget_size_bytes = %"PRIu64, backstore->nugget_size_bytes));
    
    backstore->body_real_offset = backstore->nugget_journaled_offset + backstore->nugget_size_bytes;
    IFDEBUG(dzlog_debug("backstore->body_real_offset = %"PRIu64, backstore->body_real_offset));

    backstore->writeable_size_actual = backstore_size_actual - backstore->body_real_offset;
    IFDEBUG(dzlog_debug("backstore->writeable_size_actual = %"PRIu64, backstore->writeable_size_actual));

    if(backstore->writeable_size_actual > (unsigned) backstore_size_actual)
        Throw(EXCEPTION_BACKSTORE_SIZE_TOO_SMALL);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

blfs_backstore_t * blfs_backstore_create(const char * path, uint64_t file_size_bytes)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(access(path, F_OK) != -1)
        Throw(EXCEPTION_FILE_ALREADY_EXISTS);

    blfs_backstore_t * backstore = backstore_setup_actual_pre(path);

    ftruncate(backstore->io_fd, file_size_bytes);

    // Header data
    uint64_t data_version_int = BLFS_CURRENT_VERSION;
    uint8_t * data_version = (uint8_t *) &data_version_int;

    IFDEBUG(dzlog_debug("data_version = %"PRIu64, data_version_int));
    IFDEBUG(dzlog_debug("data_version:"));
    IFDEBUG(hdzlog_debug(data_version, BLFS_HEAD_HEADER_TYPE_VERSION));

    uint8_t data_salt[BLFS_HEAD_HEADER_BYTES_SALT] = { 0x00 };
    uint8_t data_mtrh[BLFS_HEAD_HEADER_BYTES_MTRH] = { 0x00 };
    uint8_t data_tpmglobalver[BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t data_verification[BLFS_HEAD_HEADER_BYTES_VERIFICATION] = { 0x00 };
    uint8_t data_numnuggets[BLFS_HEAD_HEADER_BYTES_NUMNUGGETS] = { 0x00 };
    uint8_t data_flakespernugget[BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET] = { 0x00 };
    uint8_t data_flakesizebytes[BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES] = { 0x00 };
    uint8_t data_initialized[BLFS_HEAD_HEADER_BYTES_INITIALIZED] = { 0x00 };
    uint8_t data_rekeying[BLFS_HEAD_HEADER_BYTES_REKEYING] = { 0x00, 0x00, 0x00, 0x00 };

    // Initialize headers (add them to cache so further opens don't hit disk)
    // TODO: maybe put this in a loop that references header_types_ordered
    (void) blfs_create_header(backstore, BLFS_HEAD_HEADER_TYPE_VERSION, data_version);
    (void) blfs_create_header(backstore, BLFS_HEAD_HEADER_TYPE_SALT, data_salt);
    (void) blfs_create_header(backstore, BLFS_HEAD_HEADER_TYPE_MTRH, data_mtrh);
    (void) blfs_create_header(backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER, data_tpmglobalver);
    (void) blfs_create_header(backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION, data_verification);
    (void) blfs_create_header(backstore, BLFS_HEAD_HEADER_TYPE_NUMNUGGETS, data_numnuggets);
    (void) blfs_create_header(backstore, BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET, data_flakespernugget);
    (void) blfs_create_header(backstore, BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES, data_flakesizebytes);
    (void) blfs_create_header(backstore, BLFS_HEAD_HEADER_TYPE_INITIALIZED, data_initialized);
    (void) blfs_create_header(backstore, BLFS_HEAD_HEADER_TYPE_REKEYING, data_rekeying);

    backstore->kcs_real_offset = 0;
    backstore->tj_real_offset = 0;
    backstore->body_real_offset = 0;
    backstore->kcs_journaled_offset = 0;
    backstore->tj_journaled_offset = 0;
    backstore->nugget_journaled_offset = 0;
    backstore->nugget_size_bytes = 0;
    backstore->writeable_size_actual = 0;

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));

    return backstore;
}

blfs_backstore_t * blfs_backstore_open(const char * path)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(access(path, F_OK) == -1)
        Throw(EXCEPTION_FILE_DOES_NOT_EXIST);

    blfs_backstore_t * backstore = backstore_setup_actual_pre(path);

    // Make sure that the backstore has been initialized
    blfs_header_t * header_initialized = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_INITIALIZED);
    uint8_t is_initized = *(header_initialized->data);

    IFDEBUG(dzlog_debug("is_initized (%"PRIu8" == initialized) = %"PRIu8, (uint8_t) BLFS_HEAD_IS_INITIALIZED_VALUE, is_initized));

    if(is_initized != (uint8_t) BLFS_HEAD_IS_INITIALIZED_VALUE)
        Throw(EXCEPTION_BACKSTORE_NOT_INITIALIZED);

    // Make sure the version is, if not the same as ours, at least compatible
    blfs_header_t * header_version = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_VERSION);
    uint32_t their_version = *((uint32_t *) header_version->data);

    IFDEBUG(dzlog_debug("their_version = %"PRIu32, their_version));
    IFDEBUG(dzlog_debug("BLFS_CURRENT_VERSION = %"PRIu32, BLFS_CURRENT_VERSION));
    IFDEBUG(dzlog_debug("BLFS_LEAST_COMPAT_VERSION = %"PRIu32, BLFS_LEAST_COMPAT_VERSION));

    if(their_version != BLFS_CURRENT_VERSION && their_version < BLFS_LEAST_COMPAT_VERSION)
        Throw(EXCEPTION_INCOMPAT_BACKSTORE_VERSION);

    blfs_backstore_setup_actual_post(backstore);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));

    return backstore;
}

void blfs_backstore_close(blfs_backstore_t * backstore)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    kh_destroy(BLFS_KHASH_HEADERS_CACHE_NAME, backstore->cache_headers);
    kh_destroy(BLFS_KHASH_KCS_CACHE_NAME, backstore->cache_kcs_counts);
    kh_destroy(BLFS_KHASH_TJ_CACHE_NAME, backstore->cache_tj_entries);
    close(backstore->io_fd);
    free((void *) backstore->file_path);
    free(backstore);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_backstore_read(blfs_backstore_t * backstore, uint8_t * buffer, uint32_t length, uint64_t offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    int bytes_read;
    uint32_t size = length;
    uint8_t * temp_buffer = malloc(sizeof(uint8_t) * length);
    uint8_t * original_buffer = temp_buffer;

    if(temp_buffer == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    IFDEBUG(dzlog_info("incoming read request for data of length %"PRIu32" from offset %"PRIu64" to %"PRIu64,
                        length, offset, offset + length - 1));

    lseek64(backstore->io_fd, offset, SEEK_SET);

    while(length > 0)
    {
        bytes_read = read(backstore->io_fd, temp_buffer, length);

        if(bytes_read == -1)
        {
            dzlog_fatal("IO error: read error: %s", strerror(errno));
            errno = 0;
        }

        assert(bytes_read > 0);

        length -= bytes_read;
        temp_buffer += bytes_read;
    }

    memcpy(buffer, original_buffer, size);

    IFDEBUG(dzlog_debug("first 64 bytes:"));
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

    if(temp_buffer == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    IFDEBUG(dzlog_info("incoming write request for data of length %"PRIu32" from offset %"PRIu64" to %"PRIu64,
                        length, offset, offset + length - 1));

    IFDEBUG(dzlog_debug("first 64 bytes:"));
    IFDEBUG(hdzlog_debug(buffer, MIN(64U, length)));

    memcpy(temp_buffer, buffer, length);
    lseek64(backstore->io_fd, offset, SEEK_SET);

    while(length > 0)
    {
        bytes_written = write(backstore->io_fd, temp_buffer, length);

        if(bytes_written == -1)
        {
            dzlog_fatal("IO error: write error: %s", strerror(errno));
            errno = 0;
        }

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
