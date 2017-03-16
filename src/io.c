/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include <assert.h>
#include <string.h>
#include <inttypes.h>

#include "io.h"

/*
static int lfs_read(void * buffer, u_int32_t len, uint64_t offset, void * userdata)
{
    int bytesRead;
    u_int32_t size = len;
    char * tempBuffer = malloc(size);
    char * originalBuffer = tempBuffer;
    (void)(userdata);

    if(DEBUG_LEVEL)
        fprintf(stderr, "<< R - %" PRIu64 ", %u (%" PRIu64 ", %" PRIu64 ")\n", offset, len, offset, offset + len - 1);

    lseek64(readfd, offset, SEEK_SET);
    while(len > 0)
    {
        bytesRead = read(readfd, tempBuffer, len);
        assert(bytesRead > 0);
        len -= bytesRead;
        tempBuffer = (char *) tempBuffer + bytesRead;
    }

    if(*((short *)(userdata)) & FLAG_JOURNALING_MODE_ORDERED)
    {
        if(DEBUG_LEVEL)
            fprintf(stderr, "<< D");

        assert(chacha_crypt_actual(buffer, originalBuffer, size, offset) == 0);
    }

    else
        memcpy(buffer, originalBuffer, size);

    free(originalBuffer);
    return 0;
}

static int lfs_write(const void * buffer, u_int32_t len, uint64_t offset, void * userdata)
{
    int bytesWritten;
    char * tempBuffer = malloc(len);
    char * originalBuffer = tempBuffer;
    (void)(userdata);

    if(DEBUG_LEVEL)
        fprintf(stderr, ">> W - %" PRIu64 ", %u (%" PRIu64 ", %" PRIu64 ")\n", offset, len, offset, offset + len - 1);

    if(*((short *)(userdata)) & FLAG_JOURNALING_MODE_ORDERED)
    {
        if(DEBUG_LEVEL)
            fprintf(stderr, ">> E");

        assert(chacha_crypt_actual(tempBuffer, buffer, len, offset) == 0);
    }

    else
        memcpy(tempBuffer, buffer, len);

    lseek64(writefd, offset, SEEK_SET);
    while(len > 0)
    {
        bytesWritten = write(writefd, tempBuffer, len);
        assert(bytesWritten > 0);
        len -= bytesWritten;
        tempBuffer = (char *) tempBuffer + bytesWritten;
    }

    free(originalBuffer);
    return 0;
}
*/

void blfs_backstore_read(blfs_backstore_t * backstore, uint8_t * buffer, uint32_t len, uint64_t offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) backstore;
    (void) buffer;
    (void) len;
    (void) offset;

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_backstore_read_head(blfs_backstore_t * backstore, uint8_t * buffer, uint32_t len, uint64_t offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) backstore;
    (void) buffer;
    (void) len;
    (void) offset;

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_backstore_read_body(blfs_backstore_t * backstore, uint8_t * buffer, uint32_t len, uint64_t offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) backstore;
    (void) buffer;
    (void) len;
    (void) offset;

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_backstore_write(blfs_backstore_t * backstore, const uint8_t * buffer, uint32_t len, uint64_t offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) backstore;
    (void) buffer;
    (void) len;
    (void) offset;

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_backstore_write_head(blfs_backstore_t * backstore, const uint8_t * buffer, uint32_t len, uint64_t offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) backstore;
    (void) buffer;
    (void) len;
    (void) offset;

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_backstore_write_body(blfs_backstore_t * backstore, const uint8_t * buffer, uint32_t len, uint64_t offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) backstore;
    (void) buffer;
    (void) len;
    (void) offset;

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
