/*
 * Backend virtual block device for any LFS using BUSE
 *
 * @author Bernard Dickens
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>
#include <math.h>
#include <limits.h>
#include <errno.h>

#include "buse.h"
#include "buselfs.h"
#include "uthash.h"
#include "merkletree.h"

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
    return p;
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

int buse_read(void * buffer, uint32_t len, uint64_t offset, void * userdata)
{
    (void) buffer;
    (void) len;
    (void) offset;
    (void) userdata;

    return 0;
}

int buse_write(const void * buffer, uint32_t len, uint64_t offset, void * userdata)
{
    (void) buffer;
    (void) len;
    (void) offset;
    (void) userdata;

    return 0;
}

void buse_disc(void * userdata)
{
    (void) userdata;

    IFDEBUG(dzlog_info("Received a disconnect request (not implemented).\n"));
}

int buse_flush(void * userdata)
{
    (void) userdata;

    IFDEBUG(dzlog_info("Received a flush request (not implemented).\n"));

    return 0;
}

int buse_trim(uint64_t from, uint32_t len, void * userdata)
{
    (void) from;
    (void) len;
    (void) userdata;

    IFDEBUG(dzlog_info("Received a trim request (not implemented)\n"));

    return 0;
}

void rekey_nugget_journaled()
{

}

void password_verify()
{

}

/* FIXME:
blfs_header_t * cache_headers = NULL;
blfs_keycount_t * cache_ksc_offsets = NULL;
blfs_tjournal_entry_t * cache_tj_offsets = NULL;
uint8_t * cache_nugget_keys = NULL;
*/

int buselfs_main(int argc, char * argv[])
{
    short blfs_flags = 0;

    char * blockdevice;
    char backstore_filepath[BLFS_BACKSTORE_FILENAME_MAXLEN];

    uint64_t backstore_size = BLFS_DEFAULT_BYTES_BACKSTORE;
    uint64_t flake_size = BLFS_DEFAULT_BYTES_FLAKE;
    uint64_t flakes_per_nugget = BLFS_DEFAULT_FLAKES_PER_NUGGET;

    /* Print help text if bag argument configuration encountered */

    if(argc <= 1 || argc > 4)
    {
        fprintf(stderr,
        "\nUsage:\n"
        "  %s [--backstore-size 1073741824][--flake-size 4096][--flakes-per-nugget 64] nbd_device\n"
        "nbd_device must always appear last.\n"
        "Size is specified in bytes. Default is shown above.\n"
        "To test for correctness, run (`make check`) from the /build directory.\n"
        "Don't forget to load nbd kernel module (`modprobe nbd`) and run as root!\n", argv[0]);

        return BLFS_EXIT_STATUS_HELP_TEXT;
    }

    /* Process arguments */

    blockdevice = argv[--argc];

    while(argc-- > 1)
    {
        if(strcmp(argv[argc], "--backstore-size") == 0)
            backstore_size = strtol(argv[argc + 1], NULL, 0);

        else if(strcmp(argv[argc], "--flake-size") == 0)
            flake_size = strtol(argv[argc + 1], NULL, 0);

        else if(strcmp(argv[argc], "--flakes-per-nugget") == 0)
            flakes_per_nugget = strtol(argv[argc + 1], NULL, 0);
    }

    /* Prepare to setup the backstore file */

    const char * blockdevice_shortname = get_filename_from_path(blockdevice, 7);
    sprintf(backstore_filepath, BLFS_BACKSTORE_FILENAME, blockdevice_shortname);

    /* Initialize libsodium */

    if(sodium_init() == -1)
        Throw(EXCEPTION_SODIUM_INIT_FAILURE);

    /* Initialize zlog */

    char buf[100];

    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), blockdevice_shortname);

    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        Throw(EXCEPTION_ZLOG_INIT_FAILURE);

    /* Sanity/safety asserts */

    if(flake_size > UINT_MAX || flake_size <= 0)
        Throw(EXCEPTION_INVALID_FLAKESIZE);

    if(flake_size > UINT_MAX || flake_size <= 0)
        Throw(EXCEPTION_INVALID_FLAKESIZE);

    if(flakes_per_nugget > UINT_MAX || flakes_per_nugget <= 0)
        Throw(EXCEPTION_INVALID_FLAKES_PER_NUGGET);

    assert(crypto_stream_chacha20_KEYBYTES == BLFS_CRYPTO_BYTES_CHACHA_KEY);
    assert(crypto_stream_chacha20_NONCEBYTES == BLFS_CRYPTO_BYTES_CHACHA_NONCE);
    assert(crypto_box_SEEDBYTES == BLFS_CRYPTO_BYTES_KDF_OUT);
    assert(crypto_pwhash_SALTBYTES == BLFS_CRYPTO_BYTES_KDF_SALT);
    assert(crypto_onetimeauth_poly1305_BYTES == BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT);
    assert(crypto_onetimeauth_poly1305_KEYBYTES == BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY);
    assert(HASH_LENGTH == BLFS_CRYPTO_BYTES_MTRH);

    if(flakes_per_nugget > BLFS_CRYPTO_BYTES_MTRH * 8)
        Throw(EXCEPTION_TOO_MANY_FLAKES_PER_NUGGET);

    /* Setup backstore file access */

    // FIXME: detect existence and change startup procedure accordingly (handled by io.c, not here)
    int writefd = open(backstore_filepath, O_WRONLY | O_CREAT, 0666);
    int readfd = open(backstore_filepath, O_RDONLY);

    if(writefd < 0 || readfd < 0)
        Throw(EXCEPTION_OPEN_FAILURE);

    /* Startup procedures */


    // FIXME: determine actual size
    buseops.size = 0;

    IFDEBUG(dzlog_info(">> buselfs backend <<"));
    IFDEBUG(dzlog_info("Input flag: 0x%02X", blfs_flags));
    IFDEBUG(dzlog_info("Defined: BLFS_DEBUG_LEVEL = %i", BLFS_DEBUG_LEVEL));
    IFDEBUG(dzlog_info("backstore_filepath = %s", backstore_filepath));
    IFDEBUG(dzlog_info("backstore_size = %"PRIu64, backstore_size));
    IFDEBUG(dzlog_info("size of writable body = %"PRIu64, buseops.size));
    IFDEBUG(dzlog_info("flake_size = %"PRIu64, flake_size));
    IFDEBUG(dzlog_info("flakes_per_nugget = %"PRIu64, flakes_per_nugget));

    /* Let the show begin! */

    return buse_main(blockdevice, &buseops, (void *) &blfs_flags);
}
