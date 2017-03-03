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
#include <sodium.h>
#include <math.h>

#include "buse.h"
#include "buselfs.h"

static int lfs_read(void * buffer, uint32_t len, uint64_t offset, void * userdata)
{
     // FIXME
    return 0;
}

static int lfs_write(const void * buffer, uint32_t len, uint64_t offset, void * userdata)
{
     // FIXME
    return 0;
}

static void lfs_disc(void * userdata)
{
    (void)(userdata);

    //if(DEBUG_LEVEL)
        fprintf(stderr, ">> Received a disconnect request (not implemented).\n"); // FIXME
}

static int lfs_flush(void * userdata)
{
    (void)(userdata);

    //if(DEBUG_LEVEL)
        fprintf(stderr, ">> Received a flush request (just a sync() call).\n"); // FIXME

    return 0;
}

static int lfs_trim(uint64_t from, uint32_t len, void * userdata)
{
    (void) from;
    (void) len;
    (void) userdata;
    (void)(userdata);

    //if(DEBUG_LEVEL)
        fprintf(stderr, ">> T - (not implemented)\n"); // FIXME

    return 0;
}

static struct buse_operations buseops = {
    .read = lfs_read,
    .write = lfs_write,
    .disc = lfs_disc,
    .flush = lfs_flush,
    .trim = lfs_trim,
    .size = BLFS_DEFAULT_BYTES_BACKSTORE
};

/**
 * Get a filename from a path.
 *
 * @param  path       Path to search
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

static void rekey_nugget_journaled()
{

}

static void password_verify()
{

}

int buselfs_main(int argc, char * argv[])
{
    char buf[100];

    // XXX: FIX THIS
    snprintf(buf, sizeof buf, "%s%s%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), "XXXFIXMEXXX");

    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        Throw(EXCEPTION_ZLOG_INIT_FAILURE);

    /* Sanity asserts */
    /*BLFS_CRYPTO_CHACHA_BLOCK_SIZE           64.0 // Must be double! XXX: necessary? Even if so, eliminate doubleness
    BLFS_CRYPTO_BYTES_CHACHA_KEY            32U // crypto_stream_chacha20_KEYBYTES
    BLFS_CRYPTO_BYTES_CHACHA_NONCE          8U // crypto_stream_chacha20_NONCEBYTES
    BLFS_CRYPTO_BYTES_KDF_OUT               32U // crypto_box_SEEDBYTES
    BLFS_CRYPTO_BYTES_KDF_SALT              16U // crypto_pwhash_SALTBYTES
    BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT         16U // crypto_onetimeauth_poly1305_BYTES
    BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY         32U // crypto_onetimeauth_poly1305_KEYBYTES
    BLFS_CRYPTO_BYTES_MTRH                  32U // HASH_LENGTH XXX: this x8 is also an upper bound on flakes per nugget, sanity check this*/

    // default journaling mode BLFS_FLAG_JOURNALING_MODE_FULL
    
    // determine nugget count from flake vs backstore size, ignore end bytes (but log the ignorance)

    // XXX: Implement rekey function here in this file, then add it to header

    /* Wrapping up... */
    
    zlog_fini();

    return 0;
}

/*int main(int argc, char * argv[])
{
    short flags = 0;
    char * blockdevice = NULL;
    uint64_t blocksize = BACKSTORE_SIZE;
    char backstoreFile[256];

    sodium_init();

    if(argc <= 1 || argc > 6)
    {
        fprintf(stderr,
        "\nUsage:\n"
        "  %s [--danger][--with-encrypt][--dirty-start][--size 1073741824] nbd_device\n"
        "  %s [--danger][--with-encrypt] --test-mode test_characters_to_write\n\n"
        "nbd_device must always appear last.\n"
        "Size is specified in bytes. Default is shown above.\n"
        "Danger mode only means something with encryption on. It definitely breaks crypto.\n"
        "Don't forget to load nbd kernel module (`modprobe nbd`) and run as root.\n", argv[0], argv[0]);

        return 1;
    }

    blockdevice = argv[--argc];

    while(argc-- > 1)
    {
        if(strcmp(argv[argc], "--with-encrypt") == 0)
            flags |= FLAG_JOURNALING_MODE_ORDERED;

        else if(strcmp(argv[argc], "--danger") == 0)
            flags |= FLAG_DANGER_MODE;

        else if(!(flags & FLAG_TEST_MODE) && strcmp(argv[argc], "--dirty-start") == 0)
            flags |= FLAG_FORCE_CLEAN_START;

        else if(!(flags & FLAG_TEST_MODE) && strcmp(argv[argc], "--size") == 0)
            blocksize = strtol(argv[argc + 1], NULL, 0);

        else if(strcmp(argv[argc], "--test-mode") == 0)
        {
            flags |= FLAG_TEST_MODE;
            blocksize = strlen(blockdevice);
        }
    }

    buseops.size = blocksize;

    sprintf(backstoreFile, BACKSTORE_FILE, getFilenameFromPath(blockdevice, 7));

    if(flags & FLAG_FORCE_CLEAN_START)
        remove(backstoreFile);

    writefd = open(backstoreFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    readfd = open(backstoreFile, O_RDONLY);

    assert(writefd > 0);
    assert(readfd > 0);

    // Ensure the backstore size always starts out as what it is expected to be
    ftruncate(writefd, blocksize);

    if(DEBUG_LEVEL)
    {
        fprintf(stderr, ">> BUSE LFS Backend <<\n");
        fprintf(stderr, ">> Input flag: 0x%02X\n", flags);
        fprintf(stderr, ">> Journaling mode: %s\n", flags & FLAG_JOURNALING_MODE_ORDERED ? "ON" : "OFF");
        fprintf(stderr, ">> Operating mode: %s\n", flags & FLAG_TEST_MODE ? "TESTING" : (flags & FLAG_FORCE_CLEAN_START ? "FCLEAN" : "NORMAL"));
        fprintf(stderr, ">> Defined: DEBUG_LEVEL = %i\n", DEBUG_LEVEL);
        fprintf(stderr, ">> Defined: BACKSTORE_FILE = %s\n", BACKSTORE_FILE);
        fprintf(stderr, ">> Defined: BACKSTORE_SIZE = %i\n", BACKSTORE_SIZE);
        fprintf(stderr, ">> backstoreFile (actual) = %s\n", backstoreFile);
        fprintf(stderr, ">> blocksize (actual) = %" PRIu64 "\n", blocksize);
    }

    if(flags & FLAG_JOURNALING_MODE_ORDERED)
    {
        prepare_snake_oil();

        if(DEBUG_LEVEL && (flags & FLAG_JOURNALING_MODE_ORDERED))
        {
            fprintf(stderr, ">> Encryption key: %s\n", cryptKey);
            fprintf(stderr, ">> Encryption nonce: %s\n", cryptNonce);
        }
    }

    if(flags & FLAG_TEST_MODE)
    {
        uint64_t len = blocksize;
        uint64_t halfbs = blocksize / 2;
        char * input = blockdevice;
        char * readback = malloc(blocksize);
        char * originalRB = readback;
        char * output = malloc(halfbs);
        char * inputPart = malloc(halfbs);

        assert(blocksize > 3);

        fprintf(stderr, ">> Calling lfs_write() with test data (%" PRIu64 "): ", blocksize);
        debug_print_hex(input, blocksize);

        fprintf(stderr, ">> lfs_write() returned %i\n", lfs_write(input, blocksize, 0, (void *) &flags));

        lseek64(readfd, 0, SEEK_SET);
        while(len > 0)
        {
            uint64_t bytesRead = read(readfd, readback, len);
            assert(bytesRead > 0);
            len -= bytesRead;
            readback = readback + bytesRead;
        }

        fprintf(stderr, ">> lfs_write() wrote-back: ");
        debug_print_hex(originalRB, blocksize);

        fprintf(stderr, ">> Calling lfs_read() on a smaller portion... (%" PRIu64 " to %" PRIu64 ")\n", halfbs, 2 * halfbs - 1);
        fprintf(stderr, ">> lfs_read() returned %i\n", lfs_read(output, halfbs, halfbs, (void *) &flags));
        fprintf(stderr, ">> lfs_read() read-back: ");
        debug_print_hex(output, halfbs);

        memcpy(inputPart, input + halfbs, halfbs);

        fprintf(stderr, ">> Partial input is    : ");
        debug_print_hex(inputPart, halfbs);

        int retval = strcmp(output, inputPart);
        fprintf(stderr, ">> Test %s\n", retval == 0 ? "SUCCEEDED!" : "FAILED!");

        free(originalRB);
        free(output);
        free(inputPart);

        return retval;
    }

    else
    {
        return buse_main(blockdevice, &buseops, (void *) &flags);
    }
}*/
