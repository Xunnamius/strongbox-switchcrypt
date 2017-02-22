/*
 * Backend virtual block device for any LFS using BUSE
 *
 * @author Xunnamius
 */

#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sodium.h>
#include <math.h>

#include "../buse.h"

// 0 - no debugging messages
// 1 - some general debugging messages
// 3 - verbose debugging messages
#define DEBUG_LEVEL 3

#define BACKSTORE_FILE "./blfs-%s.bkstr"
#define BACKSTORE_SIZE 1 * 1024 * 1024 * 1024
#define CHACHA_BLOCK_SIZE 64.0 // Must be double!

#define FLAG_TEST_MODE 0x01
#define FLAG_FORCE_CLEAN_START 0x02
#define FLAG_JOURNALING_MODE_ORDERED 0x04
#define FLAG_JOURNALING_MODE_FULL 0x08

/*

static int readfd = 0;
static int writefd = 0;

unsigned char cryptKey[crypto_stream_chacha20_KEYBYTES];
unsigned char cryptNonce[crypto_stream_chacha20_NONCEBYTES];

static void prepare_snake_oil()
{
    unsigned int i;

    for(i = 0; i < crypto_stream_chacha20_KEYBYTES; i++)
        cryptKey[i] = (unsigned char)('A' + i);

    for(i = 0; i < crypto_stream_chacha20_NONCEBYTES; i++)
        cryptNonce[i] = (unsigned char)('a' + i);
}

static int chacha_crypt_actual(char * const cryptedMessage, const char * const message, u_int32_t messageLength, uint64_t absoluteOffset)
{
    int retval = -1;

    uint64_t interBlockOffset = (uint64_t) floor(absoluteOffset / CHACHA_BLOCK_SIZE);
    uint64_t intraBlockOffset = absoluteOffset % ((uint64_t) CHACHA_BLOCK_SIZE);
    uint64_t zeroStringLength = (uint64_t) (ceil((intraBlockOffset + messageLength) / CHACHA_BLOCK_SIZE) * CHACHA_BLOCK_SIZE);
    uint64_t blockReadUpperBound = intraBlockOffset + messageLength;

    if(DEBUG_LEVEL)
    {
        fprintf(stderr, " [L=%" PRIu64 " IEO=%" PRIu64 " IAO=%" PRIu64 "] (mlen=%u | {bRRdiff=%" PRIu64 "} <=> blockReadRange=(%" PRIu64 " to %" PRIu64 " - 1))\n",
                zeroStringLength, interBlockOffset, intraBlockOffset,
                messageLength, blockReadUpperBound - intraBlockOffset, intraBlockOffset, blockReadUpperBound);
    }

    assert(zeroStringLength >= messageLength);

    char * zeroString = malloc(zeroStringLength);
    char * xorString = malloc(zeroStringLength);

    memset(zeroString, '0', zeroStringLength);

    retval = crypto_stream_chacha20_xor_ic((unsigned char *) xorString, (unsigned char *) zeroString, zeroStringLength, cryptNonce, interBlockOffset, cryptKey);

    for(uint64_t i = intraBlockOffset, j = blockReadUpperBound, k = 0; i < j; ++i, ++k)
    {
        assert(k < messageLength);
        cryptedMessage[k] = message[k] ^ xorString[i];
    }

    free(zeroString);
    free(xorString);

    return retval;
}

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

static void lfs_disc(void * userdata)
{
    (void)(userdata);

    if(DEBUG_LEVEL)
        fprintf(stderr, ">> Received a disconnect request (not implemented).\n");
}

static int lfs_flush(void * userdata)
{
    (void)(userdata);

    if(DEBUG_LEVEL)
        fprintf(stderr, ">> Received a flush request (just a sync() call).\n");

    return 0;
}

static int lfs_trim(uint64_t from, u_int32_t len, void * userdata)
{
    (void) from;
    (void) len;
    (void) userdata;
    (void)(userdata);

    if(DEBUG_LEVEL)
        fprintf(stderr, ">> T - (not implemented)\n");

    return 0;
}

static struct buse_operations buseops = {
    .read = lfs_read,
    .write = lfs_write,
    .disc = lfs_disc,
    .flush = lfs_flush,
    .trim = lfs_trim,
    .size = BACKSTORE_SIZE
};
*/
/**
* Get a filename from a path.
*
* @param  path Path string
*
* @return      Filename string
*//*
static const char * getFilenameFromPath(const char * path, int maxlen)
{
    const char * p = path;
    int count = 0;

    while(*p != '\0')
    {
        count++;
        p++;
    }

    count++;

    while(*p != '/' && count-- && maxlen--)
        p--;

    p++;
    return p;
}

static void debug_print_hex(const char * str, int len)
{
    for(int i = 0; i < len; i++)
        fprintf(stderr, "0x%x ", str[i] & 0xFF);
    fprintf(stderr, "\n");
}
*/
int main(int argc, char * argv[])
{
    /*short flags = 0;
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
    }*/
}
