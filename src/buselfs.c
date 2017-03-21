/*
 * Backend virtual block device for any LFS using BUSE
 *
 * @author Bernard Dickens
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>

#include "buse.h"
#include "backstore.h"
#include "io.h"
#include "buselfs.h"
#include "bitmask.h"
#include "crypto.h"
#include "interact.h"
#include "khash.h"
#include "merkletree.h"

/**
 * A cache that holds each of the keys for every nugget and flake in the filesystem.
 *
 * Keys look like:
 * nugget keys: nugget_id => master_secret||nugget_id
 * flake keys: nugget_id||associated_keycount||flake_id => master_secret||nugget_id||associated_keycount||flake_id
 *
 * XXX: This uses quite a bit of memory, perhaps unnecessarily from a perf
 * perspective. Then again, it may not be all that much. Profile if badness.
 */
KHASH_MAP_INIT_STR(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, uint8_t *)
khash_t(BLFS_KHASH_NUGGET_KEY_CACHE_NAME) * cache_nugget_keys;

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

void buse_disc(void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) userdata;

    IFDEBUG(dzlog_info("Received a disconnect request (not implemented).\n"));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

int buse_flush(void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) userdata;

    IFDEBUG(dzlog_info("Received a flush request (not implemented).\n"));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return 0;
}

int buse_trim(uint64_t from, uint32_t len, void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) from;
    (void) len;
    (void) userdata;

    IFDEBUG(dzlog_info("Received a trim request (not implemented)\n"));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return 0;
}

int buse_read(void * buffer, uint32_t len, uint64_t offset, void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) buffer;
    (void) len;
    (void) offset;
    (void) userdata;

    // FIXME: Handle reads and deal with caching

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return 0;
}

int buse_write(const void * buffer, uint32_t len, uint64_t offset, void * userdata)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) buffer;
    (void) len;
    (void) offset;
    (void) userdata;

    if(BLFS_DEFAULT_DISABLE_JOURNALING)
    {
        // FIXME: Handle journaling
    }

    // FIXME: Handle writes and deal with caching

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return 0;
}

void rekey_nugget_journaled()
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    // FIXME: implement me!

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void password_verify()
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    // FIXME: implement me!

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

static void buselfs_main_actual(int argc, char * argv[], char * blockdevice)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    char * cin_device_name;
    char backstore_path[BLFS_BACKSTORE_FILENAME_MAXLEN];
    blfs_backstore_t * backstore;

    uint8_t  cin_allow_insecure_start       = 0;
    uint8_t  cin_backstore_mode             = BLFS_BACKSTORE_CREATE_MODE_UNKNOWN;
    uint64_t cin_backstore_size             = BLFS_DEFAULT_BYTES_BACKSTORE;
    uint64_t cin_flake_size                 = BLFS_DEFAULT_BYTES_FLAKE;
    uint64_t cin_flakes_per_nugget          = BLFS_DEFAULT_FLAKES_PER_NUGGET;

    IFDEBUG(dzlog_debug("argc: %i", argc));

    if(argc <= 1 || argc > 9)
    {
        fprintf(stderr,
        "\nUsage:\n"
        "  %s [--allow-insecure-start][--backstore-size 1024][--flake-size 4096][--flakes-per-nugget 64] open|create nbd_device_name\n\n"
        "nbd_device must always appear last.\n"
        "--backstore-size must be in MEGABYTES.\n"
        "--flake-size and --flakes-per-nugget are specified in just BYTES. Defaults are shown above.\n\n"
        "Your options are to either open an existing backstore or create a new one."
        "Note that the `create` option will force overwrite a previous backstore correlated with the same nbd device name!)\n\n"
        "To test for correctness, run `make check` from the /build directory. Check the README for more details.\n"
        "Don't forget to load nbd kernel module `modprobe nbd` and run as root!\n\n"
        "Example: %s --allow-insecure-start --backstore-size 4096 open nbd4", argv[0], argv[0]);

        exit(BLFS_EXIT_STATUS_HELP_TEXT);
    }

    /* Process arguments */

    cin_device_name = argv[--argc];

    if(strcmp(argv[--argc], "create") == 0)
        cin_backstore_mode = BLFS_BACKSTORE_CREATE_MODE_CREATE;

    else if(strcmp(argv[argc], "open") == 0)
        cin_backstore_mode = BLFS_BACKSTORE_CREATE_MODE_OPEN;

    while(argc-- > 1)
    {
        if(strcmp(argv[argc], "--backstore-size") == 0)
        {
            cin_backstore_size = strtoll(argv[argc + 1], NULL, 0);
            IFDEBUG(dzlog_debug("saw --backstore-size, got value: %"PRIu64, cin_backstore_size));
        }

        else if(strcmp(argv[argc], "--flake-size") == 0)
        {
            cin_flake_size = strtoll(argv[argc + 1], NULL, 0);
            IFDEBUG(dzlog_debug("saw --flake-size = %"PRIu64, cin_flake_size));
        }

        else if(strcmp(argv[argc], "--flakes-per-nugget") == 0)
        {
            cin_flakes_per_nugget = strtoll(argv[argc + 1], NULL, 0);
            IFDEBUG(dzlog_debug("saw --flakes-per-nugget = %"PRIu64, cin_flakes_per_nugget));
        }

        else if(strcmp(argv[argc], "--allow-insecure-start") == 0)
        {
            cin_allow_insecure_start = 1;
            IFDEBUG(dzlog_debug("saw --allow-insecure-start = %i", cin_allow_insecure_start));
        }
    }

    IFDEBUG(dzlog_debug("argument processing result:"));
    IFDEBUG(dzlog_debug("cin_allow_insecure_start = %i", cin_allow_insecure_start));
    IFDEBUG(dzlog_debug("cin_backstore_size = %"PRIu64, cin_backstore_size));
    IFDEBUG(dzlog_debug("cin_flake_size = %"PRIu64, cin_flake_size));
    IFDEBUG(dzlog_debug("cin_flakes_per_nugget = %"PRIu64, cin_flakes_per_nugget));
    IFDEBUG(dzlog_debug("cin_backstore_mode = %i", cin_backstore_mode));

    IFDEBUG(dzlog_debug("defaults:"));
    IFDEBUG(dzlog_debug("default allow_insecure_start = 0"));
    IFDEBUG(dzlog_debug("default force_overwrite_backstore = 0"));
    IFDEBUG(dzlog_debug("default backstore_size = %"PRIu64, BLFS_DEFAULT_BYTES_BACKSTORE));
    IFDEBUG(dzlog_debug("default flake_size = %"PRIu64, BLFS_DEFAULT_BYTES_FLAKE));
    IFDEBUG(dzlog_debug("default flakes_per_nugget = %"PRIu64, BLFS_DEFAULT_FLAKES_PER_NUGGET));
    IFDEBUG(dzlog_debug("cin_backstore_mode = %i", BLFS_BACKSTORE_CREATE_MODE_UNKNOWN));

    if(errno == ERANGE || cin_backstore_mode > BLFS_BACKSTORE_CREATE_MAX_MODE_NUM)
        Throw(EXCEPTION_BAD_ARGUMENT_FORM);

    errno = 0;

    if(cin_backstore_size > ULONG_MAX || cin_backstore_size <= 0)
        Throw(EXCEPTION_INVALID_BACKSTORESIZE);

    if(cin_flake_size > ULONG_MAX || cin_flake_size <= 0)
        Throw(EXCEPTION_INVALID_FLAKESIZE);

    if(cin_flakes_per_nugget > ULONG_MAX || cin_flakes_per_nugget <= 0)
        Throw(EXCEPTION_INVALID_FLAKES_PER_NUGGET);

    /* Prepare to setup the backstore file */

    sprintf(backstore_path, BLFS_BACKSTORE_FILENAME, cin_device_name);
    IFDEBUG(dzlog_debug("backstore_path = %s", backstore_path));

    /* Initialize libsodium */

    if(sodium_init() == -1)
        Throw(EXCEPTION_SODIUM_INIT_FAILURE);

    /* Initialize zlog */

    char buf[100];

    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), cin_device_name);
    IFDEBUG(dzlog_debug("BLFS_CONFIG_ZLOG = %s", BLFS_CONFIG_ZLOG));
    IFDEBUG(dzlog_debug("zlog buf = %s", buf));

    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        Throw(EXCEPTION_ZLOG_INIT_FAILURE);

    /* Sanity/safety asserts */

    assert(crypto_stream_chacha20_KEYBYTES == BLFS_CRYPTO_BYTES_CHACHA_KEY);
    assert(crypto_stream_chacha20_NONCEBYTES == BLFS_CRYPTO_BYTES_CHACHA_NONCE);
    assert(crypto_box_SEEDBYTES == BLFS_CRYPTO_BYTES_KDF_OUT);
    assert(crypto_pwhash_SALTBYTES == BLFS_CRYPTO_BYTES_KDF_SALT);
    assert(crypto_onetimeauth_poly1305_BYTES == BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT);
    assert(crypto_onetimeauth_poly1305_KEYBYTES == BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY);
    assert(HASH_LENGTH == BLFS_CRYPTO_BYTES_MTRH);

    if(cin_flakes_per_nugget > BLFS_CRYPTO_BYTES_MTRH * 8)
    {
        IFDEBUG(dzlog_debug("EXCEPTION: too many flakes per nugget! (%"PRIu64">%"PRIu32")",
                            cin_flakes_per_nugget, BLFS_CRYPTO_BYTES_MTRH * 8));

        Throw(EXCEPTION_TOO_MANY_FLAKES_PER_NUGGET);
    }

    /* Setup backstore file access */

    volatile uint8_t already_attempted_delete = 0;
    CEXCEPTION_T e = EXCEPTION_NO_EXCEPTION;

    if(cin_backstore_mode == BLFS_BACKSTORE_CREATE_MODE_CREATE)
    {
        IFDEBUG(dzlog_debug("running in CREATE mode!"));

        Try
        {
            backstore = blfs_backstore_create(backstore_path, cin_backstore_size);
        }
        
        Catch(e)
        {
            if(e == EXCEPTION_FILE_ALREADY_EXISTS && !already_attempted_delete)
            {
                IFDEBUG(dzlog_debug("backstore file already exists, deleting and trying again..."));
                unlink(backstore_path);
                already_attempted_delete = 1;
                backstore = blfs_backstore_create(backstore_path, cin_backstore_size);
                // XXX: refs to memory allocated during blfs_backstore_create
                // will be lost during an exception. It's technically a memory
                // leak, but it's not so pressing an issue at the moment.
            }

            else
            {
                IFDEBUG(dzlog_debug("EXCEPTION: rethrowing exception (already_attempted_delete = %i) %"PRIu32,
                                    already_attempted_delete, e));

                Throw(e);
            }
        }

        // FIXME: Ask questions, set init header, etc 

        blfs_backstore_setup_actual_post(backstore);

        // FIXME: Commit headers, and startup
    }

    else if(cin_backstore_mode == BLFS_BACKSTORE_CREATE_MODE_OPEN)
    {
        IFDEBUG(dzlog_debug("running in OPEN mode!"));

        backstore = blfs_backstore_open(backstore_path);

        // FIXME: Ask questions, run verifications, handle rekeying, and startup
    }

    /* Finish up startup procedures */

    IFDEBUG(dzlog_info("Defined: BLFS_DEBUG_LEVEL = %i", BLFS_DEBUG_LEVEL));

    buseops.size = backstore->writeable_size_actual;
    cache_nugget_keys = kh_init(BLFS_KHASH_NUGGET_KEY_CACHE_NAME);

    IFDEBUG(dzlog_info("buseops.size = %"PRIu64, buseops.size));

    /* Let the show begin! */

    IFDEBUG(dzlog_info(">> buselfs backend was setup successfully! <<"));

    sprintf(blockdevice, BLFS_BACKSTORE_DEVICEPATH, cin_device_name);
    IFDEBUG(dzlog_debug("RETURN: blockdevice = %s", blockdevice));
    
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

int buselfs_main(int argc, char * argv[])
{
    char blockdevice[BLFS_BACKSTORE_FILENAME_MAXLEN];
    buselfs_main_actual(argc, argv, blockdevice);

    return buse_main(blockdevice, &buseops, NULL);
}
