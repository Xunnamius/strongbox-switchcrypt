#include "unity.h"
#include "strongbox.h"
#include "swappable.h"
#include "mmc.h"
#include "merkletree.h"
#include "mt_err.h"
#include "khash.h"

#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>

#include "_struts.h"

// ? Ye olde integration tests

// ! The passwords used for this test are always "t" (without the quotes, of
// ! course)
// !
// ! Note that these tests are leaky! Cache reduction logic was not included
// ! (it's not necessary outside tests)

#define TRY_FN_CATCH_EXCEPTION(fn_call)           \
e_actual = EXCEPTION_NO_EXCEPTION;                \
Try                                               \
{                                                 \
    fn_call;                                      \
    TEST_FAIL();                                  \
}                                                 \
Catch(e_actual)                                   \
    TEST_ASSERT_EQUAL_HEX_MESSAGE(e_expected, e_actual, "Encountered an unsuspected error condition!");

#define _TEST_BLFS_TPM_ID 1 // ! ensure different than prod value
#define BACKSTORE_FILE_PATH "/tmp/test.io.bin"

static int iofd;
static buselfs_state_t * buselfs_state;
static char blockdevice[BLFS_BACKSTORE_FILENAME_MAXLEN] = { 0x00 };
static blfs_swappable_cipher_t global_active_cipher;

static void open_real_backstore()
{
    free(buselfs_state->backstore);

    buselfs_state->backstore = blfs_backstore_open(BACKSTORE_FILE_PATH);

    // ? set to 8 to match the dummy data
    buselfs_state->backstore->md_bytes_per_nugget = 8;

    blfs_backstore_setup_actual_finish(buselfs_state->backstore);
}

static void make_fake_state()
{
    buselfs_state = malloc(sizeof *buselfs_state);

    buselfs_state->backstore                    = NULL;
    buselfs_state->is_cipher_swapping           = FALSE;
    buselfs_state->cache_nugget_keys            = kh_init(BLFS_KHASH_NUGGET_KEY_CACHE_NAME);
    buselfs_state->merkle_tree                  = mt_create();
    buselfs_state->default_password             = BLFS_DEFAULT_PASS;
    buselfs_state->rpmb_secure_index            = _TEST_BLFS_TPM_ID;
    buselfs_state->primary_cipher               = &global_active_cipher;
    buselfs_state->swap_cipher                  = buselfs_state->primary_cipher;

    sc_set_cipher_ctx(buselfs_state->primary_cipher, sc_default);
    blfs_initialize_queues(buselfs_state);

    buselfs_state->active_cipher_enum_id = buselfs_state->primary_cipher->enum_id;

    iofd = open(BACKSTORE_FILE_PATH, O_CREAT | O_RDWR | O_TRUNC, 0777);

    buselfs_state->backstore                          = malloc(sizeof *buselfs_state->backstore);
    buselfs_state->backstore->io_fd                   = iofd;
    buselfs_state->backstore->body_real_offset        = 180;
    buselfs_state->backstore->file_size_actual        = (uint64_t)(sizeof buffer_init_backstore_state);
    buselfs_state->backstore->md_default_cipher_ident = buselfs_state->primary_cipher->enum_id;

    // ? set to 8 to match the dummy data
    buselfs_state->backstore->md_bytes_per_nugget = 8;
    buselfs_state->primary_cipher->requested_md_bytes_per_nugget = buselfs_state->backstore->md_bytes_per_nugget - 1;
    buselfs_state->swap_cipher = buselfs_state->primary_cipher;

    blfs_backstore_write(buselfs_state->backstore, buffer_init_backstore_state, sizeof buffer_init_backstore_state, 0);

    uint8_t data_in[BLFS_CRYPTO_RPMB_BLOCK] = { 0x06, 0x07, 0x08, 0x09, 0x06, 0x07, 0x08, 0x09 };
    volatile CEXCEPTION_T e = EXCEPTION_NO_EXCEPTION;

    memset(data_in + 8, 0, sizeof(data_in) - 8);

    Try
    {
        rpmb_write_block(_TEST_BLFS_TPM_ID, data_in);
    }

    Catch(e)
    {
        if(e == EXCEPTION_RPMB_DOES_NOT_EXIST && BLFS_MANUAL_GV_FALLBACK != -1)
        {
            dzlog_warn("RPMB device is not able to be opened but BLFS_MANUAL_GV_FALLBACK (%i) is in effect; ignoring...",
                       BLFS_MANUAL_GV_FALLBACK);
        }

        else
            Throw(e);
    }
}

static void clear_tj()
{
    blfs_backstore_t * backstore = blfs_backstore_open_with_ctx(BACKSTORE_FILE_PATH, buselfs_state);

    blfs_tjournal_entry_t * entry0 = blfs_open_tjournal_entry(backstore, 0);
    blfs_tjournal_entry_t * entry1 = blfs_open_tjournal_entry(backstore, 1);
    blfs_tjournal_entry_t * entry2 = blfs_open_tjournal_entry(backstore, 2);

    memset(entry0->bitmask->mask, 0, entry0->data_length);
    memset(entry1->bitmask->mask, 0, entry1->data_length);
    memset(entry2->bitmask->mask, 0, entry2->data_length);

    blfs_commit_tjournal_entry(backstore, entry0);
    blfs_commit_tjournal_entry(backstore, entry1);
    blfs_commit_tjournal_entry(backstore, entry2);

    blfs_backstore_close(backstore);
}

static int is_sudo()
{
    return !geteuid();
}

void setUp(void)
{
    if(sodium_init() == -1)
        exit(EXCEPTION_SODIUM_INIT_FAILURE);

    char buf[100] = { 0x00 };
    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), "device_test");

    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        exit(EXCEPTION_ZLOG_INIT_FAILURE);

    if(BLFS_MANUAL_GV_FALLBACK == -1 && !is_sudo())
    {
        dzlog_fatal("Must be root!");
        exit(255);
    }

    make_fake_state();
}

void tearDown(void)
{
    mt_delete(buselfs_state->merkle_tree);

    mq_close(buselfs_state->qd_incoming);
    mq_close(buselfs_state->qd_outgoing);
    mq_unlink(BLFS_SV_QUEUE_INCOMING_NAME);
    mq_unlink(BLFS_SV_QUEUE_OUTGOING_NAME);

    if(!BLFS_DEFAULT_DISABLE_KEY_CACHING)
        kh_destroy(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys);

    free(buselfs_state);

    zlog_fini();
    close(iofd);
    unlink(BACKSTORE_FILE_PATH);
}

// *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***

// ! Also need to test a delete function to fix the memory leak issue as
// ! discussed in strongbox.h

/***void test_mq_empty_read_works(void)
{
    blfs_mq_msg_t msg = { .opcode = 1 };
    blfs_read_input_queue(buselfs_state, &msg);
    TEST_ASSERT_EQUAL_UINT(0, msg.opcode);
}

void test_mq_write_read_works(void)
{
    // ? Gonna swap the two descriptors since the two queues otherwise do not
    // ? overlap!
    buselfs_state_t fake_buselfs_state;
    fake_buselfs_state.qd_incoming = mq_open(BLFS_SV_QUEUE_OUTGOING_NAME, O_RDONLY | O_NONBLOCK, BLFS_SV_QUEUE_PERM);

    assert(fake_buselfs_state.qd_incoming > 0);

    blfs_mq_msg_t outgoing_msg = { .opcode = 10, .payload = "Payload" };
    blfs_write_output_queue(buselfs_state, &outgoing_msg, BLFS_SV_MESSAGE_DEFAULT_PRIORITY);

    blfs_mq_msg_t incoming_msg;
    blfs_read_input_queue(&fake_buselfs_state, &incoming_msg);

    TEST_ASSERT_EQUAL_UINT(outgoing_msg.opcode, incoming_msg.opcode);
    TEST_ASSERT_EQUAL_MEMORY(outgoing_msg.payload, incoming_msg.payload, BLFS_SV_MESSAGE_SIZE_BYTES - 1);
}

void test_adding_and_evicting_from_the_keycache_works_as_expected(void)
{
    free(buselfs_state->backstore);

    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        TEST_IGNORE_MESSAGE("BLFS_DEFAULT_DISABLE_KEY_CACHING is in effect, so this test will be skipped!");

    else
    {
        uint32_t nugget_index1 = 0;
        uint32_t nugget_index2 = 55;
        uint32_t nugget_index3 = 124;

        uint8_t expected_nugget_key1[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0xFF, 0xF0, 0x0F };
        uint8_t expected_nugget_key2[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0xC0, 0xAF, 0x44 };
        uint8_t expected_nugget_key3[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0xBE, 0xCD, 0x12 };

        uint8_t expected_flake_key1[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0xC0, 0xF1, 0x04 };
        uint8_t expected_flake_key2[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0xFD, 0xA0, 0xFE };
        uint8_t expected_flake_key3[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0xB4, 0xFC, 0xF2 };

        uint8_t actual_nugget_key1[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };
        uint8_t actual_nugget_key2[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };
        uint8_t actual_nugget_key3[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };

        uint8_t actual_flake_key1[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0x00 };
        uint8_t actual_flake_key2[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0x00 };
        uint8_t actual_flake_key3[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY] = { 0x00 };

        add_index_to_key_cache(buselfs_state, nugget_index1, expected_nugget_key1);
        add_index_to_key_cache(buselfs_state, nugget_index2, expected_nugget_key2);
        add_index_to_key_cache(buselfs_state, nugget_index3, expected_nugget_key3);

        get_nugget_key_using_index(actual_nugget_key1, buselfs_state, nugget_index1);
        get_nugget_key_using_index(actual_nugget_key2, buselfs_state, nugget_index2);
        get_nugget_key_using_index(actual_nugget_key3, buselfs_state, nugget_index3);

        add_keychain_to_key_cache(buselfs_state, nugget_index1, 7, 4, expected_flake_key1);
        add_keychain_to_key_cache(buselfs_state, nugget_index2, 8, 5, expected_flake_key2);
        add_keychain_to_key_cache(buselfs_state, nugget_index3, 9, 6, expected_flake_key3);

        get_flake_key_using_keychain(actual_flake_key1, buselfs_state, nugget_index1, 7, 4);
        get_flake_key_using_keychain(actual_flake_key2, buselfs_state, nugget_index2, 8, 5);
        get_flake_key_using_keychain(actual_flake_key3, buselfs_state, nugget_index3, 9, 6);

        TEST_ASSERT_EQUAL_MEMORY(expected_nugget_key1, actual_nugget_key1, BLFS_CRYPTO_BYTES_KDF_OUT);
        TEST_ASSERT_EQUAL_MEMORY(expected_nugget_key2, actual_nugget_key2, BLFS_CRYPTO_BYTES_KDF_OUT);
        TEST_ASSERT_EQUAL_MEMORY(expected_nugget_key3, actual_nugget_key3, BLFS_CRYPTO_BYTES_KDF_OUT);

        TEST_ASSERT_EQUAL_MEMORY(expected_flake_key1, actual_flake_key1, BLFS_CRYPTO_BYTES_KDF_OUT);
        TEST_ASSERT_EQUAL_MEMORY(expected_flake_key2, actual_flake_key2, BLFS_CRYPTO_BYTES_KDF_OUT);
        TEST_ASSERT_EQUAL_MEMORY(expected_flake_key3, actual_flake_key3, BLFS_CRYPTO_BYTES_KDF_OUT);
    }
}

// ! The password used was "t" but almost no matter what you input the test will
// ! win. Don't forget to also test using the correct password!
void test_blfs_soft_open_throws_exception_on_invalid_password(void)
{
    open_real_backstore();

    blfs_header_t * header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);
    memset(header->data, 0xFF, BLFS_HEAD_HEADER_BYTES_VERIFICATION);
    blfs_commit_header(buselfs_state->backstore, header);

    CEXCEPTION_T e_expected = EXCEPTION_BAD_PASSWORD;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION(blfs_soft_open(buselfs_state, (uint8_t)(0)));
    blfs_backstore_close(buselfs_state->backstore);
}

void test_blfs_soft_open_throws_exception_on_bad_init_header(void)
{
    open_real_backstore();

    blfs_header_t * header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_INITIALIZED);
    memset(header->data, 0xFF, BLFS_HEAD_HEADER_BYTES_INITIALIZED);
    blfs_commit_header(buselfs_state->backstore, header);

    CEXCEPTION_T e_expected = EXCEPTION_BACKSTORE_NOT_INITIALIZED;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION(blfs_soft_open(buselfs_state, (uint8_t)(0)));
    blfs_backstore_close(buselfs_state->backstore);
}

void test_blfs_soft_open_throws_exception_on_invalid_mtrh(void)
{
    uint8_t data_write[BLFS_HEAD_HEADER_BYTES_MTRH] = { 0xFF, 0xFF };
    blfs_backstore_write(buselfs_state->backstore, data_write, sizeof data_write, 20);

    open_real_backstore();

    CEXCEPTION_T e_expected = EXCEPTION_INTEGRITY_FAILURE;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    TRY_FN_CATCH_EXCEPTION(blfs_soft_open(buselfs_state, (uint8_t)(0)));
    blfs_backstore_close(buselfs_state->backstore);
}

void test_blfs_soft_open_does_not_throw_exception_if_ignore_flag_is_1(void)
{
    open_real_backstore();

    blfs_header_t * header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_MTRH);
    memset(header->data, 0xFF, BLFS_HEAD_HEADER_BYTES_MTRH);
    blfs_commit_header(buselfs_state->backstore, header);

    blfs_soft_open(buselfs_state, (uint8_t)(1));
    blfs_backstore_close(buselfs_state->backstore);
}

void test_blfs_soft_open_works_as_expected(void)
{
    open_real_backstore();

    blfs_soft_open(buselfs_state, (uint8_t)(0));

    // Ensure initial state is accurate

    TEST_ASSERT_EQUAL_STRING(BACKSTORE_FILE_PATH, buselfs_state->backstore->file_path);
    TEST_ASSERT_EQUAL_STRING("test.io.bin", buselfs_state->backstore->file_name);
    TEST_ASSERT_EQUAL_UINT(105, buselfs_state->backstore->kcs_real_offset);
    TEST_ASSERT_EQUAL_UINT(129, buselfs_state->backstore->tj_real_offset);
    TEST_ASSERT_EQUAL_UINT(132, buselfs_state->backstore->md_real_offset);
    TEST_ASSERT_EQUAL_UINT(156, buselfs_state->backstore->body_real_offset);
    TEST_ASSERT_EQUAL_UINT(48, buselfs_state->backstore->writeable_size_actual);
    TEST_ASSERT_EQUAL_UINT(16, buselfs_state->backstore->nugget_size_bytes);
    TEST_ASSERT_EQUAL_UINT(8, buselfs_state->backstore->flake_size_bytes);
    TEST_ASSERT_EQUAL_UINT(3, buselfs_state->backstore->num_nuggets);
    TEST_ASSERT_EQUAL_UINT(2, buselfs_state->backstore->flakes_per_nugget);
    TEST_ASSERT_EQUAL_UINT(204, buselfs_state->backstore->file_size_actual);


    blfs_header_t * header_version = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERSION);
    blfs_header_t * header_salt = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_SALT);
    blfs_header_t * header_mtrh = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_MTRH);
    blfs_header_t * header_tpmglobalver = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
    blfs_header_t * header_verification = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);
    blfs_header_t * header_numnuggets = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_NUMNUGGETS);
    blfs_header_t * header_flakespernugget = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET);
    blfs_header_t * header_flakesize_bytes = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES);
    blfs_header_t * header_initialized = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_INITIALIZED);

    uint8_t expected_ver[BLFS_HEAD_HEADER_BYTES_VERSION] = { 0xFF, 0xFF, 0xFF, 0xFF };
    uint8_t expected_salt[BLFS_HEAD_HEADER_BYTES_SALT] = {
        0x8f, 0xa2, 0x0d, 0x92, 0x35, 0xd6, 0xc2, 0x4c, 0xe4, 0xbc, 0x4f, 0x47,
        0xa4, 0xce, 0x69, 0xa8
    };

    uint8_t expected_tpmglobalver[BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER] = { 0x06, 0x07, 0x08, 0x09, 0x06, 0x07, 0x08, 0x09 };
    uint8_t expected_verification[BLFS_HEAD_HEADER_BYTES_VERIFICATION] = {
        0xa7, 0x35, 0x05, 0xed, 0x0a, 0x2c, 0x81, 0xf9, 0x74, 0xf9, 0xd4, 0xe7,
        0x59, 0xaf, 0x92, 0xca, 0xe7, 0x15, 0x52, 0x04, 0xed, 0xb1, 0xb5, 0x46,
        0x24, 0x18, 0x31, 0x7f, 0xfb, 0x84, 0x79, 0x1d
    };

    uint8_t nexpected_master_secret[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };
    uint8_t set_initialized[BLFS_HEAD_HEADER_BYTES_INITIALIZED] = { BLFS_HEAD_IS_INITIALIZED_VALUE };

    TEST_ASSERT_EQUAL_UINT(*(uint32_t *) expected_ver, *(uint32_t *) header_version->data);
    TEST_ASSERT_EQUAL_MEMORY(expected_salt, header_salt->data, BLFS_HEAD_HEADER_BYTES_SALT);
    TEST_ASSERT_EQUAL_MEMORY(buffer_init_backstore_state + 20, header_mtrh->data, BLFS_HEAD_HEADER_BYTES_MTRH);
    TEST_ASSERT_EQUAL_MEMORY(expected_tpmglobalver, header_tpmglobalver->data, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER);
    TEST_ASSERT_EQUAL_MEMORY(expected_verification, header_verification->data, BLFS_HEAD_HEADER_BYTES_VERIFICATION);
    TEST_ASSERT_EQUAL_UINT32(3, *(uint32_t *) header_numnuggets->data);
    TEST_ASSERT_EQUAL_UINT32(2, *(uint32_t *) header_flakespernugget->data);
    TEST_ASSERT_EQUAL_UINT32(8, *(uint32_t *) header_flakesize_bytes->data);
    TEST_ASSERT_EQUAL_MEMORY(set_initialized, header_initialized->data, BLFS_HEAD_HEADER_BYTES_INITIALIZED);

    // TODO: should we test for backstore->md_default_cipher_ident and *_md_* correctness?

    // Ensure remaining state is accurate

    TEST_ASSERT_TRUE(memcmp(buselfs_state->backstore->master_secret, nexpected_master_secret, BLFS_CRYPTO_BYTES_KDF_OUT) != 0);

    blfs_backstore_close(buselfs_state->backstore);
}

void test_blfs_soft_open_initializes_keycache_and_merkle_tree_properly(void)
{
    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        TEST_IGNORE_MESSAGE("BLFS_DEFAULT_DISABLE_KEY_CACHING is in effect, so this test will be skipped!");

    else
    {
        open_real_backstore();
        blfs_soft_open(buselfs_state, (uint8_t)(0));

        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "2"));
        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "3"));

        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||0||0"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||1||0"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "2||0||2"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "2||1||2"));

        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||0||2"));
        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||2||0"));
        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "3||||0"));

        blfs_header_t * version_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERSION);
        blfs_header_t * salt_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_SALT);
        blfs_header_t * tpmgv_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
        blfs_header_t * verification_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);
        blfs_header_t * numnuggets_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_NUMNUGGETS);
        blfs_header_t * flakespernugget_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET);
        blfs_header_t * flakesize_bytes_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES);

        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, tpmgv_header->data, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER, 0) == MT_SUCCESS);

        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, version_header->data, BLFS_HEAD_HEADER_BYTES_VERSION, 1) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, salt_header->data, BLFS_HEAD_HEADER_BYTES_SALT, 2) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, verification_header->data, BLFS_HEAD_HEADER_BYTES_VERIFICATION, 3) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, numnuggets_header->data, BLFS_HEAD_HEADER_BYTES_NUMNUGGETS, 4) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, flakespernugget_header->data, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET, 5) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, flakesize_bytes_header->data, BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES, 6) == MT_SUCCESS);

        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 8));
        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 10));

        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 11));
        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 13));

        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 14));
        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 19));

        TEST_ASSERT_FALSE(mt_exists(buselfs_state->merkle_tree, 20));
        blfs_backstore_close(buselfs_state->backstore);
    }
}

void test_blfs_run_mode_create_works_when_backstore_exists_already(void)
{
    blfs_run_mode_create(BACKSTORE_FILE_PATH, 4096, 2, 12, buselfs_state);
    blfs_backstore_t * backstore = buselfs_state->backstore;

    // Ensure initial state is accurate

    TEST_ASSERT_EQUAL_STRING(BACKSTORE_FILE_PATH, backstore->file_path);
    TEST_ASSERT_EQUAL_STRING("test.io.bin", backstore->file_name);
    TEST_ASSERT_EQUAL_UINT(105, backstore->kcs_real_offset);
    TEST_ASSERT_EQUAL_UINT(865, backstore->tj_real_offset);
    TEST_ASSERT_EQUAL_UINT(1055, backstore->md_real_offset);
    TEST_ASSERT_EQUAL_UINT(1815, backstore->body_real_offset);
    TEST_ASSERT_EQUAL_UINT(2280, backstore->writeable_size_actual);
    TEST_ASSERT_EQUAL_UINT(24, backstore->nugget_size_bytes);
    TEST_ASSERT_EQUAL_UINT(2, backstore->flake_size_bytes);
    TEST_ASSERT_EQUAL_UINT(12, backstore->flakes_per_nugget);
    TEST_ASSERT_EQUAL_UINT(95, backstore->num_nuggets);
    TEST_ASSERT_EQUAL_UINT(4096, backstore->file_size_actual);

    // Ensure headers are accurate

    blfs_header_t * header_version = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_VERSION);
    blfs_header_t * header_salt = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_SALT);
    blfs_header_t * header_mtrh = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_MTRH);
    blfs_header_t * header_tpmglobalver = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
    blfs_header_t * header_verification = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);
    blfs_header_t * header_numnuggets = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_NUMNUGGETS);
    blfs_header_t * header_flakespernugget = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET);
    blfs_header_t * header_flakesize_bytes = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES);
    blfs_header_t * header_initialized = blfs_open_header(backstore, BLFS_HEAD_HEADER_TYPE_INITIALIZED);

    uint8_t zero_salt[BLFS_HEAD_HEADER_BYTES_SALT] = { 0x00 };
    uint8_t zero_tpmglobalver[BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER] = { 0x00 };
    uint8_t zero_verification[BLFS_HEAD_HEADER_BYTES_VERIFICATION] = { 0x00 };
    uint8_t zero_master_secret[BLFS_CRYPTO_BYTES_KDF_OUT] = { 0x00 };
    uint8_t set_initialized[BLFS_HEAD_HEADER_BYTES_INITIALIZED] = { BLFS_HEAD_IS_INITIALIZED_VALUE };

    TEST_ASSERT_EQUAL_UINT32(BLFS_CURRENT_VERSION, *(uint32_t *) header_version->data);
    TEST_ASSERT_TRUE(memcmp(header_salt->data, zero_salt, BLFS_HEAD_HEADER_BYTES_SALT) != 0);
    TEST_ASSERT_TRUE(memcmp(header_mtrh->data, buffer_init_backstore_state + 20, BLFS_HEAD_HEADER_BYTES_MTRH) != 0);
    TEST_ASSERT_TRUE(memcmp(header_tpmglobalver->data, zero_tpmglobalver, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER) != 0);
    TEST_ASSERT_TRUE(memcmp(header_verification->data, zero_verification, BLFS_HEAD_HEADER_BYTES_VERIFICATION) != 0);
    TEST_ASSERT_EQUAL_UINT32(backstore->num_nuggets, *(uint32_t *) header_numnuggets->data);
    TEST_ASSERT_EQUAL_UINT32(backstore->flakes_per_nugget, *(uint32_t *) header_flakespernugget->data);
    TEST_ASSERT_EQUAL_UINT32(backstore->flake_size_bytes, *(uint32_t *) header_flakesize_bytes->data);
    TEST_ASSERT_EQUAL_MEMORY(set_initialized, header_initialized->data, BLFS_HEAD_HEADER_BYTES_INITIALIZED);

    // Ensure remaining state is accurate

    TEST_ASSERT_TRUE(memcmp(backstore->master_secret, zero_master_secret, BLFS_CRYPTO_BYTES_KDF_OUT) != 0);

    blfs_backstore_close(backstore);
}

void test_blfs_run_mode_create_works_when_backstore_DNE(void)
{
    unlink(BACKSTORE_FILE_PATH);
    blfs_run_mode_create(BACKSTORE_FILE_PATH, 4096, 2, 12, buselfs_state);

    blfs_backstore_t * backstore = buselfs_state->backstore;

    // Ensure initial state is accurate

    TEST_ASSERT_EQUAL_STRING(BACKSTORE_FILE_PATH, backstore->file_path);
    TEST_ASSERT_EQUAL_STRING("test.io.bin", backstore->file_name);
    TEST_ASSERT_EQUAL_UINT(105, backstore->kcs_real_offset);
    TEST_ASSERT_EQUAL_UINT(865, backstore->tj_real_offset);
    TEST_ASSERT_EQUAL_UINT(1055, backstore->md_real_offset);
    TEST_ASSERT_EQUAL_UINT(1815, backstore->body_real_offset);
    TEST_ASSERT_EQUAL_UINT(2280, backstore->writeable_size_actual);
    TEST_ASSERT_EQUAL_UINT(24, backstore->nugget_size_bytes);
    TEST_ASSERT_EQUAL_UINT(2, backstore->flake_size_bytes);
    TEST_ASSERT_EQUAL_UINT(12, backstore->flakes_per_nugget);
    TEST_ASSERT_EQUAL_UINT(95, backstore->num_nuggets);
    TEST_ASSERT_EQUAL_UINT(4096, backstore->file_size_actual);

    blfs_backstore_close(backstore);
}

void test_blfs_run_mode_create_initializes_keycache_and_merkle_tree_properly(void)
{
    free(buselfs_state->backstore);

    if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        TEST_IGNORE_MESSAGE("BLFS_DEFAULT_DISABLE_KEY_CACHING is in effect, so this test will be skipped!");

    else
    {
        blfs_run_mode_create(BACKSTORE_FILE_PATH, 4096, 2, 12, buselfs_state);

        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "2"));
        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "116"));

        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||0||0"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||10||0"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "115||0||0"));
        TEST_ASSERT(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "115||11||0"));

        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "116||0||0"));
        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||0||10"));
        TEST_ASSERT_FALSE(KHASH_CACHE_EXISTS(BLFS_KHASH_NUGGET_KEY_CACHE_NAME, buselfs_state->cache_nugget_keys, "0||12||0"));

        blfs_header_t * version_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERSION);
        blfs_header_t * salt_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_SALT);
        blfs_header_t * tpmgv_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_TPMGLOBALVER);
        blfs_header_t * verification_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_VERIFICATION);
        blfs_header_t * numnuggets_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_NUMNUGGETS);
        blfs_header_t * flakespernugget_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESPERNUGGET);
        blfs_header_t * flakesize_bytes_header = blfs_open_header(buselfs_state->backstore, BLFS_HEAD_HEADER_TYPE_FLAKESIZE_BYTES);

        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, tpmgv_header->data, BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER, 0) == MT_SUCCESS);

        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, version_header->data, BLFS_HEAD_HEADER_BYTES_VERSION, 1) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, salt_header->data, BLFS_HEAD_HEADER_BYTES_SALT, 2) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, verification_header->data, BLFS_HEAD_HEADER_BYTES_VERIFICATION, 3) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, numnuggets_header->data, BLFS_HEAD_HEADER_BYTES_NUMNUGGETS, 4) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, flakespernugget_header->data, BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET, 5) == MT_SUCCESS);
        TEST_ASSERT(mt_verify(buselfs_state->merkle_tree, flakesize_bytes_header->data, BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES, 6) == MT_SUCCESS);

        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 0));
        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 1 + (BLFS_HEAD_NUM_HEADERS - 3)));
        TEST_ASSERT(mt_exists(buselfs_state->merkle_tree, 1431));

        TEST_ASSERT_FALSE(mt_exists(buselfs_state->merkle_tree, 1432));

        blfs_backstore_close(buselfs_state->backstore);
    }
}

void test_strongbox_main_actual_throws_exception_if_wrong_argc(void)
{
    CEXCEPTION_T e_expected = EXCEPTION_MUST_HALT;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv[] = { "progname" };

    TRY_FN_CATCH_EXCEPTION(strongbox_main_actual(0, argv, blockdevice));
}

void test_strongbox_main_actual_throws_exception_if_bad_cmd(void)
{
    CEXCEPTION_T e_expected = EXCEPTION_UNKNOWN_MODE;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv[] = {
        "progname",
        "cmd",
        "device1"
    };
    TRY_FN_CATCH_EXCEPTION(strongbox_main_actual(3, argv, blockdevice));
}

void test_strongbox_main_actual_throws_exception_if_too_many_fpn(void)
{
    zlog_fini();

    CEXCEPTION_T e_expected = EXCEPTION_TOO_MANY_FLAKES_PER_NUGGET;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv[] = {
        "progname",
        "--flakes-per-nugget",
        "4000000000",
        "create",
        "device2"
    };

    TRY_FN_CATCH_EXCEPTION(strongbox_main_actual(5, argv, blockdevice));
}

void test_strongbox_main_actual_throws_exception_if_bad_numbers_given_as_args(void)
{
    CEXCEPTION_T e_expected = EXCEPTION_INVALID_FLAKES_PER_NUGGET;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv[] = {
        "progname",
        "--flakes-per-nugget",
        "10241024102410241024102410241024",
        "create",
        "device3"
    };

    TRY_FN_CATCH_EXCEPTION(strongbox_main_actual(5, argv, blockdevice));

    e_expected = EXCEPTION_INVALID_BACKSTORESIZE;
    e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv2[] = {
        "progname",
        "--backstore-size",
        "-5",
        "create",
        "device4"
    };

    TRY_FN_CATCH_EXCEPTION(strongbox_main_actual(5, argv2, blockdevice));

    e_expected = EXCEPTION_INVALID_BACKSTORESIZE;
    e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv3[] = {
        "progname",
        "--backstore-size",
        "40000000000",
        "create",
        "device5"
    };

    TRY_FN_CATCH_EXCEPTION(strongbox_main_actual(5, argv3, blockdevice));

    e_expected = EXCEPTION_INVALID_FLAKES_PER_NUGGET;
    e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv4[] = {
        "progname",
        "--flakes-per-nugget",
        "-5",
        "create",
        "device6"
    };

    TRY_FN_CATCH_EXCEPTION(strongbox_main_actual(5, argv4, blockdevice));

    e_expected = EXCEPTION_INVALID_FLAKES_PER_NUGGET;
    e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv5[] = {
        "progname",
        "--flakes-per-nugget",
        "5294967295",
        "create",
        "device7"
    };

    TRY_FN_CATCH_EXCEPTION(strongbox_main_actual(5, argv5, blockdevice));

    e_expected = EXCEPTION_INVALID_FLAKESIZE;
    e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv7[] = {
        "progname",
        "--flake-size",
        "-5",
        "create",
        "device8"
    };

    TRY_FN_CATCH_EXCEPTION(strongbox_main_actual(5, argv7, blockdevice));

    e_expected = EXCEPTION_INVALID_FLAKESIZE;
    e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv8[] = {
        "progname",
        "--flake-size",
        "40000000000",
        "create",
        "device9"
    };

    TRY_FN_CATCH_EXCEPTION(strongbox_main_actual(5, argv8, blockdevice));
}

void test_strongbox_main_actual_throws_exception_if_invalid_cipher(void)
{
    zlog_fini();

    CEXCEPTION_T e_expected = EXCEPTION_STRING_TO_CIPHER_FAILED;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv[] = {
        "progname",
        "--default-password",
        "--cipher",
        "fakecipher",
        "create",
        "device115"
    };

    TRY_FN_CATCH_EXCEPTION(strongbox_main_actual(6, argv, blockdevice));
}

void test_strongbox_main_actual_throws_exception_if_invalid_tpm_id(void)
{
    zlog_fini();

    CEXCEPTION_T e_expected = EXCEPTION_INVALID_TPM_ID;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv[] = {
        "progname",
        "--default-password",
        "--tpm-id",
        "fds",
        "create",
        "device115"
    };

    TRY_FN_CATCH_EXCEPTION(strongbox_main_actual(6, argv, blockdevice));

    e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv2[] = {
        "progname",
        "--default-password",
        "--tpm-id",
        "0",
        "create",
        "device115"
    };

    TRY_FN_CATCH_EXCEPTION(strongbox_main_actual(6, argv2, blockdevice));
}

void test_strongbox_main_actual_throws_exception_if_nonimpl_cipher(void)
{
    zlog_fini();

    CEXCEPTION_T e_expected = EXCEPTION_STRING_TO_CIPHER_FAILED;//EXCEPTION_SC_ALGO_NO_IMPL;
    volatile CEXCEPTION_T e_actual = EXCEPTION_NO_EXCEPTION;

    char * argv[] = {
        "progname",
        "--default-password",
        "--cipher",
        "sc_not_impl",
        "create",
        "device115"
    };

    TRY_FN_CATCH_EXCEPTION(strongbox_main_actual(6, argv, blockdevice));
}

// * All read and write tests should go below this line! *

void test_buse_read_works_as_expected(void)
{
    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t in_buffer1[1] = { 0x00 };
    uint64_t offset1 = 0;

    //blfs_nugget_metadata_t * meta = blfs_open_nugget_metadata(buselfs_state->backstore, nugget_offset);
    buse_read(in_buffer1, sizeof in_buffer1, offset1, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset1, in_buffer1, sizeof in_buffer1);

    uint8_t in_buffer2[16] = { 0x00 };
    uint64_t offset2 = 0;

    buse_read(in_buffer2, sizeof in_buffer2, offset2, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset2, in_buffer2, sizeof in_buffer2);

    uint8_t in_buffer3[20] = { 0x00 };
    uint64_t offset3 = 0;

    buse_read(in_buffer3, sizeof in_buffer3, offset3, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset3, in_buffer3, sizeof in_buffer3);

    uint8_t buffer4[20] = { 0x00 };
    uint64_t offset4 = 20;

    buse_read(buffer4, sizeof buffer4, offset4, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset4, buffer4, sizeof buffer4);

    uint8_t buffer5[48] = { 0x00 };
    uint64_t offset5 = 0;

    buse_read(buffer5, sizeof buffer5, offset5, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset5, buffer5, sizeof buffer5);

    uint8_t buffer6[1] = { 0x00 };
    uint64_t offset6 = 47;

    buse_read(buffer6, sizeof buffer6, offset6, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset6, buffer6, sizeof buffer6);

    uint8_t buffer7[35] = { 0x00 };
    uint64_t offset7 = 10;

    buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset7, buffer7, sizeof buffer7);

    uint8_t buffer8[20] = { 0x00 };
    uint64_t offset8 = 28;

    buse_read(buffer8, sizeof buffer8, offset8, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset8, buffer8, sizeof buffer8);

    uint8_t buffer9[8] = { 0x00 };
    uint64_t offset9 = 1;

    buse_read(buffer9, sizeof buffer9, offset9, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset9, buffer9, sizeof buffer9);
}

void test_buse_writeread_works_as_expected1(void)
{
    blfs_backstore_write(buselfs_state->backstore, alternate_mtrh_data, sizeof alternate_mtrh_data, 20);

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t in_buffer1[20] = { 0x00 };
    uint64_t offset1 = 28;

    buse_write(test_play_data + offset1, sizeof in_buffer1, offset1, (void *) buselfs_state);
    buse_read(in_buffer1, sizeof in_buffer1, offset1, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset1, in_buffer1, sizeof in_buffer1);
}

void test_buse_writeread_works_as_expected2(void)
{
    blfs_backstore_write(buselfs_state->backstore, alternate_mtrh_data, sizeof alternate_mtrh_data, 20);

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t in_buffer2[20] = { 0x00 };
    uint64_t offset2 = 28;

    buse_write(test_play_data + offset2, sizeof in_buffer2, offset2, (void *) buselfs_state);
    buse_read(in_buffer2, sizeof in_buffer2, offset2, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset2, in_buffer2, sizeof in_buffer2);
}

void test_buse_writeread_works_as_expected3(void)
{
    blfs_backstore_write(buselfs_state->backstore, alternate_mtrh_data, sizeof alternate_mtrh_data, 20);

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t in_buffer3[48] = { 0x00 };
    uint64_t offset3 = 0;

    buse_write(test_play_data + offset3, sizeof in_buffer3, offset3, (void *) buselfs_state);
    buse_read(in_buffer3, sizeof in_buffer3, offset3, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset3, in_buffer3, sizeof in_buffer3);
}

void test_buse_writeread_works_as_expected4(void)
{
    blfs_backstore_write(buselfs_state->backstore, alternate_mtrh_data, sizeof alternate_mtrh_data, 20);

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer4[8] = { 0x00 };
    uint64_t offset4 = 0;

    buse_write(test_play_data + offset4, sizeof buffer4, offset4, (void *) buselfs_state);
    buse_read(buffer4, sizeof buffer4, offset4, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset4, buffer4, sizeof buffer4);
}

// ? interflake
void test_buse_writeread_works_as_expected5(void)
{
    blfs_backstore_write(buselfs_state->backstore, alternate_mtrh_data, sizeof alternate_mtrh_data, 20);

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer5[8] = { 0x00 };
    uint64_t offset5 = 1;

    buse_write(test_play_data + offset5, sizeof buffer5, offset5, (void *) buselfs_state);
    buse_read(buffer5, sizeof buffer5, offset5, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset5, buffer5, sizeof buffer5);
}

void test_buse_writeread_works_as_expected6(void)
{
    blfs_backstore_write(buselfs_state->backstore, alternate_mtrh_data, sizeof alternate_mtrh_data, 20);

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer6[1] = { 0x00 };
    uint64_t offset6 = 47;

    buse_write(test_play_data + offset6, sizeof buffer6, offset6, (void *) buselfs_state);
    buse_read(buffer6, sizeof buffer6, offset6, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset6, buffer6, sizeof buffer6);
}

void test_buse_writeread_works_as_expected7(void)
{
    blfs_backstore_write(buselfs_state->backstore, alternate_mtrh_data, sizeof alternate_mtrh_data, 20);

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer7[1] = { 0x00 };
    uint64_t offset7 = 35;

    buse_write(test_play_data + offset7, sizeof buffer7, offset7, (void *) buselfs_state);
    buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset7, buffer7, sizeof buffer7);
}

void test_buse_writeread_works_as_expected8(void)
{
    blfs_backstore_write(buselfs_state->backstore, alternate_mtrh_data, sizeof alternate_mtrh_data, 20);

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer[8] = { 0x00 };
    uint64_t offset = 17;

    buse_write(test_play_data + offset, sizeof buffer, offset, (void *) buselfs_state);
    buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset, buffer, sizeof buffer);
}

// ? interflake
void test_buse_writeread_works_as_expected9(void)
{
    blfs_backstore_write(buselfs_state->backstore, alternate_mtrh_data, sizeof alternate_mtrh_data, 20);

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer[32] = { 0x00 };
    uint64_t offset = 0;

    buse_write(test_play_data + offset, sizeof buffer, offset, (void *) buselfs_state);
    buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset, buffer, sizeof buffer);
}

// ? interflake internugget
void test_buse_writeread_works_as_expected10(void)
{
    blfs_backstore_write(buselfs_state->backstore, alternate_mtrh_data, sizeof alternate_mtrh_data, 20);

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer[32] = { 0x00 };
    uint64_t offset = 1;

    buse_write(test_play_data + offset, sizeof buffer, offset, (void *) buselfs_state);
    buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset, buffer, sizeof buffer);
}

// ? interflake internugget
void test_buse_writeread_works_as_expected11(void)
{
    blfs_backstore_write(buselfs_state->backstore, alternate_mtrh_data, sizeof alternate_mtrh_data, 20);

    free(buselfs_state->backstore);

    clear_tj();

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer[46] = { 0x00 };
    uint64_t offset = 1;

    buse_write(test_play_data + offset, sizeof buffer, offset, (void *) buselfs_state);
    buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset, buffer, sizeof buffer);
}

// TODO: implement checking if the keycount increased instead of visual cues from debug output
// TODO: not all of these trigger rekeyings (some are just r/w tests)...???
void test_buse_write_dirty_write_triggers_rekeying1(void)
{
    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer[8] = { 0x00 };
    uint64_t offset = 17;

    buse_write(test_play_data + offset, sizeof buffer, offset, (void *) buselfs_state);
    buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset, buffer, sizeof buffer);
}

void test_buse_write_dirty_write_triggers_rekeying2(void)
{
    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer5[8] = { 0x00 };
    uint64_t offset5 = 1;

    buse_write(test_play_data + offset5, sizeof buffer5, offset5, (void *) buselfs_state);
    buse_read(buffer5, sizeof buffer5, offset5, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset5, buffer5, sizeof buffer5);
}

void test_buse_write_dirty_write_triggers_rekeying3(void)
{
    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer6[1] = { 0x00 };
    uint64_t offset6 = 47;

    buse_write(test_play_data + offset6, sizeof buffer6, offset6, (void *) buselfs_state);
    buse_read(buffer6, sizeof buffer6, offset6, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset6, buffer6, sizeof buffer6);
}

void test_buse_write_dirty_write_triggers_rekeying4(void)
{
    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer7[1] = { 0x00 };
    uint64_t offset7 = 35;

    buse_write(test_play_data + offset7, sizeof buffer7, offset7, (void *) buselfs_state);
    buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset7, buffer7, sizeof buffer7);
}

void test_buse_write_dirty_write_triggers_rekeying5(void)
{
    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer7[1] = { 0x00 };
    uint64_t offset7 = 0;

    buse_write(test_play_data + offset7, sizeof buffer7, offset7, (void *) buselfs_state);
    buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset7, buffer7, sizeof buffer7);
}

void test_buse_write_dirty_write_triggers_rekeying6(void)
{
    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer7[8] = { 0x00 };
    uint64_t offset7 = 0;

    buse_write(test_play_data + offset7, sizeof buffer7, offset7, (void *) buselfs_state);
    buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset7, buffer7, sizeof buffer7);
}

void test_buse_write_dirty_write_triggers_rekeying7(void)
{
    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer7[1] = { 0x00 };
    uint64_t offset7 = 47;

    buse_write(test_play_data + offset7, sizeof buffer7, offset7, (void *) buselfs_state);
    buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset7, buffer7, sizeof buffer7);
}

void test_buse_write_dirty_write_triggers_rekeying8(void)
{
    free(buselfs_state->backstore);

    blfs_run_mode_open(BACKSTORE_FILE_PATH, (uint8_t)(0), buselfs_state);

    uint8_t buffer7[8] = { 0x00 };
    uint64_t offset7 = 40;

    buse_write(test_play_data + offset7, sizeof buffer7, offset7, (void *) buselfs_state);
    buse_read(buffer7, sizeof buffer7, offset7, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY(test_play_data + offset7, buffer7, sizeof buffer7);
}

static void readwrite_quicktests()
{
    IFDEBUG(dzlog_notice("Running read/write quicktests (stage 1)..."));
    fflush(stdout);

    uint8_t expected_buffer1[4096];
    memset(&expected_buffer1, 0xCE, 4096);
    expected_buffer1[4095] = 0xAB;
    expected_buffer1[4094] = 0xAA;
    uint32_t offset = 0;

    for(; offset < 1024; offset++)
    {
        uint8_t buffer[sizeof expected_buffer1];

        char strbuf[100];
        snprintf(strbuf, sizeof strbuf, "loop offset: %"PRIu32, offset);

        buse_write(expected_buffer1, sizeof buffer, sizeof(buffer) * offset, (void *) buselfs_state);
        buse_read(buffer, sizeof buffer, sizeof(buffer) * offset, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected_buffer1, buffer, sizeof buffer, strbuf);
    }

    IFDEBUG(dzlog_notice("Running read/write quicktests (stage 2)..."));
    fflush(stdout);

    uint8_t expected_buffer2[5000] = { 0x00 };
    memset(&expected_buffer2, 0xFA, 5000);

    for(; offset < 2048; offset+=2)
    {
        uint8_t buffer[sizeof expected_buffer2];

        char strbuf[100];
        snprintf(strbuf, sizeof strbuf, "loop offset: %"PRIu32, offset);

        buse_write(expected_buffer2, sizeof buffer, sizeof(buffer) * offset, (void *) buselfs_state);
        buse_read(buffer, sizeof buffer, sizeof(buffer) * offset, (void *) buselfs_state);

        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected_buffer2, buffer, sizeof buffer, strbuf);
    }

    IFDEBUG(dzlog_notice("Running read/write quicktests (stage 3)..."));
    fflush(stdout);

    // Test end writes
    uint8_t buffer[sizeof expected_buffer1];
    offset = buselfs_state->backstore->writeable_size_actual - sizeof(expected_buffer1);

    char strbuf[100];
    snprintf(strbuf, sizeof strbuf, "loop offset (final): %"PRIu32, offset);

    buse_write(expected_buffer1, sizeof buffer, offset, (void *) buselfs_state);
    buse_read(buffer, sizeof buffer, offset, (void *) buselfs_state);

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected_buffer1, buffer, sizeof buffer, strbuf);
}

void test_strongbox_main_actual_creates(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "200",
        "create",
        "device_actual-112"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);
    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    TEST_ASSERT_EQUAL_UINT(209715200, buselfs_state->backstore->file_size_actual); // ? 200 MiB specified (209715200)

    readwrite_quicktests();
}


void test_strongbox_main_actual_does_not_throw_exception_if_valid_cipher(void)
{
    zlog_fini();

    char * argv[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "200",
        "--cipher",
        "sc_sosemanuk",
        "create",
        "device_actual-113"
    };

    int argc = sizeof(argv)/sizeof(argv[0]);

    strongbox_main_actual(argc, argv, blockdevice);
}

void test_strongbox_main_actual_does_not_throw_exception_if_valid_tpm_id(void)
{
    zlog_fini();

    char * argv[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "200",
        "--tpm-id",
        "115",
        "create",
        "device_actual-114"
    };

    int argc = sizeof(argv)/sizeof(argv[0]);

    strongbox_main_actual(argc, argv, blockdevice);
}

void test_strongbox_main_actual_creates_with_cipher_and_tpm(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "200",
        "--tpm-id",
        "115",
        "--cipher",
        "sc_salsa8",
        "create",
        "device_actual-115"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);
    readwrite_quicktests();
}

void test_strongbox_main_actual_creates_expected_buselfs_state(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--tpm-id",
        "115",
        "--cipher",
        "sc_aes256_xts",
        "--flake-size",
        "16384",
        "--flakes-per-nugget",
        "8",
        "create",
        "device_actual-116"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    TEST_ASSERT_EQUAL_UINT(sc_aes256_xts, buselfs_state->primary_cipher->enum_id);
    TEST_ASSERT_EQUAL_UINT(sc_aes256_xts, buselfs_state->swap_cipher->enum_id);
    TEST_ASSERT_EQUAL_UINT(115, buselfs_state->rpmb_secure_index);
    TEST_ASSERT_EQUAL_UINT(131072, buselfs_state->backstore->nugget_size_bytes);
    TEST_ASSERT_EQUAL_UINT(16384, buselfs_state->backstore->flake_size_bytes);
    TEST_ASSERT_EQUAL_UINT(1073741824, buselfs_state->backstore->file_size_actual); // ? Defaults to 1 GiB (1073741824)
    TEST_ASSERT_EQUAL_UINT(8191, buselfs_state->backstore->num_nuggets); // ? Also changes with the above ^^^
    TEST_ASSERT_EQUAL_UINT(8, buselfs_state->backstore->flakes_per_nugget);
    TEST_ASSERT_EQUAL_UINT(buselfs_state->primary_cipher->enum_id, buselfs_state->backstore->md_default_cipher_ident);
}

void test_strongbox_inits_with_requested_md_bytes_per_nugget(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "200",
        "--cipher",
        "sc_freestyle_fast",
        "create",
        "device_actual-117"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    TEST_ASSERT_EQUAL_UINT(buselfs_state->primary_cipher->requested_md_bytes_per_nugget + 1, buselfs_state->backstore->md_bytes_per_nugget);
    TEST_ASSERT_EQUAL_UINT(buselfs_state->swap_cipher->requested_md_bytes_per_nugget + 1, buselfs_state->backstore->md_bytes_per_nugget);
}

void test_strongbox_inits_with_requested_md_bytes_per_nugget2(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "200",
        "--swap-cipher",
        "sc_freestyle_fast",
        "create",
        "device_actual-117-2"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    blfs_swappable_cipher_t default_ctx;
    sc_set_cipher_ctx(&default_ctx, sc_default);

    TEST_ASSERT_EQUAL_UINT(1, buselfs_state->primary_cipher->requested_md_bytes_per_nugget + 1);
    TEST_ASSERT_EQUAL(default_ctx.enum_id, buselfs_state->active_cipher_enum_id);
    TEST_ASSERT_EQUAL(default_ctx.enum_id, buselfs_state->primary_cipher->enum_id);
    TEST_ASSERT_EQUAL(sc_freestyle_fast, buselfs_state->swap_cipher->enum_id);
    // ? The freestyle cipher's bigger requirements should make the number > 1
    TEST_ASSERT_EQUAL_UINT(buselfs_state->swap_cipher->requested_md_bytes_per_nugget + 1, buselfs_state->backstore->md_bytes_per_nugget);
}

void test_strongbox_inits_properly_with_1_md_bytes_per_nugget(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "200",
        "create",
        "device_actual-118"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    TEST_ASSERT_EQUAL_UINT(0, buselfs_state->primary_cipher->requested_md_bytes_per_nugget);
    TEST_ASSERT_EQUAL_UINT(0, buselfs_state->swap_cipher->requested_md_bytes_per_nugget);
    TEST_ASSERT_TRUE(buselfs_state->primary_cipher->enum_id == buselfs_state->swap_cipher->enum_id);
    TEST_ASSERT_EQUAL_UINT(1, buselfs_state->backstore->md_bytes_per_nugget);
}

void test_strongbox_inits_with_proper_swap_strategy_and_usecase1(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "200",
        "create",
        "device_actual-119"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    blfs_swappable_cipher_t default_ctx;
    sc_set_cipher_ctx(&default_ctx, sc_default);

    TEST_ASSERT_EQUAL(default_ctx.enum_id, buselfs_state->primary_cipher->enum_id);
    TEST_ASSERT_EQUAL_UINT(default_ctx.enum_id, buselfs_state->swap_cipher->enum_id);
    TEST_ASSERT_EQUAL_UINT(swap_default, buselfs_state->active_swap_strategy);
    TEST_ASSERT_EQUAL_UINT(uc_default, buselfs_state->active_usecase);
}

void test_strongbox_inits_with_proper_swap_strategy_and_usecase2(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "200",
        "--swap-strategy",
        "swap_mirrored",
        "--support-uc",
        "uc_lockdown",
        "create",
        "device_actual-120"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    TEST_ASSERT_EQUAL_UINT(swap_mirrored, buselfs_state->active_swap_strategy);
    TEST_ASSERT_EQUAL_UINT(uc_lockdown, buselfs_state->active_usecase);
}

void test_blfs_swap_nugget_to_active_cipher_updates_metadata(void)
{
    open_real_backstore();

    blfs_soft_open(buselfs_state, (uint8_t)(0));

    blfs_swappable_cipher_t swap_cipher;
    blfs_nugget_metadata_t * meta = blfs_open_nugget_metadata(buselfs_state->backstore, 0);

    TEST_ASSERT_EQUAL_UINT8(buselfs_state->primary_cipher->enum_id, meta->cipher_ident);

    sc_set_cipher_ctx(&swap_cipher, sc_chacha12_neon);

    buselfs_state->swap_cipher = &swap_cipher;
    buselfs_state->active_cipher_enum_id = buselfs_state->swap_cipher->enum_id;

    blfs_swap_nugget_to_active_cipher(SWAP_WHILE_READ, buselfs_state, 0, NULL, 0, 0);
    buselfs_state->is_cipher_swapping = FALSE; // ? Have to do this manually since we're hijacking the swap function

    TEST_ASSERT_EQUAL_UINT8(buselfs_state->swap_cipher->enum_id, meta->cipher_ident);

    buselfs_state->active_cipher_enum_id = buselfs_state->primary_cipher->enum_id;

    blfs_swap_nugget_to_active_cipher(SWAP_WHILE_READ, buselfs_state, 0, NULL, 0, 0);
    buselfs_state->is_cipher_swapping = FALSE; // ? Have to do this manually since we're hijacking the swap function

    TEST_ASSERT_EQUAL_UINT8(buselfs_state->primary_cipher->enum_id, meta->cipher_ident);
}***/

static void swap_readwrite_quicktest()
{
    buselfs_state_t fake_state = {
        .qd_outgoing = mq_open(BLFS_SV_QUEUE_INCOMING_NAME, O_WRONLY | O_NONBLOCK, BLFS_SV_QUEUE_PERM)
    };

    uint32_t nugget_size = buselfs_state->backstore->nugget_size_bytes;
    blfs_mq_msg_t swap_cmd_msg = { .opcode = 1 };

    uint8_t in_buffer1[nugget_size * 3];
    uint8_t in_buffer2[nugget_size * 2];
    uint8_t in_buffer3[nugget_size / 2];

    uint8_t out_buffer1[sizeof in_buffer1];
    uint8_t out_buffer2[sizeof in_buffer2];
    uint8_t out_buffer3[sizeof in_buffer3];

    memset(in_buffer1,  0x01, sizeof in_buffer1);
    memset(in_buffer2,  0x02, sizeof in_buffer2);
    memset(in_buffer3,  0x03, sizeof in_buffer3);
    memset(out_buffer1, 0x04, sizeof out_buffer1);
    memset(out_buffer2, 0x05, sizeof out_buffer2);
    memset(out_buffer3, 0x06, sizeof out_buffer3);

    blfs_nugget_metadata_t * meta[3] = {
        blfs_open_nugget_metadata(buselfs_state->backstore, 0),
        blfs_open_nugget_metadata(buselfs_state->backstore, 1),
        blfs_open_nugget_metadata(buselfs_state->backstore, 2)
    };

    // Ensure metadata is correct
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->primary_cipher->enum_id, meta[0]->cipher_ident);
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->primary_cipher->enum_id, meta[1]->cipher_ident);
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->primary_cipher->enum_id, meta[2]->cipher_ident);

    // Write and then read it and make sure it's correct
    IFDEBUG(dzlog_notice("(write)"));
    buse_write(in_buffer1, sizeof in_buffer1, 0, buselfs_state);
    IFDEBUG(dzlog_notice("(read)"));
    buse_read(out_buffer1, sizeof out_buffer1, 0, buselfs_state);

    // Verify read
    TEST_ASSERT_EQUAL_MEMORY(in_buffer1, out_buffer1, sizeof in_buffer1);

    // * (#1) Swap ciphers
    IFDEBUG(dzlog_notice("-- swap #1 --"));
    blfs_write_output_queue(&fake_state, &swap_cmd_msg, BLFS_SV_MESSAGE_DEFAULT_PRIORITY);

    memset(out_buffer1, 0x04, sizeof out_buffer1);

    // Read what was written earlier under the new cipher
    IFDEBUG(dzlog_notice("(read)"));
    buse_read(out_buffer1, sizeof out_buffer1, 0, buselfs_state);

    // Ensure metadata is correct
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->swap_cipher->enum_id, meta[0]->cipher_ident);
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->swap_cipher->enum_id, meta[1]->cipher_ident);
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->swap_cipher->enum_id, meta[2]->cipher_ident);

    // Verify read
    TEST_ASSERT_EQUAL_MEMORY(in_buffer1, out_buffer1, sizeof in_buffer1);

    // * (#2) Swap ciphers again
    IFDEBUG(dzlog_notice("-- swap #2 --"));
    blfs_write_output_queue(&fake_state, &swap_cmd_msg, BLFS_SV_MESSAGE_DEFAULT_PRIORITY);

    // Write and read again, this time partially in the first and third nuggets
    IFDEBUG(dzlog_notice("(write)"));
    buse_write(in_buffer2, sizeof in_buffer2, nugget_size / 2, buselfs_state);
    IFDEBUG(dzlog_notice("(read)"));
    buse_read(out_buffer2, sizeof out_buffer2, nugget_size / 2, buselfs_state);

    // Ensure metadata is correct
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->primary_cipher->enum_id, meta[0]->cipher_ident);
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->primary_cipher->enum_id, meta[1]->cipher_ident);
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->primary_cipher->enum_id, meta[2]->cipher_ident);

    // Verify read
    TEST_ASSERT_EQUAL_MEMORY(in_buffer2, out_buffer2, sizeof in_buffer2);

    // * (#3) Swap ciphers again
    IFDEBUG(dzlog_notice("-- swap #3 --"));
    blfs_write_output_queue(&fake_state, &swap_cmd_msg, BLFS_SV_MESSAGE_DEFAULT_PRIORITY);

    // Write and read again, this time partially in the third nugget
    IFDEBUG(dzlog_notice("(write)"));
    buse_write(in_buffer3, sizeof in_buffer3, nugget_size * 2 + nugget_size / 4, buselfs_state);
    IFDEBUG(dzlog_notice("(read)"));
    buse_read(out_buffer3, sizeof out_buffer3, nugget_size * 2 + nugget_size / 4, buselfs_state);

    // Ensure metadata is correct
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->primary_cipher->enum_id, meta[0]->cipher_ident);
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->primary_cipher->enum_id, meta[1]->cipher_ident);
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->swap_cipher->enum_id, meta[2]->cipher_ident);

    // Verify read
    TEST_ASSERT_EQUAL_MEMORY(in_buffer3, out_buffer3, sizeof in_buffer3);

    // * (#4) Swap ciphers once more
    IFDEBUG(dzlog_notice("-- swap #4 --"));
    blfs_write_output_queue(&fake_state, &swap_cmd_msg, BLFS_SV_MESSAGE_DEFAULT_PRIORITY);

    memset(out_buffer3, 0x06, sizeof out_buffer3);

    // Read what was written earlier under a new cipher
    IFDEBUG(dzlog_notice("(read)"));
    buse_read(out_buffer3, sizeof out_buffer3, nugget_size * 2 + nugget_size / 4, buselfs_state);

    // Ensure metadata is correct
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->primary_cipher->enum_id, meta[0]->cipher_ident);
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->primary_cipher->enum_id, meta[1]->cipher_ident);
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->primary_cipher->enum_id, meta[2]->cipher_ident);

    // Verify read
    TEST_ASSERT_EQUAL_MEMORY(in_buffer3, out_buffer3, sizeof in_buffer3);

    // * (#5) Swap ciphers one final time
    IFDEBUG(dzlog_notice("-- swap #5 --"));
    blfs_write_output_queue(&fake_state, &swap_cmd_msg, BLFS_SV_MESSAGE_DEFAULT_PRIORITY);

    memset(out_buffer1, 0x04, sizeof out_buffer1);

    // This time, write first, then read and compare
    IFDEBUG(dzlog_notice("(write)"));
    buse_write(in_buffer1, (sizeof in_buffer1) - 2, 1, buselfs_state);
    IFDEBUG(dzlog_notice("(read)"));
    buse_read(out_buffer1, (sizeof out_buffer1) - 2, 1, buselfs_state);

    // Verify read
    TEST_ASSERT_EQUAL_MEMORY(in_buffer1, out_buffer1, (sizeof in_buffer1) - 2);

    // Ensure metadata is correct
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->swap_cipher->enum_id, meta[0]->cipher_ident);
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->swap_cipher->enum_id, meta[1]->cipher_ident);
    TEST_ASSERT_EQUAL_UINT8(buselfs_state->swap_cipher->enum_id, meta[2]->cipher_ident);
}

/***void test_strongbox_can_cipher_switch1(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "50",
        "--cipher",
        "sc_chacha20",
        "--swap-cipher",
        "sc_chacha8_neon",
        "--swap-strategy",
        "swap_forward",
        "create",
        "device_actual-121"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);
    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    swap_readwrite_quicktest();
}***/

void test_strongbox_can_cipher_switch2(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "50",
        "--cipher",
        "sc_chacha20",
        "--swap-cipher",
        "sc_freestyle_fast",
        "--swap-strategy",
        "swap_forward",
        "create",
        "device_actual-122"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);
    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    swap_readwrite_quicktest();
}

/***void test_strongbox_can_cipher_switch3(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "50",
        "--cipher",
        "sc_freestyle_fast",
        "--swap-cipher",
        "sc_freestyle_secure",
        "--swap-strategy",
        "swap_forward",
        "create",
        "device_actual-124"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);
    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    swap_readwrite_quicktest();
}***/

/***void test_strongbox_works_when_mirrored1(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "50",
        "--cipher",
        "sc_chacha20",
        "--swap-cipher",
        "sc_chacha8_neon",
        "--swap-strategy",
        "swap_mirrored",
        "create",
        "device_actual-125"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    // TODO:! test cipher switching worked
    TEST_IGNORE();
}

void test_strongbox_works_when_mirrored2(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "50",
        "--cipher",
        "sc_chacha20",
        "--swap-cipher",
        "sc_freestyle_fast",
        "--swap-strategy",
        "swap_mirrored",
        "create",
        "device_actual-126"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    // TODO:! test cipher switching worked
    TEST_IGNORE();
}

void test_strongbox_works_when_mirrored3(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "50",
        "--cipher",
        "sc_freestyle_fast",
        "--swap-cipher",
        "sc_freestyle_secure",
        "--swap-strategy",
        "swap_mirrored",
        "create",
        "device_actual-128"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    // TODO:! test cipher switching worked
    TEST_IGNORE();
}

void test_usecase_uc_secure_regions(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "50",
        "--cipher",
        "sc_freestyle_fast",
        "--swap-cipher",
        "sc_freestyle_secure",
        "--swap-strategy",
        "swap_forward",
        "--support-uc",
        "uc_secure_regions",
        "create",
        "device_actual-129"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    // TODO:! test use case actually works!
    TEST_IGNORE();
}

void test_usecase_uc_fixed_energy(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "50",
        "--cipher",
        "sc_freestyle_fast",
        "--swap-cipher",
        "sc_freestyle_secure",
        "--swap-strategy",
        "swap_forward",
        "--support-uc",
        "uc_fixed_energy",
        "create",
        "device_actual-130"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    // TODO:! test use case actually works!
    TEST_IGNORE();
}

void test_usecase_uc_offset_slowdown(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "50",
        "--cipher",
        "sc_freestyle_fast",
        "--swap-cipher",
        "sc_freestyle_secure",
        "--swap-strategy",
        "swap_forward",
        "--support-uc",
        "uc_offset_slowdown",
        "create",
        "device_actual-131"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    // TODO:! test use case actually works!
    // TODO:! (test that uc is set properly for all these types of tests)
    TEST_IGNORE();
}

void test_usecase_uc_lockdown(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "50",
        "--cipher",
        "sc_freestyle_fast",
        "--swap-cipher",
        "sc_freestyle_secure",
        "--swap-strategy",
        "swap_forward",
        "--support-uc",
        "uc_lockdown",
        "create",
        "device_actual-132"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    // TODO:! test use case actually works!
    TEST_IGNORE();
}

void test_usecase_uc_auto_locations(void)
{
    zlog_fini();

    char * argv_create1[] = {
        "progname",
        "--default-password",
        "--backstore-size",
        "50",
        "--cipher",
        "sc_freestyle_fast",
        "--swap-cipher",
        "sc_freestyle_secure",
        "--swap-strategy",
        "swap_forward",
        "--support-uc",
        "uc_auto_locations",
        "create",
        "device_actual-133"
    };

    int argc = sizeof(argv_create1)/sizeof(argv_create1[0]);

    buselfs_state = strongbox_main_actual(argc, argv_create1, blockdevice);

    // TODO:! test use case actually works!
    TEST_IGNORE();
}***/
