#include <limits.h>
#include <string.h>

#include "unity.h"

#ifndef __INTELLISENSE__
#include "mock_io.h"
#include "mock_backstore.h"
#include "mock_strongbox.h"
#endif
#include "unity.h"
#include "swappable.h"

#define BLFS_TEST_FLAKE_SIZE 512
#define BLFS_TEST_FLAKES_PER_NUGGET 64
#define BLFS_TEST_NUGGET_SIZE_BYTES BLFS_TEST_FLAKE_SIZE * BLFS_TEST_FLAKES_PER_NUGGET

static swappable_cipher_e test_ciphers_fn_crypt_data[] = {
    // sc_default,
    // sc_not_impl,
    sc_chacha8_neon,
    sc_chacha12_neon,
    sc_chacha20_neon,
    sc_chacha20,
    sc_salsa8,
    sc_salsa12,
    sc_salsa20,
    sc_aes128_ctr,
    sc_aes256_ctr,
    sc_hc128,
    sc_rabbit,
    sc_sosemanuk,
};

// ! Welcome back !

// ? Any new ciphers should be tested here in this file. You should also include
// ? tests that validate what sc_calculate_cipher_bytes_per_nugget calculates
// ? is what you expect IFF your cipher sets requested_md_bytes_per_nugget != 0.

// ? The *_handle and other functions that some ciphers expose accept a
// ? virtually infinite set of argument configurations and so must be tested
// ? individually. Add your tests for new advanced ciphers to this file.

uint8_t * global_buffer1 = NULL;

uint32_t flake_size;
uint_fast32_t flakes_per_nugget;
uint_fast32_t flake_index;
uint_fast32_t flake_end;
uint_fast32_t flake_internal_offset;
uint32_t mt_offset;
uint_fast32_t nugget_offset;
uint32_t first_affected_flake;
uint32_t nugget_internal_offset;
uint_fast32_t buffer_read_length;
uint_fast32_t buffer_write_length;

#define TRY_FN_CATCH_EXCEPTION(fn_call)           \
e_actual = EXCEPTION_NO_EXCEPTION;                \
Try                                               \
{                                                 \
    fn_call;                                      \
    TEST_FAIL();                                  \
}                                                 \
Catch(e_actual)                                   \
    TEST_ASSERT_EQUAL_HEX_MESSAGE(e_expected, e_actual, "Encountered an unsuspected error condition!");

void blfs_backstore_write_body_callback(blfs_backstore_t * backstore,
                                        const uint8_t * buffer,
                                        uint32_t length,
                                        uint64_t offset,
                                        int num_calls)
{
    (void) backstore;
    (void) offset;
    (void) num_calls;

    memcpy(global_buffer1 + offset - (nugget_offset * flake_size * flakes_per_nugget), buffer, length);
}

void setUp(void)
{
    if(sodium_init() == -1)
        exit(EXCEPTION_SODIUM_INIT_FAILURE);

    char buf[100] = { 0x00 };
    snprintf(buf, sizeof buf, "%s%s_%s", "blfs_level", STRINGIZE(BLFS_DEBUG_LEVEL), "test");

    if(dzlog_init(BLFS_CONFIG_ZLOG, buf))
        exit(EXCEPTION_ZLOG_INIT_FAILURE);
}

void tearDown(void)
{
    zlog_fini();
}

void test_crypt_data_algos_crypt_properly(void)
{
    int print = 0;

    for(size_t ri = 0, j = COUNT(test_ciphers_fn_crypt_data) * 2; ri < j; ++ri, print = !print)
    {
        size_t i = ri / 2;
        blfs_swappable_cipher_t sc;

        sc_set_cipher_ctx(&sc, test_ciphers_fn_crypt_data[i]);
        
        if(print)
            dzlog_notice("Testing %s (#%i)", sc.name, (int) test_ciphers_fn_crypt_data[i]);

        uint8_t data[20] = "20chardat20chardat!";
        uint8_t crypted_data[sizeof data] = { 0x00 };
        uint64_t kcs_keycount = 10242048;
        uint64_t nugget_internal_offset = 64;

        uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT] = {
            0xd9, 0x76, 0xff, 0x4c, 0xd9, 0xaa, 0x1, 0xea,
            0xa5, 0xad, 0xdc, 0x68, 0xcf, 0xe1, 0x8f, 0xc1
        };

        blfs_swappable_crypt(&sc, crypted_data, data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

        uint8_t crypted_data_round2[sizeof data] = { 0x00 };

        blfs_swappable_crypt(
            &sc,
            crypted_data_round2,
            crypted_data,
            sizeof data,
            nugget_key,
            kcs_keycount,
            nugget_internal_offset
        );

        TEST_ASSERT_EQUAL_MEMORY(data, crypted_data_round2, sizeof data);

        uint8_t crypted_data_round3[1] = { 0x00 };

        blfs_swappable_crypt(
            &sc,
            crypted_data_round3,
            data,
            sizeof crypted_data_round3,
            nugget_key,
            kcs_keycount,
            nugget_internal_offset
        );

        TEST_ASSERT_EQUAL_MEMORY(crypted_data, crypted_data_round3, sizeof crypted_data_round3);

        uint8_t crypted_data_round4[1] = { 0x00 };

        blfs_swappable_crypt(
            &sc,
            crypted_data_round4,
            crypted_data_round3,
            sizeof crypted_data_round4,
            nugget_key,
            kcs_keycount,
            nugget_internal_offset
        );

        TEST_ASSERT_EQUAL_MEMORY(data, crypted_data_round4, sizeof crypted_data_round4);
    }
}

void test_crypt_data_algos_with_BIGLY_inputs(void)
{
    for(size_t ri = 0, j = COUNT(test_ciphers_fn_crypt_data) * 2; ri < j; ++ri)
    {
        size_t i = ri / 2;
        blfs_swappable_cipher_t sc;

        sc_set_cipher_ctx(&sc, test_ciphers_fn_crypt_data[i]);
    
        uint8_t data[4096] = { 0x00 };
        randombytes_buf(data, sizeof data);

        uint8_t crypted_data[sizeof data] = { 0x00 };
        uint64_t kcs_keycount = 123456789101112;
        uint64_t nugget_internal_offset = 72;

        uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT] = {
            0xd9, 0x76, 0xff, 0x4c, 0xd9, 0xaa, 0x1, 0xea,
            0xa5, 0xad, 0xdc, 0x68, 0xcf, 0xe1, 0x8f, 0xc1
        };

        blfs_swappable_crypt(&sc, crypted_data, data, sizeof data, nugget_key, kcs_keycount, nugget_internal_offset);

        uint8_t crypted_data_round2[sizeof data] = { 0x00 };

        blfs_swappable_crypt(
            &sc,
            crypted_data_round2,
            crypted_data,
            sizeof data,
            nugget_key,
            kcs_keycount,
            nugget_internal_offset
        );

        TEST_ASSERT_EQUAL_MEMORY(data, crypted_data_round2, sizeof crypted_data_round2);
    }
}

void test_crypt_custom_algos_crypt_properly(void)
{
    TEST_IGNORE();
}

void test_crypt_custom_algos_with_BIGLY_inputs(void)
{
    TEST_IGNORE();
}

void test_aes256_xts_handles_basic_crypt_properly(void)
{
    blfs_swappable_cipher_t sc;

    flake_size = BLFS_TEST_FLAKE_SIZE;
    flakes_per_nugget = BLFS_TEST_FLAKES_PER_NUGGET;
    flake_index = 0;
    flake_end = 64;
    flake_internal_offset = 0;
    mt_offset = 50;
    nugget_offset = 50;
    // * 1 nugget size = 32768

    sc_set_cipher_ctx(&sc, sc_aes256_xts);

    TEST_ASSERT_EQUAL_INT32_MESSAGE(0, sc.requested_md_bytes_per_nugget, "requested metadata bytes per nugget init failed");
    uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT];
    uint8_t message[BLFS_TEST_FLAKE_SIZE*BLFS_TEST_FLAKES_PER_NUGGET];
    uint8_t ciphertext[sizeof message] = { 0 };
    uint8_t plaintext[sizeof message];
    uint8_t plaintext2[sizeof message];

    global_buffer1 = ciphertext;
    memset(ciphertext, 0x3A, sizeof ciphertext);

    srand(5);

    uint32_t i;

    for(i = 0; i < sizeof nugget_key; ++i)
        nugget_key[i] = rand();

    for(i = 0; i < sizeof message; ++i)
        message[i] = rand();

    buselfs_state_t buselfs_state;
    blfs_backstore_t backstore;
    blfs_keycount_t count;

    buselfs_state.backstore = &backstore;
    backstore.nugget_size_bytes = sizeof message;

    buffer_read_length = (uint_fast32_t) sizeof plaintext;
    buffer_write_length = (uint_fast32_t) sizeof message;

    for(uint32_t counter = flake_index; counter < flake_end; counter++)
    {
        update_in_merkle_tree_Expect(
            NULL,
            BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT,
            mt_offset + nugget_offset * flakes_per_nugget + counter,
            &buselfs_state
        );

        update_in_merkle_tree_IgnoreArg_data();

        blfs_backstore_write_body_ExpectAnyArgs();
        blfs_backstore_write_body_StubWithCallback(&blfs_backstore_write_body_callback);
        verify_in_merkle_tree_ExpectAnyArgs();
        verify_in_merkle_tree_ExpectAnyArgs();
    }

    sc.write_handle(
        message,
        (const buselfs_state_t *) &buselfs_state,
        buffer_write_length,
        flake_index,
        flake_end,
        flake_size,
        flakes_per_nugget,
        flake_internal_offset,
        mt_offset,
        nugget_key,
        nugget_offset,
        (const blfs_keycount_t *) &count
    );

    first_affected_flake = 0;
    nugget_internal_offset = 0;

    sc.read_handle(
        plaintext,
        (const buselfs_state_t *) &buselfs_state,
        buffer_read_length,
        flake_index,
        flake_end,
        first_affected_flake,
        flake_size,
        flakes_per_nugget,
        mt_offset,
        ciphertext,
        nugget_key,
        nugget_offset,
        nugget_internal_offset,
        (const blfs_keycount_t *) &count,
        true,
        true
    );

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(message, plaintext, sizeof message, "write-then-read failed");

    first_affected_flake = 0;
    nugget_internal_offset = 0;

    sc.read_handle(
        plaintext2,
        (const buselfs_state_t *) &buselfs_state,
        buffer_read_length,
        flake_index,
        flake_end,
        first_affected_flake,
        flake_size,
        flakes_per_nugget,
        mt_offset,
        ciphertext,
        nugget_key,
        nugget_offset,
        nugget_internal_offset,
        (const blfs_keycount_t *) &count,
        true,
        true
    );

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(plaintext, plaintext2, sizeof plaintext, "plaintext to plaintext2 match failed");

    uint8_t ciphertext_original[sizeof message];

    memcpy(ciphertext_original, ciphertext, sizeof ciphertext_original);
    memset(ciphertext, 0x3B, sizeof ciphertext_original);

    first_affected_flake = flake_index = 2;
    flake_end = 28;
    flake_internal_offset = 12;
    uint32_t from_the_back = 4;

    uint32_t nio_to_flake = flake_size * flake_index;
    nugget_internal_offset = nio_to_flake + flake_internal_offset;
    buffer_read_length = buffer_write_length = flake_size * flake_end - nugget_internal_offset - from_the_back;

    for(uint32_t counter = flake_index; counter < flake_end; counter++)
    {
        uint32_t sufx = counter * flake_size;

        if((flake_internal_offset && counter == flake_index) || (from_the_back && counter == flake_end - 1))
        {
            blfs_backstore_read_body_Expect(
                &backstore,
                NULL,
                flake_size,
                nugget_offset * (sizeof message) + sufx
            );
            
            blfs_backstore_read_body_IgnoreArg_buffer();
            blfs_backstore_read_body_ReturnArrayThruPtr_buffer((ciphertext_original + sufx), flake_size);
            verify_in_merkle_tree_ExpectAnyArgs();
            
        }

        update_in_merkle_tree_Expect(
            NULL,
            BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT,
            mt_offset + nugget_offset * flakes_per_nugget + counter,
            &buselfs_state
        );

        update_in_merkle_tree_IgnoreArg_data();

        blfs_backstore_write_body_ExpectAnyArgs();
        blfs_backstore_write_body_StubWithCallback(&blfs_backstore_write_body_callback);
    }

    sc.write_handle(
        message + nugget_internal_offset,
        (const buselfs_state_t *) &buselfs_state,
        buffer_write_length,
        flake_index,
        flake_end,
        flake_size,
        flakes_per_nugget,
        flake_internal_offset,
        mt_offset,
        nugget_key,
        nugget_offset,
        (const blfs_keycount_t *) &count
    );

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(
        ciphertext_original + nio_to_flake,
        ciphertext + nio_to_flake,
        buffer_write_length,
        "ciphertext_original to ciphertext match failed"
    );
}

void test_aes256_xts_handles_offset_crypt_properly(void)
{
    blfs_swappable_cipher_t sc;
    buselfs_state_t buselfs_state;

    flake_size = BLFS_TEST_FLAKE_SIZE;
    flakes_per_nugget = BLFS_TEST_FLAKES_PER_NUGGET;
    flake_index = 0;
    flake_end = 64;
    flake_internal_offset = 0;
    mt_offset = 50;
    nugget_offset = 50;
    // * 1 nugget size = 32768

    sc_set_cipher_ctx(&sc, sc_aes256_xts);
    sc_calculate_cipher_bytes_per_nugget(&sc, flakes_per_nugget, flake_size, sc.output_size_bytes);

    TEST_ASSERT_EQUAL_INT32_MESSAGE(0, sc.requested_md_bytes_per_nugget, "requested metadata bytes per nugget miscalculation");

    uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT];
    uint8_t message[BLFS_TEST_FLAKE_SIZE*BLFS_TEST_FLAKES_PER_NUGGET];
    uint8_t message2[sizeof message];
    uint8_t ciphertext[sizeof message] = { 0 };
    uint8_t ciphertext_original[sizeof message] = { 0 };
    uint8_t plaintext[sizeof message];

    memset(ciphertext_original, 0xF0, sizeof message);
    memset(plaintext, 0xF1, sizeof message);
    memset(message, 0xF2, sizeof message);
    memset(message2, 0xF3, sizeof message);

    global_buffer1 = ciphertext;
    memset(ciphertext, 0x3A, sizeof ciphertext);

    srand(5);

    uint32_t i;

    for(i = 0; i < sizeof nugget_key; ++i)
        nugget_key[i] = rand();

    for(i = 0; i < sizeof message; ++i)
    {
        message[i] = rand();
        message2[i] = rand();
    }

    blfs_backstore_t backstore;
    blfs_keycount_t count;

    buselfs_state.backstore = &backstore;
    backstore.nugget_size_bytes = sizeof message;

    buffer_read_length = (uint_fast32_t) sizeof plaintext;
    buffer_write_length = (uint_fast32_t) sizeof message;

    for(uint32_t counter = flake_index; counter < flake_end; counter++)
    {
        update_in_merkle_tree_Expect(
            NULL,
            BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT,
            mt_offset + nugget_offset * flakes_per_nugget + counter,
            &buselfs_state
        );

        update_in_merkle_tree_IgnoreArg_data();

        blfs_backstore_write_body_ExpectAnyArgs();
        blfs_backstore_write_body_StubWithCallback(&blfs_backstore_write_body_callback);
    }

    sc.write_handle(
        message,
        (const buselfs_state_t *) &buselfs_state,
        buffer_write_length,
        flake_index,
        flake_end,
        flake_size,
        flakes_per_nugget,
        flake_internal_offset,
        mt_offset,
        nugget_key,
        nugget_offset,
        (const blfs_keycount_t *) &count
    );

    memcpy(ciphertext_original, ciphertext, sizeof ciphertext_original);
    memset(ciphertext, 0x3B, sizeof ciphertext_original);

    first_affected_flake = flake_index = 2;
    flake_end = 28;
    flake_internal_offset = 12;
    uint32_t from_the_back = 4;

    uint32_t nio_to_flake = flake_size * flake_index;
    nugget_internal_offset = nio_to_flake + flake_internal_offset;
    buffer_read_length = buffer_write_length = flake_size * flake_end - nugget_internal_offset - from_the_back;

    for(uint32_t counter = flake_index; counter < flake_end; counter++)
    {
        uint32_t sufx = counter * flake_size;

        if((flake_internal_offset && counter == flake_index) || (from_the_back && counter == flake_end - 1))
        {
            blfs_backstore_read_body_Expect(
                &backstore,
                NULL,
                flake_size,
                nugget_offset * (sizeof message) + sufx
            );
            
            blfs_backstore_read_body_IgnoreArg_buffer();
            blfs_backstore_read_body_ReturnArrayThruPtr_buffer((ciphertext_original + sufx), flake_size);
            verify_in_merkle_tree_ExpectAnyArgs();
            
        }

        update_in_merkle_tree_Expect(
            NULL,
            BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT,
            mt_offset + nugget_offset * flakes_per_nugget + counter,
            &buselfs_state
        );

        update_in_merkle_tree_IgnoreArg_data();

        blfs_backstore_write_body_ExpectAnyArgs();
        blfs_backstore_write_body_StubWithCallback(&blfs_backstore_write_body_callback);
    }

    sc.write_handle(
        message2,
        (const buselfs_state_t *) &buselfs_state,
        buffer_write_length,
        flake_index,
        flake_end,
        flake_size,
        flakes_per_nugget,
        flake_internal_offset,
        mt_offset,
        nugget_key,
        nugget_offset,
        (const blfs_keycount_t *) &count
    );

    uint8_t ciphertext_amalgum[sizeof message];
    
    memset(ciphertext_amalgum, 0x3C, sizeof ciphertext_amalgum);
    memcpy(ciphertext_amalgum, ciphertext_original, sizeof ciphertext_original);
    memcpy(ciphertext_amalgum + nio_to_flake, ciphertext + nio_to_flake, buffer_write_length + from_the_back + flake_internal_offset);

    uint32_t original_nio2f = nio_to_flake;
    uint32_t original_fio = flake_internal_offset;
    uint32_t original_ftb = from_the_back;

    first_affected_flake = flake_index = 0;
    flake_end = 64;
    flake_internal_offset = 0;
    from_the_back = 0;
    
    nio_to_flake = flake_size * flake_index;
    nugget_internal_offset = nio_to_flake + flake_internal_offset;
    buffer_read_length = flake_size * flake_end - nugget_internal_offset - from_the_back;

    for(uint32_t counter = flake_index; counter < flake_end; counter++)
        verify_in_merkle_tree_ExpectAnyArgs();

    sc.read_handle(
        plaintext,
        (const buselfs_state_t *) &buselfs_state,
        buffer_read_length,
        flake_index,
        flake_end,
        first_affected_flake,
        flake_size,
        flakes_per_nugget,
        mt_offset,
        ciphertext_amalgum,
        nugget_key,
        nugget_offset,
        nugget_internal_offset,
        (const blfs_keycount_t *) &count,
        true,
        true
    );

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(
        message,
        plaintext,
        original_nio2f,
        "plaintext failed from^-to-nio match"
    );

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(
        message + original_nio2f,
        plaintext + original_nio2f,
        original_fio,
        "plaintext failed from-nio-to-fio match"
    );

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(
        message2,
        plaintext + original_nio2f + original_fio,
        buffer_write_length - original_fio,
        "plaintext failed from-fio-to-bwl match"
    );

    uint32_t offset = original_nio2f + original_fio + buffer_write_length;

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(
        message + offset,
        plaintext + offset,
        original_ftb,
        "plaintext failed from-bwl-to-ftb match"
    );

    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(
        message + offset + original_ftb,
        plaintext + offset + original_ftb,
        sizeof(message) - (offset + original_ftb),
        "plaintext failed from-ftb-to$ match"
    );
}

void test_freestyle_handles_crypt_properly(void)
{
    blfs_swappable_cipher_t sc;
    buselfs_state_t buselfs_state;
    blfs_backstore_t backstore;
    blfs_keycount_t count;
    swappable_cipher_e cipher;

    buselfs_state.backstore = &backstore;
    backstore.nugget_size_bytes = BLFS_TEST_NUGGET_SIZE_BYTES;
    buselfs_state.active_cipher = &sc;

    flake_size = backstore.flake_size_bytes = BLFS_TEST_FLAKE_SIZE;
    flakes_per_nugget = backstore.flakes_per_nugget = BLFS_TEST_FLAKES_PER_NUGGET;
    flake_index = 0;
    flake_end = 64;
    flake_internal_offset = 0;
    mt_offset = 127;
    nugget_offset = 50;
    
    backstore.md_real_offset = 500;
    backstore.num_nuggets = 60;

    swappable_cipher_e ciphers_under_test[] = { sc_freestyle_fast,  sc_freestyle_balanced, sc_freestyle_secure };

    for(uint32_t runs = 0, size = sizeof(ciphers_under_test)/sizeof(ciphers_under_test[0]); runs < size; ++runs)
    {
        cipher = ciphers_under_test[runs];

        sc_set_cipher_ctx(&sc, cipher);

        TEST_ASSERT_EQUAL_INT32_MESSAGE(0, sc.requested_md_bytes_per_nugget, "requested metadata bytes per nugget init failed");

        sc_calculate_cipher_bytes_per_nugget(&sc, flakes_per_nugget, flake_size, sc.output_size_bytes);

        TEST_ASSERT_EQUAL_INT32_MESSAGE(4608, sc.requested_md_bytes_per_nugget, "requested metadata bytes per nugget miscalculation");

        backstore.md_bytes_per_nugget = sc.requested_md_bytes_per_nugget + 1;

        dzlog_info("Testing %s", sc.name);
        fflush(stdout);

        uint8_t nugget_key[BLFS_CRYPTO_BYTES_KDF_OUT];
        uint8_t message[BLFS_TEST_NUGGET_SIZE_BYTES];
        uint8_t message2[sizeof message];
        uint8_t plaintext[sizeof message];
        uint8_t plaintext2[sizeof message];
        uint8_t plaintext3[sizeof message];
        uint8_t metadata[backstore.md_bytes_per_nugget];
        uint8_t ciphertext_original[sizeof message];
        uint8_t * ciphertext = global_buffer1 = malloc(BLFS_TEST_NUGGET_SIZE_BYTES * sizeof(uint8_t));

        memset(ciphertext, 0x3A, BLFS_TEST_NUGGET_SIZE_BYTES);
        memset(metadata, 0xDD, sizeof metadata);

        srand(5);

        uint32_t i;

        for(i = 0; i < sizeof nugget_key; ++i)
            nugget_key[i] = rand();

        for(i = 0; i < sizeof message; ++i)
        {
            message[i] = rand();
            message2[i] = rand();
        }

        buffer_read_length = (uint_fast32_t) sizeof plaintext;
        buffer_write_length = (uint_fast32_t) sizeof message;

        blfs_nugget_metadata_t meta;

        meta.data_length = backstore.md_bytes_per_nugget;
        meta.metadata_length = meta.data_length - 1;
        meta.metadata = metadata;
        meta.nugget_index = nugget_offset;
        meta.cipher_ident = sc.enum_id;

        // ? 2 writes + 3 reads
        blfs_open_nugget_metadata_ExpectAndReturn(&backstore, nugget_offset, &meta);
        blfs_open_nugget_metadata_ExpectAndReturn(&backstore, nugget_offset, &meta);
        blfs_open_nugget_metadata_ExpectAndReturn(&backstore, nugget_offset, &meta);
        blfs_open_nugget_metadata_ExpectAndReturn(&backstore, nugget_offset, &meta);
        blfs_open_nugget_metadata_ExpectAndReturn(&backstore, nugget_offset, &meta);

        for(uint32_t counter = flake_index; counter < flake_end; counter++)
        {
            // ? Encrypted write
            update_in_merkle_tree_Expect(
                NULL,
                BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT,
                mt_offset + nugget_offset * flakes_per_nugget + counter,
                &buselfs_state
            );

            update_in_merkle_tree_IgnoreArg_data();

            blfs_backstore_write_body_ExpectAnyArgs();
            blfs_backstore_write_body_StubWithCallback(&blfs_backstore_write_body_callback);

            // ? For the two reads
            verify_in_merkle_tree_ExpectAnyArgs();
            verify_in_merkle_tree_ExpectAnyArgs();
        }

        // ? Commit nugget metadata and hash to merkle tree (1 per write)

        blfs_commit_nugget_metadata_ExpectAnyArgs();
        update_in_merkle_tree_Expect(
            NULL,
            BLFS_CRYPTO_BYTES_STRUCT_HASH_OUT,
            1 + backstore.num_nuggets * 2 + (BLFS_HEAD_NUM_HEADERS - 3) + nugget_offset,
            &buselfs_state
        );

        update_in_merkle_tree_IgnoreArg_data();

        sc.write_handle(
            message,
            (const buselfs_state_t *) &buselfs_state,
            buffer_write_length,
            flake_index,
            flake_end,
            flake_size,
            flakes_per_nugget,
            flake_internal_offset,
            mt_offset,
            nugget_key,
            nugget_offset,
            (const blfs_keycount_t *) &count
        );

        first_affected_flake = 0;
        nugget_internal_offset = 0;

        sc.read_handle(
            plaintext,
            (const buselfs_state_t *) &buselfs_state,
            buffer_read_length,
            flake_index,
            flake_end,
            first_affected_flake,
            flake_size,
            flakes_per_nugget,
            mt_offset,
            ciphertext,
            nugget_key,
            nugget_offset,
            nugget_internal_offset,
            (const blfs_keycount_t *) &count,
            true,
            true
        );

        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(message, plaintext, sizeof message, "write-then-read failed");

        first_affected_flake = 0;
        nugget_internal_offset = 0;

        sc.read_handle(
            plaintext2,
            (const buselfs_state_t *) &buselfs_state,
            buffer_read_length,
            flake_index,
            flake_end,
            first_affected_flake,
            flake_size,
            flakes_per_nugget,
            mt_offset,
            ciphertext,
            nugget_key,
            nugget_offset,
            nugget_internal_offset,
            (const blfs_keycount_t *) &count,
            true,
            true
        );

        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(plaintext, plaintext2, sizeof plaintext, "plaintext to plaintext2 match failed");

        memcpy(ciphertext_original, ciphertext, sizeof ciphertext_original);
        memset(ciphertext, 0x3B, sizeof ciphertext_original);

        first_affected_flake = flake_index = 2;
        flake_end = 28;
        flake_internal_offset = 12;
        uint32_t from_the_back = 4;

        uint32_t nio_to_flake = flake_size * flake_index;
        nugget_internal_offset = nio_to_flake + flake_internal_offset;
        buffer_read_length = buffer_write_length = flake_size * flake_end - nugget_internal_offset - from_the_back;

        for(uint32_t counter = flake_index; counter < flake_end; counter++)
        {
            uint32_t sufx = counter * flake_size;

            if((flake_internal_offset && counter == flake_index) || (from_the_back && counter == flake_end - 1))
            {
                blfs_backstore_read_body_Expect(
                    &backstore,
                    NULL,
                    flake_size,
                    nugget_offset * (sizeof message) + sufx
                );
                
                blfs_backstore_read_body_IgnoreArg_buffer();
                blfs_backstore_read_body_ReturnArrayThruPtr_buffer((ciphertext_original + sufx), flake_size);
                verify_in_merkle_tree_ExpectAnyArgs();
                
            }

            update_in_merkle_tree_Expect(
                NULL,
                BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT,
                mt_offset + nugget_offset * flakes_per_nugget + counter,
                &buselfs_state
            );

            update_in_merkle_tree_IgnoreArg_data();

            blfs_backstore_write_body_ExpectAnyArgs();
            blfs_backstore_write_body_StubWithCallback(&blfs_backstore_write_body_callback);
        }

        // ? Commit nugget metadata and hash to merkle tree (1 per write)

        blfs_commit_nugget_metadata_ExpectAnyArgs();
        update_in_merkle_tree_Expect(
            NULL,
            BLFS_CRYPTO_BYTES_STRUCT_HASH_OUT,
            1 + backstore.num_nuggets * 2 + (BLFS_HEAD_NUM_HEADERS - 3) + nugget_offset,
            &buselfs_state
        );

        update_in_merkle_tree_IgnoreArg_data();

        sc.write_handle(
            message2,
            (const buselfs_state_t *) &buselfs_state,
            buffer_write_length,
            flake_index,
            flake_end,
            flake_size,
            flakes_per_nugget,
            flake_internal_offset,
            mt_offset,
            nugget_key,
            nugget_offset,
            (const blfs_keycount_t *) &count
        );

        uint8_t ciphertext_amalgum[sizeof ciphertext_original];
        
        memcpy(ciphertext_amalgum, ciphertext_original, sizeof ciphertext_original);
        memcpy(ciphertext_amalgum + nio_to_flake, ciphertext + nio_to_flake, buffer_write_length + from_the_back + flake_internal_offset);

        uint32_t original_nio2f = nio_to_flake;
        uint32_t original_fio = flake_internal_offset;
        uint32_t original_ftb = from_the_back;

        first_affected_flake = flake_index = 0;
        flake_end = 64;
        flake_internal_offset = 0;
        from_the_back = 0;
        
        nio_to_flake = flake_size * flake_index;
        nugget_internal_offset = nio_to_flake + flake_internal_offset;
        buffer_read_length = flake_size * flake_end - nugget_internal_offset - from_the_back;

        for(uint32_t counter = flake_index; counter < flake_end; counter++)
            verify_in_merkle_tree_ExpectAnyArgs();

        sc.read_handle(
            plaintext3,
            (const buselfs_state_t *) &buselfs_state,
            buffer_read_length,
            flake_index,
            flake_end,
            first_affected_flake,
            flake_size,
            flakes_per_nugget,
            mt_offset,
            ciphertext_amalgum,
            nugget_key,
            nugget_offset,
            nugget_internal_offset,
            (const blfs_keycount_t *) &count,
            true,
            true
        );

        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(
            message,
            plaintext3,
            original_nio2f,
            "plaintext3 failed from^-to-nio match"
        );

        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(
            message + original_nio2f,
            plaintext3 + original_nio2f,
            original_fio,
            "plaintext3 failed from-nio-to-fio match"
        );

        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(
            message2,
            plaintext3 + original_nio2f + original_fio,
            buffer_write_length - original_fio,
            "plaintext3 failed from-fio-to-bwl match"
        );

        uint32_t offset = original_nio2f + original_fio + buffer_write_length;

        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(
            message + offset,
            plaintext3 + offset,
            original_ftb,
            "plaintext3 failed from-bwl-to-ftb match"
        );

        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(
            message + offset + original_ftb,
            plaintext3 + offset + original_ftb,
            sizeof(message) - (offset + original_ftb),
            "plaintext3 failed from-ftb-to$ match"
        );
    }
}
