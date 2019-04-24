#include "cipher/_freestyle.h"
#include "strongbox.h"

static int32_t INIT_COUNT = 0;

static void variant_as_configuration(freestyle_variant_configuration * config, freestyle_variant variant)
{
    switch(variant)
    {
        case FREESTYLE_FAST:
            config->min_rounds = 8;
            config->max_rounds = 20;
            config->hash_interval = 4;
            config->pepper_bits = 8;
            break;

        case FREESTYLE_BALANCED:
            config->min_rounds = 12;
            config->max_rounds = 28;
            config->hash_interval = 2;
            config->pepper_bits = 10;
            break;

        case FREESTYLE_SECURE:
            config->min_rounds = 20;
            config->max_rounds = 36;
            config->hash_interval = 1;
            config->pepper_bits = 12;
            break;

        default:
            Throw(EXCEPTION_UNKNOWN_FSTYLE_VARIANT);
    }
}

static uint32_t calc_expected_hashes_size_bytes(uint32_t flake_size_bytes, uint64_t output_size_bytes)
{
    // ? space for output hashes
    return CEIL(flake_size_bytes, output_size_bytes) * 2;
}

static uint32_t calc_handle(uint32_t flakes_per_nugget, uint32_t flake_size_bytes, uint64_t output_size_bytes)
{
    // ? {["flakes per nugget" * CEIL("max flksize" / "fstyle blk bytes") * 2] + ("flakes per nugget" * 28 "16 bit hashes" * 2)
    // ! The (1 "sc ident")} bytes are added by strongbox.c

    return flakes_per_nugget
        * calc_expected_hashes_size_bytes(flake_size_bytes, output_size_bytes)
        + flakes_per_nugget * BLFS_CRYPTO_BYTES_FSTYLE_INIT_HASHES; // ? space for init (16-bit input) hashes per flake
}

// TODO: DRY out the read and write handle functions, refactoring similar code
// TODO: back into the higher level read and write functions in strongbox.c
int sc_generic_freestyle_read_handle(freestyle_variant variant,
                                      uint8_t * buffer,
                                      const buselfs_state_t * buselfs_state,
                                      uint_fast32_t buffer_read_length,
                                      uint_fast32_t flake_index,
                                      uint_fast32_t flake_end,
                                      uint_fast32_t first_affected_flake,
                                      uint32_t flake_size,
                                      uint_fast32_t flakes_per_nugget,
                                      uint32_t mt_offset,
                                      const uint8_t * nugget_data,
                                      const uint8_t * nugget_key,
                                      uint_fast32_t nugget_offset,
                                      uint_fast32_t nugget_internal_offset,
                                      const blfs_keycount_t * count,
                                      int first_nugget,
                                      int last_nugget)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    const uint8_t * original_buffer = buffer;

    freestyle_variant_configuration config;
    variant_as_configuration(&config, variant);

    const blfs_nugget_metadata_t * meta = blfs_open_nugget_metadata(buselfs_state->backstore, nugget_offset);
    const blfs_swappable_cipher_t * cipher = meta->cipher_ident == buselfs_state->active_cipher_enum_id
                                             ? blfs_get_active_cipher(buselfs_state)
                                             : blfs_get_inactive_cipher(buselfs_state);

    IFDEBUG(assert(cipher->enum_id == meta->cipher_ident));
    IFDEBUG(assert(!meta->data_length || meta->metadata != NULL));

    uint32_t expected_hashes_size_bytes = calc_expected_hashes_size_bytes(
        buselfs_state->backstore->flake_size_bytes,
        cipher->output_size_bytes
    );

    for(uint_fast32_t i = 0; flake_index < flake_end; flake_index++, i++)
    {
        uint8_t flake_key[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY];
        uint8_t tag[BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT];

        if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        {
            IFDEBUG(dzlog_debug("KEY CACHING DISABLED!"));
            blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, count->keycount);
        }

        else
        {
            IFDEBUG(dzlog_debug("KEY CACHING ENABLED!"));
            get_flake_key_using_keychain(flake_key, buselfs_state, nugget_offset, flake_index, count->keycount);
        }

        blfs_poly1305_generate_tag(tag, nugget_data + (i * flake_size), flake_size, flake_key);
        verify_in_merkle_tree(tag, sizeof tag, mt_offset + nugget_offset * flakes_per_nugget + flake_index, buselfs_state);

        uint8_t flake_plaintext[flake_size];
        uint32_t first_flake_internal_offset = nugget_internal_offset - first_affected_flake * flake_size;

        // ! Potential endianness problem
        uint32_t nonce = nugget_offset * flakes_per_nugget + flake_index;
        uint8_t * nonce_ptr = (uint8_t *) &nonce;
        uint8_t stream_nonce[cipher->nonce_size_bytes];

        memset(stream_nonce, 0, sizeof stream_nonce);
        memcpy(stream_nonce, nonce_ptr, sizeof nonce);

        IFDEBUG(assert(cipher->key_size_bytes == BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY));
        IFDEBUG(assert(cipher->nonce_size_bytes >= sizeof nonce));

        freestyle_ctx crypt;

        uint16_t * init_hashes     = (uint16_t *)(meta->metadata + flake_index * BLFS_CRYPTO_BYTES_FSTYLE_INIT_HASHES);
        uint16_t * expected_hashes = (uint16_t *)(meta->metadata
            + buselfs_state->backstore->flakes_per_nugget * BLFS_CRYPTO_BYTES_FSTYLE_INIT_HASHES
            + flake_index * expected_hashes_size_bytes);

        freestyle_init_decrypt(
            &crypt,
            flake_key,
            sizeof(flake_key) * BITS_IN_A_BYTE,
            stream_nonce,
            config.min_rounds,
            config.max_rounds,
            config.hash_interval,
            config.pepper_bits,
            init_hashes,
            (uint8_t *) &INIT_COUNT
        );

        IFDEBUG(assert(flake_size == (uint16_t) flake_size));

        freestyle_decrypt(&crypt, nugget_data + (i * flake_size), flake_plaintext, flake_size, expected_hashes);

        if(first_nugget && flake_index == first_affected_flake)
        {
            uint32_t flake_internal_length = MIN(buffer_read_length, flake_size - first_flake_internal_offset);

            IFDEBUG(assert(first_flake_internal_offset + flake_internal_length <= flake_size));
            memcpy(buffer, flake_plaintext + first_flake_internal_offset, flake_internal_length);

            buffer += flake_internal_length;
        }

        else if(last_nugget && flake_index == flake_end - 1)
        {
            uint32_t flake_internal_end_length = buffer_read_length - (i * flake_size - (first_nugget ? first_flake_internal_offset : 0));

            IFDEBUG(assert(flake_internal_end_length <= flake_size));
            IFDEBUG(assert(flake_internal_end_length > 0));
            memcpy(buffer, flake_plaintext, flake_internal_end_length);

            buffer += flake_internal_end_length;
        }

        else
        {
            memcpy(buffer, flake_plaintext, flake_size);
            buffer += flake_size;
        }
    }

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));

    return buffer - original_buffer;
}

int sc_generic_freestyle_write_handle(freestyle_variant variant,
                                       const uint8_t * buffer,
                                       const buselfs_state_t * buselfs_state,
                                       uint_fast32_t buffer_write_length,
                                       uint_fast32_t flake_index,
                                       uint_fast32_t flake_end,
                                       uint32_t flake_size,
                                       uint_fast32_t flakes_per_nugget,
                                       uint_fast32_t flake_internal_offset,
                                       uint32_t mt_offset,
                                       const uint8_t * nugget_key,
                                       uint_fast32_t nugget_offset,
                                       const blfs_keycount_t * count)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    const uint8_t * original_buffer = buffer;

    freestyle_variant_configuration config;
    variant_as_configuration(&config, variant);

    // ! Maybe update and commit the MTRH here first and again later?
    uint_fast32_t flake_total_bytes_to_write = buffer_write_length;
    uint_fast32_t nugget_size = buselfs_state->backstore->nugget_size_bytes;

    blfs_nugget_metadata_t * meta = blfs_open_nugget_metadata(buselfs_state->backstore, nugget_offset);
    const blfs_swappable_cipher_t * cipher = meta->cipher_ident == buselfs_state->active_cipher_enum_id
                                             ? blfs_get_active_cipher(buselfs_state)
                                             : blfs_get_inactive_cipher(buselfs_state);

    IFDEBUG(assert(cipher->enum_id == meta->cipher_ident));
    IFDEBUG(assert(!meta->data_length || meta->metadata != NULL));

    uint32_t expected_hashes_size_bytes = calc_expected_hashes_size_bytes(
        buselfs_state->backstore->flake_size_bytes,
        cipher->output_size_bytes
    );

    for(; flake_index < flake_end; flake_index++)
    {
        uint_fast32_t flake_write_length = MIN(flake_total_bytes_to_write, flake_size - flake_internal_offset);

        uint16_t * init_hashes     = (uint16_t *)(meta->metadata + flake_index * BLFS_CRYPTO_BYTES_FSTYLE_INIT_HASHES);
        uint16_t * expected_hashes = (uint16_t *)(meta->metadata
            + buselfs_state->backstore->flakes_per_nugget * BLFS_CRYPTO_BYTES_FSTYLE_INIT_HASHES
            + flake_index * expected_hashes_size_bytes);

        // ! Potential endianness problem
        uint32_t nonce = nugget_offset * flakes_per_nugget + flake_index;
        uint8_t * nonce_ptr = (uint8_t *) &nonce;
        uint8_t stream_nonce[cipher->nonce_size_bytes];

        memset(stream_nonce, 0, sizeof stream_nonce);
        memcpy(stream_nonce, nonce_ptr, sizeof nonce);

        IFDEBUG(assert(cipher->key_size_bytes == BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY));
        IFDEBUG(assert(cipher->nonce_size_bytes >= sizeof nonce));

        IFDEBUG(dzlog_debug("flake_write_length: %"PRIuFAST32, flake_write_length));
        IFDEBUG(dzlog_debug("flake_index: %"PRIuFAST32, flake_index));
        IFDEBUG(dzlog_debug("flake_end: %"PRIuFAST32, flake_end));

        uint8_t flake_data[flake_size];
        uint8_t flake_out[flake_size];
        IFDEBUG(memset(flake_data, 0x3D, flake_size));
        IFDEBUG(memset(flake_out, 0x3E, flake_size));

        // ! Data to write isn't aligned and/or is smaller than
        // ! flake_size, so we need to verify its integrity
        if(flake_internal_offset != 0 || flake_internal_offset + flake_write_length < flake_size)
        {
            // ! This code should NEVER RUN if we're in the middle of cipher
            // ! switching!
            IFDEBUG(assert(!buselfs_state->is_cipher_swapping));

            IFDEBUG(dzlog_debug("UNALIGNED! Write flake requires verification"));

            // Read in the entire flake
            blfs_backstore_read_body(buselfs_state->backstore,
                                    flake_data,
                                    flake_size,
                                    nugget_offset * nugget_size + flake_index * flake_size);

            // Generate a local flake key
            uint8_t local_flake_key[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY];
            uint8_t local_tag[BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT];

            if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
            {
                IFDEBUG(dzlog_debug("KEY CACHING DISABLED!"));
                blfs_poly1305_key_from_data(local_flake_key, nugget_key, flake_index, count->keycount);
            }

            else
            {
                IFDEBUG(dzlog_debug("KEY CACHING ENABLED!"));
                get_flake_key_using_keychain(local_flake_key, buselfs_state, nugget_offset, flake_index, count->keycount);
            }

            // Generate tag
            blfs_poly1305_generate_tag(local_tag, flake_data, flake_size, local_flake_key);

            // Check tag in Merkle Tree
            verify_in_merkle_tree(local_tag, sizeof local_tag, mt_offset + nugget_offset * flakes_per_nugget + flake_index, buselfs_state);
        }

        IFDEBUG(dzlog_debug("*complete* flake_data (initial 64 bytes):"));
        IFDEBUG(hdzlog_debug(flake_data, MIN(64U, flake_size)));

        uint8_t flake_key[BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY];
        uint8_t tag[BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT];

        if(BLFS_DEFAULT_DISABLE_KEY_CACHING)
        {
            IFDEBUG(dzlog_debug("KEY CACHING DISABLED!"));
            blfs_poly1305_key_from_data(flake_key, nugget_key, flake_index, count->keycount);
        }

        else
        {
            IFDEBUG(dzlog_debug("KEY CACHING ENABLED!"));
            get_flake_key_using_keychain(flake_key, buselfs_state, nugget_offset, flake_index, count->keycount);
        }

        if(flake_internal_offset != 0 || flake_internal_offset + flake_write_length < flake_size)
        {
            // ! This code should NEVER RUN if we're in the middle of cipher
            // ! switching!
            IFDEBUG(assert(!buselfs_state->is_cipher_swapping));

            freestyle_ctx decrypt;

            freestyle_init_decrypt(
                &decrypt,
                flake_key,
                sizeof(flake_key) * BITS_IN_A_BYTE,
                stream_nonce,
                config.min_rounds,
                config.max_rounds,
                config.hash_interval,
                config.pepper_bits,
                init_hashes,
                (uint8_t *) &INIT_COUNT
            );

            IFDEBUG(assert(flake_size == (uint16_t) flake_size));

            freestyle_decrypt(&decrypt, flake_data, flake_out, flake_size, expected_hashes);
            memcpy(flake_data, flake_out, flake_size);
        }

        IFDEBUG(dzlog_debug("flake_write_length: %"PRIuFAST32, flake_write_length));
        memcpy(flake_data + flake_internal_offset, buffer, flake_write_length);

        freestyle_ctx encrypt;

        freestyle_init_encrypt(
            &encrypt,
            flake_key,
            sizeof(flake_key) * BITS_IN_A_BYTE,
            stream_nonce,
            config.min_rounds,
            config.max_rounds,
            config.hash_interval,
            config.pepper_bits,
            (uint8_t *) &INIT_COUNT
        );

        freestyle_encrypt(&encrypt, flake_data, flake_out, flake_size, expected_hashes);

        memcpy(init_hashes, encrypt.init_hash, BLFS_CRYPTO_BYTES_FSTYLE_INIT_HASHES);

        blfs_poly1305_generate_tag(tag, flake_out, flake_size, flake_key);

        IFDEBUG(dzlog_debug("flake_key (initial 64 bytes):"));
        IFDEBUG(hdzlog_debug(flake_key, MIN(64U, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY)));

        IFDEBUG(dzlog_debug("tag (initial 64 bytes):"));
        IFDEBUG(hdzlog_debug(tag, MIN(64U, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT)));

        IFDEBUG(dzlog_debug("update_in_merkle_tree calculated offset: %"PRIuFAST32,
                            mt_offset + nugget_offset * flakes_per_nugget + flake_index));

        update_in_merkle_tree(tag, sizeof tag, mt_offset + nugget_offset * flakes_per_nugget + flake_index, buselfs_state);

        blfs_backstore_write_body(buselfs_state->backstore,
                                  flake_out,
                                  flake_size,
                                  nugget_offset * nugget_size + flake_index * flake_size);

        IFDEBUG(dzlog_debug("blfs_backstore_write_body input (initial 64 bytes):"));
        IFDEBUG(hdzlog_debug(flake_out, MIN(64U, flake_size)));

        flake_internal_offset = 0;

        IFDEBUG(assert(flake_total_bytes_to_write >= flake_write_length));

        flake_total_bytes_to_write -= flake_write_length;
        buffer += flake_write_length;
    }

    assert(meta->metadata_length > 0);

    blfs_commit_nugget_metadata(buselfs_state->backstore, meta);

    uint8_t data[meta->data_length];
    uint8_t hash[BLFS_CRYPTO_BYTES_STRUCT_HASH_OUT];

    memcpy(data, &(meta->cipher_ident), 1);
    memcpy(data + 1, meta->metadata, meta->metadata_length);

    blfs_chacha20_struct_hash(hash, data, meta->data_length, buselfs_state->backstore->master_secret);

    // ! Update this if you add new layers to StrongBox ahead of the metadata layer
    // TODO: add another more flexible mt_calculate_* function to
    // TODO: strongbox.c that can encapsulate these calculations
    update_in_merkle_tree(
        hash,
        sizeof hash,
        1 + buselfs_state->backstore->num_nuggets * 2 + (BLFS_HEAD_NUM_HEADERS - 3) + nugget_offset,
        buselfs_state
    );

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));

    return buffer - original_buffer;
}

void sc_impl_freestyle(blfs_swappable_cipher_t * sc)
{
    sc->name = "Freestyle (partially initialized)";
    sc->enum_id = 0;

    sc->key_size_bytes = BLFS_CRYPTO_BYTES_FSTYLE_KEY;
    sc->nonce_size_bytes = BLFS_CRYPTO_BYTES_FSTYLE_IV;
    sc->output_size_bytes = BLFS_CRYPTO_BYTES_FSTYLE_BLOCK;

    sc->calc_handle = &calc_handle;
}
