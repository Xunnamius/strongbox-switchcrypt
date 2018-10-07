#include "cipher/aes256_xts.h"
#include "strongbox.h"
#include "backstore.h"

// ? With AES-XTS, we treat each flake as a sector!

static int read_handle(uint8_t * buffer,
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
    uint8_t * original_buffer = buffer;

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

        blfs_aesxts_decrypt(flake_plaintext,
                            nugget_data + (i * flake_size),
                            flake_size,
                            flake_key,
                            nugget_offset * flakes_per_nugget + flake_index);

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

    return buffer - original_buffer;
}

static int write_handle(const uint8_t * buffer,
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
    const uint8_t * original_buffer = buffer;

    // ! Maybe update and commit the MTRH here first and again later?
    uint_fast32_t flake_total_bytes_to_write = buffer_write_length;
    uint_fast32_t nugget_size = buselfs_state->backstore->nugget_size_bytes;

    for(uint_fast32_t i = 0; flake_index < flake_end; flake_index++, i++)
    {
        uint_fast32_t flake_write_length = MIN(flake_total_bytes_to_write, flake_size - flake_internal_offset);

        IFDEBUG(dzlog_debug("flake_write_length: %"PRIuFAST32, flake_write_length));
        IFDEBUG(dzlog_debug("flake_index: %"PRIuFAST32, flake_index));
        IFDEBUG(dzlog_debug("flake_end: %"PRIuFAST32, flake_end));

        uint8_t flake_data[flake_size];
        IFDEBUG(memset(flake_data, 0x3D, flake_size));

        // ! Data to write isn't aligned and/or is smaller than
        // ! flake_size, so we need to verify its integrity
        if(flake_internal_offset != 0 || flake_internal_offset + flake_write_length < flake_size)
        {
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
            blfs_aesxts_decrypt(flake_data,
                                flake_data,
                                flake_size,
                                flake_key,
                                nugget_offset * flakes_per_nugget + flake_index);
        }

        IFDEBUG(dzlog_debug("flake_write_length: %"PRIuFAST32, flake_write_length));
        memcpy(flake_data + flake_internal_offset, buffer, flake_write_length);

        blfs_aesxts_encrypt(flake_data,
                            flake_data,
                            flake_size,
                            flake_key,
                            nugget_offset * flakes_per_nugget + flake_index);

        blfs_poly1305_generate_tag(tag, flake_data, flake_size, flake_key);

        IFDEBUG(dzlog_debug("flake_key (initial 64 bytes):"));
        IFDEBUG(hdzlog_debug(flake_key, MIN(64U, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY)));

        IFDEBUG(dzlog_debug("tag (initial 64 bytes):"));
        IFDEBUG(hdzlog_debug(tag, MIN(64U, BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT)));

        IFDEBUG(dzlog_debug("update_in_merkle_tree calculated offset: %"PRIuFAST32,
                            mt_offset + nugget_offset * flakes_per_nugget + flake_index));

        update_in_merkle_tree(tag, sizeof tag, mt_offset + nugget_offset * flakes_per_nugget + flake_index, buselfs_state);

        blfs_backstore_write_body(buselfs_state->backstore,
                                  flake_data,
                                  flake_size,
                                  nugget_offset * nugget_size + flake_index * flake_size);

        IFDEBUG(dzlog_debug("blfs_backstore_write_body input (initial 64 bytes):"));
        IFDEBUG(hdzlog_debug(flake_data, MIN(64U, flake_size)));

        flake_internal_offset = 0;

        IFDEBUG(assert(flake_total_bytes_to_write >= flake_write_length));

        flake_total_bytes_to_write -= flake_write_length;
        buffer += flake_write_length;
    }

    return buffer - original_buffer;
}

void sc_impl_aes256_xts(blfs_swappable_cipher_t * sc)
{
    sc->name = "256-bit AES in XTS mode";
    sc->enum_id = sc_aes256_xts;

    sc->key_size_bytes = 0;
    sc->nonce_size_bytes = 0;
    sc->output_size_bytes = 0;

    sc->read_handle = &read_handle;
    sc->write_handle = &write_handle;
    sc->crypt_data = NULL;
    sc->crypt_custom = NULL;
}
