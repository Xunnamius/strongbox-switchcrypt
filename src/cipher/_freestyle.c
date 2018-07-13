#include "cipher/_freestyle.h"

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
            config->max_rounds = 24;
            config->hash_interval = 2;
            config->pepper_bits = 16;
            break;

        case FREESTYLE_SECURE:
            config->min_rounds = 20;
            config->max_rounds = 32;
            config->hash_interval = 1;
            config->pepper_bits = 32;
            break;
            
        default:
            Throw(EXCEPTION_UNKNOWN_FSTYLE_VARIANT);
    }
}

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

    // TODO:!
    // (void) intrablock_offset;
    // (void) num_blocks;
    // (void) block_read_upper_bound;

    // sc_context_t * sc_context = (sc_context_t *) context;

    // uint64_t counter = interblock_offset;
    // uint8_t stream_nonce[BLFS_CRYPTO_BYTES_FSTYLE_IV];

    // IFDEBUG(assert(sizeof(sc_context->kcs_keycount) + sizeof(counter) <= sizeof(stream_nonce)));

    // memset(stream_nonce, 0, sizeof(stream_nonce));
    // memcpy(stream_nonce, kcs_keycount_ptr, sizeof(sc_context->kcs_keycount));

    // IFDEBUG(assert(BLFS_CRYPTO_BYTES_FSTYLE_KEY == BLFS_CRYPTO_BYTES_KDF_OUT));

    // int min_rounds = 0;
    // int max_rounds = 0;
    // int hash_interval = 0;
    // int pepper_bits = 0;

    

    // freestyle_ctx crypt;

    // for(uint64_t i = 0; i < num_blocks; i++, counter++)
    // {
    //     // ! Needs to be more flexible taking into account changing constants like FSTYLE IV size et al
    //     memcpy(stream_nonce + sizeof(sc_context->kcs_keycount) - 4, (uint8_t *) &counter, sizeof(counter));
        
    //     if(backstore->read_state)
    //     {
    //         freestyle_init_encrypt(
    //             &crypt,
    //             sc_context->nugget_key,
    //             BLFS_CRYPTO_BYTES_FSTYLE_KEY * BITS_IN_A_BYTE,
    //             stream_nonce,
    //             min_rounds,
    //             max_rounds,
    //             hash_interval,
    //             pepper_bits
    //         );

    //         freestyle_encrypt_block(&crypt, )
    //     }

    //     else
    //     {
    //         freestyle_init_decrypt(
    //             &crypt,
    //             sc_context->nugget_key,
    //             BLFS_CRYPTO_BYTES_FSTYLE_KEY * BITS_IN_A_BYTE,
    //             stream_nonce,
    //             min_rounds,
    //             max_rounds,
    //             hash_interval,
    //             pepper_bits,

    //         );

    //         freestyle_decrypt_block(&crypt, stream_nonce, xor_str + (i * sc_context->output_size_bytes))
    //     }
    // }

    // for(uint64_t i = intrablock_offset, j = block_read_upper_bound, k = 0; i < j; ++i, ++k)
    // {
    //     IFDEBUG(assert(k < sc_context->data_length));
    //     sc_context->crypted_data[k] = sc_context->data[k] ^ xor_str[i];
    // }

    // hc128_init(&output_state, raw_key, stream_nonce);
    // hc128_extract(&output_state, xor_str + (i * sc_context->output_size_bytes));

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

    // TODO:!

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

    sc->crypt_data = NULL;
    sc->crypt_custom = NULL;
}
