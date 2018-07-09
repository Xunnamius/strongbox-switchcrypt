#include "cipher/_freestyle.h"

static void sc_generic_freestyle_impl(const char * output_name,
                                      uint64_t output_size_bytes,
                                      uint64_t key_size_bytes,
                                      freestyle_variant freestyle_configuration,
                                      uint8_t * crypted_data,
                                      const uint8_t * data,
                                      uint32_t data_length,
                                      const uint8_t * nugget_key,
                                      uint64_t kcs_keycount,
                                      uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    sc_context_t sc_context = {
        .output_name = output_name,
        .output_size_bytes = output_size_bytes,
        .crypted_data = crypted_data,
        .data = data,
        .data_length = data_length,
        .nugget_key = nugget_key,
        .kcs_keycount = kcs_keycount,
        .nugget_internal_offset = nugget_internal_offset,
        .crypt_handle = NULL,
        .data_handle = NULL,
        #ifndef __INTELLISENSE__
        .read_handle = NULL,
        .write_handle = LAMBDA(void,
            // TODO: !! freestyle_configuration
            (void * context,
             uint64_t interblock_offset,
             uint64_t intrablock_offset,
             uint64_t num_blocks,
             uint64_t zero_str_length,
             uint64_t block_read_upper_bound,
             const uint8_t * const kcs_keycount_ptr)
            {
                (void) intrablock_offset;
                (void) num_blocks;
                (void) block_read_upper_bound;

                sc_context_t * sc_context = (sc_context_t *) context;

                uint64_t counter = interblock_offset;
                uint8_t stream_nonce[BLFS_CRYPTO_BYTES_FSTYLE_IV];

                IFDEBUG(assert(sizeof(sc_context->kcs_keycount) + sizeof(counter) <= sizeof(stream_nonce)));

                memset(stream_nonce, 0, sizeof(stream_nonce));
                memcpy(stream_nonce, kcs_keycount_ptr, sizeof(sc_context->kcs_keycount));

                IFDEBUG(assert(BLFS_CRYPTO_BYTES_FSTYLE_KEY == BLFS_CRYPTO_BYTES_KDF_OUT));
                IFDEBUG(assert(backstore->read_state != backstore->write_state));

                int min_rounds = 0;
                int max_rounds = 0;
                int hash_interval = 0;
                int pepper_bits = 0;

                switch(freestyle_configuration)
                {
                    case FREESTYLE_FAST:
                        min_rounds = 8;
                        max_rounds = 20;
                        hash_interval = 4;
                        pepper_bits = 8;
                        break;

                    case FREESTYLE_BALANCED:
                        min_rounds = 12;
                        max_rounds = 24;
                        hash_interval = 2;
                        pepper_bits = 16;
                        break;

                    case FREESTYLE_SECURE:
                        min_rounds = 20;
                        max_rounds = 32;
                        hash_interval = 1;
                        pepper_bits = 32;
                        break;
                        
                    default:
                        Throw(EXCEPTION_UNKNOWN_FSTYLE_CONFIGURATION);
                }

                freestyle_ctx crypt;

                for(uint64_t i = 0; i < num_blocks; i++, counter++)
                {
                    // ! Needs to be more flexible taking into account changing constants like FSTYLE IV size et al
                    memcpy(stream_nonce + sizeof(sc_context->kcs_keycount) - 4, (uint8_t *) &counter, sizeof(counter));
                    
                    if(backstore->read_state)
                    {
                        freestyle_init_encrypt(
                            &crypt,
                            sc_context->nugget_key,
                            BLFS_CRYPTO_BYTES_FSTYLE_KEY * BITS_IN_A_BYTE,
                            stream_nonce,
                            min_rounds,
                            max_rounds,
                            hash_interval,
                            pepper_bits
                        );

                        freestyle_encrypt_block(&crypt, )
                    }

                    else
                    {
                        freestyle_init_decrypt(
                            &crypt,
                            sc_context->nugget_key,
                            BLFS_CRYPTO_BYTES_FSTYLE_KEY * BITS_IN_A_BYTE,
                            stream_nonce,
                            min_rounds,
                            max_rounds,
                            hash_interval,
                            pepper_bits,

                        );

                        freestyle_decrypt_block(&crypt, stream_nonce, xor_str + (i * sc_context->output_size_bytes))
                    }
                }

                for(uint64_t i = intrablock_offset, j = block_read_upper_bound, k = 0; i < j; ++i, ++k)
                {
                    IFDEBUG(assert(k < sc_context->data_length));
                    sc_context->crypted_data[k] = sc_context->data[k] ^ xor_str[i];
                }
            }
        ),

        hc128_init(&output_state, raw_key, stream_nonce);
        hc128_extract(&output_state, xor_str + (i * sc_context->output_size_bytes));
        #endif
    };

    sc_generic_impl(&sc_context);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
