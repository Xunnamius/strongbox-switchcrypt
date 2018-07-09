#include "cipher/rabbit.h"

void sc_impl_rabbit(uint8_t * crypted_data,
                    const uint8_t * data,
                    uint32_t data_length,
                    const uint8_t * nugget_key,
                    uint64_t kcs_keycount,
                    uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    sc_context_t sc_context = {
        .output_name = "sc_rabbit",
        .output_size_bytes = BLFS_CRYPTO_BYTES_RABBIT_BLOCK,
        .crypted_data = crypted_data,
        .data = data,
        .data_length = data_length,
        .nugget_key = nugget_key,
        .kcs_keycount = kcs_keycount,
        .nugget_internal_offset = nugget_internal_offset,
        .read_handle = NULL,
        .write_handle = NULL,
        .crypt_handle = NULL,
        #ifndef __INTELLISENSE__
        .data_handle = LAMBDA(void,
            (void * context,
             uint64_t interblock_offset,
             uint64_t intrablock_offset,
             uint64_t num_blocks,
             uint64_t zero_str_length,
             uint64_t block_read_upper_bound,
             const uint8_t * const kcs_keycount_ptr,
             uint8_t * xor_str)
            {
                (void) intrablock_offset;
                (void) block_read_upper_bound;
                (void) zero_str_length;

                sc_context_t * sc_context = (sc_context_t *) context;

                rabbit_state key_state;
                rabbit_state iv_state;

                uint64_t counter = interblock_offset;
                uint8_t raw_key[BLFS_CRYPTO_BYTES_RABBIT_KEY];
                // uint8_t iv[BLFS_CRYPTO_BYTES_RABBIT_IV]; // ! handled by the 8 byte keycount (predictable keycounts, is problem?)

                memcpy(raw_key, sc_context->nugget_key, sizeof(raw_key)); // ! cutting off the key, bad bad not good! Need key schedule!

                rabbit_init_key(&key_state, raw_key);

                for(uint64_t i = 0; i < num_blocks; i++, counter++)
                {
                    // ! NOTE THAT THIS IMPLEMENTATION IS CERTAINLY NOT SECURE (we discard keycount here for expedience)
                    // ! Possible remedy: hash the keycount and the counter and use that output as IV
                    (void) kcs_keycount_ptr;
                    
                    rabbit_init_iv(&iv_state, &key_state, (uint8_t *) &counter);
                    rabbit_extract(&iv_state, xor_str + (i * sc_context->output_size_bytes));
                }
            }
        ),
        #endif
    };

    sc_generic_impl(&sc_context);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
