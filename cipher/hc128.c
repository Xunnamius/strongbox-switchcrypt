#include "cipher/hc128.h"

void sc_impl_hc128(uint8_t * crypted_data,
                   const uint8_t * data,
                   uint32_t data_length,
                   const uint8_t * nugget_key,
                   uint64_t kcs_keycount,
                   uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    sc_context_t sc_context = {
        .output_name = "sc_hc128",
        .output_size_bytes = BLFS_CRYPTO_BYTES_HC128_BLOCK,
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

                hc128_state output_state;

                uint64_t counter = interblock_offset;
                uint8_t raw_key[BLFS_CRYPTO_BYTES_HC128_KEY];
                uint8_t stream_nonce[BLFS_CRYPTO_BYTES_HC128_IV];

                IFDEBUG(assert(sizeof(sc_context->kcs_keycount) + sizeof(counter) <= sizeof(stream_nonce)));
                
                memset(stream_nonce, 0, sizeof(stream_nonce));
                memcpy(stream_nonce, kcs_keycount_ptr, sizeof(sc_context->kcs_keycount));
                memcpy(raw_key, sc_context->nugget_key, sizeof(raw_key)); // ! cutting off the key, bad bad not good! Need key schedule!

                for(uint64_t i = 0; i < num_blocks; i++, counter++)
                {
                    memcpy(stream_nonce + sizeof(sc_context->kcs_keycount), (uint8_t *) &counter, sizeof(counter));

                    hc128_init(&output_state, raw_key, stream_nonce);
                    hc128_extract(&output_state, xor_str + (i * sc_context->output_size_bytes));
                }
            }
        ),
        #endif
    };

    sc_generic_impl(&sc_context);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
