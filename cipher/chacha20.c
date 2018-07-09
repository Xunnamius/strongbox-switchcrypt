#include "chacha20.h"

void sc_impl_chacha20(uint8_t * crypted_data,
                      const uint8_t * data,
                      uint32_t data_length,
                      const uint8_t * nugget_key,
                      uint64_t kcs_keycount,
                      uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    sc_context_t sc_context = {
        .output_name = "sc_chacha20",
        .output_size_bytes = BLFS_CRYPTO_BYTES_CHACHA20_BLOCK,
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
                (void) num_blocks;
                (void) block_read_upper_bound;

                uint8_t * zero_str = calloc(zero_str_length, sizeof(*zero_str));

                if(zero_str == NULL)
                    Throw(EXCEPTION_ALLOC_FAILURE);

                sc_context_t * sc_context = (sc_context_t *) context;

                if(crypto_stream_chacha20_xor_ic(
                        xor_str,
                        zero_str,
                        zero_str_length,
                        kcs_keycount_ptr,
                        interblock_offset,
                        sc_context->nugget_key) != 0)
                {
                    Throw(EXCEPTION_CHACHA20_BAD_RETVAL);
                }

                free(zero_str);
            }
        ),
        #endif
    };

    sc_generic_impl(&sc_context);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
