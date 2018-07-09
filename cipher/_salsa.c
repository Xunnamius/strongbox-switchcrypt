#include "cipher/_salsa.h"

void sc_generic_salsa_impl(const char * output_name,
                           uint64_t output_size_bytes,
                           uint64_t key_size_bytes,
                           salsa20_variant salsa_rounds,
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

                salsa20_master_state key_state;
                salsa20_state output_state;

                uint8_t key[key_size_bytes];
                // uint8_t iv[BLFS_CRYPTO_BYTES_SALSA8_IV]; // ? represented by the 8 byte keycount

                memcpy(key, sc_context->nugget_key, sizeof key); // ! cutting off the key, bad bad not good! Need key schedule!

                salsa20_init_key(&key_state, salsa_rounds, key, SALSA20_256_BITS);
                salsa20_init_iv(&output_state, &key_state, kcs_keycount_ptr);
                salsa20_set_counter(&output_state, interblock_offset);

                for(uint64_t i = 0; i < num_blocks; ++i)
                    salsa20_extract(&output_state, xor_str + (i * sc_context->output_size_bytes));
            }
        ),
        #endif
    };

    sc_generic_impl(&sc_context);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
