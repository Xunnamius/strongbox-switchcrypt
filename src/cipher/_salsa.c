#include "cipher/_salsa.h"

void sc_generic_salsa_crypt_data(salsa20_variant variant,
                                 const blfs_stream_cipher_t * stream_cipher,
                                 uint64_t interblock_offset,
                                 uint64_t intrablock_offset,
                                 uint64_t num_blocks,
                                 uint64_t zero_str_length,
                                 uint64_t block_read_upper_bound,
                                 const uint8_t * nugget_key,
                                 const uint64_t kcs_keycount,
                                 const uint8_t * const kcs_keycount_ptr,
                                 uint8_t * xor_str)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) intrablock_offset;
    (void) block_read_upper_bound;
    (void) zero_str_length;
    (void) kcs_keycount;

    salsa20_master_state key_state;
    salsa20_state output_state;

    uint8_t key[stream_cipher->key_size_bytes];
    // uint8_t iv[BLFS_CRYPTO_BYTES_SALSA8_IV]; // ? represented by the 8 byte keycount

    memcpy(key, nugget_key, sizeof key); // ! cutting off the key, bad bad not good! Need key schedule!

    salsa20_init_key(&key_state, variant, key, SALSA20_256_BITS);
    salsa20_init_iv(&output_state, &key_state, kcs_keycount_ptr);
    salsa20_set_counter(&output_state, interblock_offset);

    for(uint64_t i = 0; i < num_blocks; ++i)
        salsa20_extract(&output_state, xor_str + (i * stream_cipher->output_size_bytes));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void sc_impl_salsa(blfs_stream_cipher_t * sc)
{
    sc->crypt_nugget = NULL;
    sc->read_handle = NULL;
    sc->write_handle = NULL;
}
