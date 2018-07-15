#include "cipher/_aes.h"

void sc_generic_aes_crypt_data(const blfs_swappable_cipher_t * sc,
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
    (void) intrablock_offset;
    (void) block_read_upper_bound;
    (void) zero_str_length;

    uint64_t counter = interblock_offset;
    uint8_t stream_nonce[sc->nonce_size_bytes];
    uint8_t raw_key[sc->key_size_bytes];

    const uint8_t * raw_key_bin = (const uint8_t *) &raw_key;
    int key_size_bits = (int)(sc->key_size_bytes * BITS_IN_A_BYTE);

    AES_KEY aes_key;
    AES_KEY * aes_key_ptr = &aes_key;

    IFDEBUG(assert(sizeof(kcs_keycount) + sizeof(counter) <= sizeof(stream_nonce)));

    memset(stream_nonce, 0, sizeof(stream_nonce));
    memcpy(stream_nonce, kcs_keycount_ptr, sizeof(kcs_keycount));
    memcpy(raw_key, nugget_key, sizeof(raw_key)); // ! cutting off the key, bad bad not good! Need key schedule!

    for(uint64_t i = 0; i < num_blocks; i++, counter++)
    {
        memcpy(stream_nonce + sizeof(kcs_keycount), (uint8_t *) &counter, sizeof(counter));

        AES_set_encrypt_key(raw_key_bin, key_size_bits, aes_key_ptr);
        AES_encrypt(stream_nonce, xor_str + (i * sc->output_size_bytes), aes_key_ptr);
    }
}

void sc_impl_aes(blfs_swappable_cipher_t * sc)
{
    sc->name = "AES (partially initialized)";
}
