#include "_aes.h"

static void crypt_fn(void * context,
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

    uint64_t counter = interblock_offset;
    uint8_t stream_nonce[iv_size_bytes];
    uint8_t raw_key[key_size_bytes];

    const uint8_t * raw_key_bin = (const uint8_t *) &raw_key;
    int key_size_bits = (int)(key_size_bytes * BITS_IN_A_BYTE);

    AES_KEY aes_key;
    AES_KEY * aes_key_ptr = &aes_key;

    IFDEBUG(assert(sizeof(sc_context->kcs_keycount) + sizeof(counter) <= sizeof(stream_nonce)));

    memset(stream_nonce, 0, sizeof(stream_nonce));
    memcpy(stream_nonce, kcs_keycount_ptr, sizeof(sc_context->kcs_keycount));
    memcpy(raw_key, sc_context->nugget_key, sizeof(raw_key)); // ! cutting off the key, bad bad not good! Need key schedule!

    for(uint64_t i = 0; i < num_blocks; i++, counter++)
    {
        memcpy(stream_nonce + sizeof(sc_context->kcs_keycount), (uint8_t *) &counter, sizeof(counter));

        AES_set_encrypt_key(raw_key_bin, key_size_bits, aes_key_ptr);
        AES_encrypt(stream_nonce, xor_str + (i * output_size_bytes), aes_key_ptr);
    }
}

void sc_generic_aes_impl(const char * output_name,
                         uint64_t output_size_bytes,
                         uint64_t key_size_bytes,
                         uint64_t iv_size_bytes,
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
        .crypt_data = crypt_data,
        .crypt_nugget = NULL
    };

    sc_generic_impl(&sc_context);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
