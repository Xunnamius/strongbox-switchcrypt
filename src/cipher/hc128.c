#include "cipher/hc128.h"
#include "libestream/hc-128.h"

static void crypt_data(const blfs_swappable_cipher_t * sc,
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

    hc128_state output_state;

    uint64_t counter = interblock_offset;
    uint8_t raw_key[BLFS_CRYPTO_BYTES_HC128_KEY];
    uint8_t stream_nonce[BLFS_CRYPTO_BYTES_HC128_IV];

    IFDEBUG(assert(sizeof(kcs_keycount) + sizeof(counter) <= sizeof(stream_nonce)));

    memset(stream_nonce, 0, sizeof(stream_nonce));
    memcpy(stream_nonce, kcs_keycount_ptr, sizeof(kcs_keycount));
    memcpy(raw_key, nugget_key, sizeof(raw_key)); // ! cutting off the key, bad bad not good! Need key schedule!

    for(uint64_t i = 0; i < num_blocks; i++, counter++)
    {
        memcpy(stream_nonce + sizeof(kcs_keycount), (uint8_t *) &counter, sizeof(counter));

        hc128_init(&output_state, raw_key, stream_nonce);
        hc128_extract(&output_state, xor_str + (i * sc->output_size_bytes));
    }

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void sc_impl_hc128(blfs_swappable_cipher_t * sc)
{
    sc->crypt_data = &crypt_data;

    sc->name = "HC-128";
    sc->enum_id = sc_hc128;

    sc->key_size_bytes = BLFS_CRYPTO_BYTES_HC128_KEY;
    sc->nonce_size_bytes = BLFS_CRYPTO_BYTES_HC128_IV;
    sc->output_size_bytes = BLFS_CRYPTO_BYTES_HC128_BLOCK;
}
