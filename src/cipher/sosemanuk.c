#include "cipher/sosemanuk.h"
#include "libestream/sosemanuk.h"

static void crypt_data(const blfs_stream_cipher_t * stream_cipher,
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

    sosemanuk_master_state key_state;
    sosemanuk_state iv_state;

    uint64_t counter = interblock_offset;
    uint8_t raw_key[BLFS_CRYPTO_BYTES_SOSEK_KEY];
    uint8_t stream_nonce[BLFS_CRYPTO_BYTES_SOSEK_IV];

    IFDEBUG(assert(sizeof(kcs_keycount) + sizeof(counter) <= sizeof(stream_nonce)));

    memset(stream_nonce, 0, sizeof(stream_nonce));
    memcpy(stream_nonce, kcs_keycount_ptr, sizeof(kcs_keycount));
    memcpy(raw_key, nugget_key, sizeof(raw_key)); // ! cutting off the key, bad bad not good! Need key schedule!

    sosemanuk_init_key(&key_state, raw_key, BLFS_CRYPTO_BYTES_SOSEK_KEY * BITS_IN_A_BYTE);

    for(uint64_t i = 0; i < num_blocks; i++, counter++)
    {
        memcpy(stream_nonce + sizeof(kcs_keycount), (uint8_t *) &counter, sizeof(counter));

        sosemanuk_init_iv(&iv_state, &key_state, stream_nonce);
        sosemanuk_extract(&iv_state, xor_str + (i * stream_cipher->output_size_bytes));
    }

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void sc_impl_sosemanuk(blfs_stream_cipher_t * sc)
{
    sc->crypt_data = &crypt_data;
    sc->crypt_nugget = NULL;
    sc->read_handle = NULL;
    sc->write_handle = NULL;
}
