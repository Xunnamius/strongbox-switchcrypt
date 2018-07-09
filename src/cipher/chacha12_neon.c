#include "cipher/chacha12_neon.h"

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

    sc_generic_chacha_neon_crypt_data(
        CHACHA12_NEON,
        stream_cipher,
        interblock_offset,
        intrablock_offset,
        num_blocks,
        zero_str_length,
        block_read_upper_bound,
        nugget_key,
        kcs_keycount,
        kcs_keycount_ptr,
        xor_str
    );

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void sc_impl_chacha12_neon(blfs_stream_cipher_t * sc)
{
    sc_impl_chacha_neon(sc);
    sc->crypt_data = &crypt_data;
}
