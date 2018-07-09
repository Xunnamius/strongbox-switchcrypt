#include "cipher/chacha12_neon.h"

void sc_impl_chacha12_neon(uint8_t * crypted_data,
                          const uint8_t * data,
                          uint32_t data_length,
                          const uint8_t * nugget_key,
                          uint64_t kcs_keycount,
                          uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    sc_generic_chacha_neon_impl(
        "sc_chacha12_neon",
        BLFS_CRYPTO_BYTES_CHACHA12N_BLOCK,
        BLFS_CRYPTO_BYTES_CHACHA12N_KEY,
        CHACHA12_NEON,
        crypted_data,
        data,
        data_length,
        nugget_key,
        kcs_keycount,
        nugget_internal_offset
    );

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
