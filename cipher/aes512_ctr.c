#include "cipher/aes512_ctr.h"

void sc_impl_aes512_ctr(uint8_t * crypted_data,
                        const uint8_t * data,
                        uint32_t data_length,
                        const uint8_t * nugget_key,
                        uint64_t kcs_keycount,
                        uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    sc_generic_aes_impl("sc_aes512_ctr",
                        BLFS_CRYPTO_BYTES_AES512_BLOCK,
                        BLFS_CRYPTO_BYTES_AES512_KEY,
                        BLFS_CRYPTO_BYTES_AES512_IV,
                        crypted_data,
                        data,
                        data_length,
                        nugget_key,
                        kcs_keycount,
                        nugget_internal_offset);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
