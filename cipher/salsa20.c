#include "cipher/salsa20.h"

void sc_impl_salsa20(uint8_t * crypted_data,
                    const uint8_t * data,
                    uint32_t data_length,
                    const uint8_t * nugget_key,
                    uint64_t kcs_keycount,
                    uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    sc_generic_salsa_impl("sc_salsa20",
                          BLFS_CRYPTO_BYTES_SALSA20_BLOCK,
                          BLFS_CRYPTO_BYTES_SALSA20_KEY,
                          SALSA20_20,
                          crypted_data,
                          data,
                          data_length,
                          nugget_key,
                          kcs_keycount,
                          nugget_internal_offset);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
