#include "cipher/freestyle_secure.h"

void sc_impl_freestyle_secure(uint8_t * crypted_data,
                              const uint8_t * data,
                              uint32_t data_length,
                              const uint8_t * nugget_key,
                              uint64_t kcs_keycount,
                              uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    sc_generic_freestyle_impl("sc_freestyle_secure",
                          BLFS_CRYPTO_BYTES_FSTYLE_BLOCK,
                          BLFS_CRYPTO_BYTES_FSTYLE_KEY,
                          FREESTYLE_SECURE,
                          crypted_data,
                          data,
                          data_length,
                          nugget_key,
                          kcs_keycount,
                          nugget_internal_offset);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
