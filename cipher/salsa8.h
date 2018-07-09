#ifndef BLFS_CIPHER_SALSA8_H_
#define BLFS_CIPHER_SALSA8_H_

#include "cipher/_salsa.h"

void sc_impl_salsa8(uint8_t * crypted_data,
                    const uint8_t * data,
                    uint32_t data_length,
                    const uint8_t * nugget_key,
                    uint64_t kcs_keycount,
                    uint64_t nugget_internal_offset);

#endif /* BLFS_CIPHER_SALSA8_H_ */
