#ifndef BLFS_CIPHER__SALSA_H_
#define BLFS_CIPHER__SALSA_H_

#include "cipher/_base.h"
#include "libestream/salsa20.h"

/**
 * This is a generic implementation of using the SALSA stream cipher to crypt
 * some amount of data. Made adding all the SALSA20/x variants much easier!
 *
 * @param sc_context
 */
void sc_generic_salsa_impl(const char * output_name,
                           uint64_t output_size_bytes,
                           uint64_t key_size_bytes,
                           salsa20_variant salsa_rounds,
                           uint8_t * crypted_data,
                           const uint8_t * data,
                           uint32_t data_length,
                           const uint8_t * nugget_key,
                           uint64_t kcs_keycount,
                           uint64_t nugget_internal_offset);

#endif /* BLFS_CIPHER__SALSA_H_ */
