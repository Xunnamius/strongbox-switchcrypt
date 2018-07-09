#ifndef BLFS_CIPHER__FREESTYLE_H_
#define BLFS_CIPHER__FREESTYLE_H_

#include "cipher/_base.h"
#include "freestyle.h"

/**
 * Freestyle round count version selection
 */
typedef enum {
  FREESTYLE_FAST,
  FREESTYLE_BALANCED,
  FREESTYLE_SECURE
} freestyle_variant;

void sc_generic_freestyle_impl(const char * output_name,
                               uint64_t output_size_bytes,
                               uint64_t key_size_bytes,
                               freestyle_variant freestyle_configuration,
                               uint8_t * crypted_data,
                               const uint8_t * data,
                               uint32_t data_length,
                               const uint8_t * nugget_key,
                               uint64_t kcs_keycount,
                               uint64_t nugget_internal_offset);

#endif /* BLFS_CIPHER__FREESTYLE_H_ */
