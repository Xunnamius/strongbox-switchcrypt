#ifndef BLFS__CIPHER_CHACHA_NEON_H_
#define BLFS__CIPHER_CHACHA_NEON_H_

#include "_base.h"

/**
 * Chacha (with Neon optimizations) round count version selection
 */
typedef enum {
  CHACHA8_NEON = 8,
  CHACHA12_NEON = 12,
  CHACHA20_NEON = 20
} chacha_neon_variant;

void sc_generic_chacha_neon_impl(const char * output_name,
                                 uint64_t output_size_bytes,
                                 uint64_t key_size_bytes,
                                 chacha_neon_variant chacha_rounds,
                                 uint8_t * crypted_data,
                                 const uint8_t * data,
                                 uint32_t data_length,
                                 const uint8_t * nugget_key,
                                 uint64_t kcs_keycount,
                                 uint64_t nugget_internal_offset);

#endif /* BLFS__CIPHER_CHACHA_NEON_H_ */
