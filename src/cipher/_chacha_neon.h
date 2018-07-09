#ifndef BLFS__CIPHER_CHACHA_NEON_H_
#define BLFS__CIPHER_CHACHA_NEON_H_

#include "cipher/_base.h"

/**
 * Chacha (with Neon optimizations) round count version selection
 */
typedef enum {
    CHACHA8_NEON,
    CHACHA12_NEON,
    CHACHA20_NEON
} chacha_neon_variant;

void sc_generic_chacha_neon_crypt_data(chacha_neon_variant variant,
                                       const blfs_stream_cipher_t * stream_cipher,
                                       uint64_t interblock_offset,
                                       uint64_t intrablock_offset,
                                       uint64_t num_blocks,
                                       uint64_t zero_str_length,
                                       uint64_t block_read_upper_bound,
                                       const uint8_t * nugget_key,
                                       const uint64_t kcs_keycount,
                                       const uint8_t * const kcs_keycount_ptr,
                                       uint8_t * xor_str);

// TODO: comment me!
void sc_impl_chacha_neon(blfs_stream_cipher_t * stream_cipher);
#endif /* BLFS__CIPHER_CHACHA_NEON_H_ */
