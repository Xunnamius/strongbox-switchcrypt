#ifndef BLFS__CIPHER_CHACHA_NEON_H_
#define BLFS__CIPHER_CHACHA_NEON_H_

#include "cipher/_base.h"

/**
 * Chacha (with Neon optimizations) round count version selection
 */
typedef enum {
    CHACHA8_NEON = 8,
    CHACHA12_NEON = 12,
    CHACHA20_NEON = 20
} chacha_neon_variant;

/**
 * This function provides a generic implementation of Neon-optimized Chacha.
 * Makes adding new similar algo versions much easier!
 */
void sc_generic_chacha_neon_crypt_data(chacha_neon_variant variant,
                                       const blfs_swappable_cipher_t * sc,
                                       uint64_t interblock_offset,
                                       uint64_t intrablock_offset,
                                       uint64_t num_blocks,
                                       uint64_t zero_str_length,
                                       uint64_t block_read_upper_bound,
                                       const uint8_t * nugget_key,
                                       const uint64_t kcs_keycount,
                                       const uint8_t * const kcs_keycount_ptr,
                                       uint8_t * xor_str);


/**
 * This function adheres to the standard swappable cipher interface for
 * initializing and returning (through the sc pointer) specific cipher
 * implementations. See the StrongBox documentation for more information.
 */
void sc_impl_chacha_neon(blfs_swappable_cipher_t * sc);

#endif /* BLFS__CIPHER_CHACHA_NEON_H_ */
