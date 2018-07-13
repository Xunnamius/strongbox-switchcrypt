#ifndef BLFS_CIPHER_CHACHA12_NEON_H_
#define BLFS_CIPHER_CHACHA12_NEON_H_

#include "cipher/_chacha_neon.h"

/**
 * This function adheres to the standard swappable cipher interface for
 * initializing and returning (through the sc pointer) specific cipher
 * implementations. See the StrongBox documentation for more information.
 */
void sc_impl_chacha12_neon(blfs_swappable_cipher_t * sc);

#endif /* BLFS_CIPHER_CHACHA12_NEON_H_ */
