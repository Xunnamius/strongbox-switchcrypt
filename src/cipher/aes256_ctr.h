#ifndef BLFS_CIPHER_AES256_CTR_H_
#define BLFS_CIPHER_AES256_CTR_H_

#include "cipher/_aes.h"

/**
 * This function adheres to the standard swappable cipher interface for
 * initializing and returning (through the sc pointer) specific cipher
 * implementations. See the StrongBox documentation for more information.
 */
void sc_impl_aes256_ctr(blfs_swappable_cipher_t * sc);

#endif /* BLFS_CIPHER_AES256_CTR_H_ */
