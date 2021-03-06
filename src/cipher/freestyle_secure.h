#ifndef BLFS_CIPHER_FREESTYLE_SECURE_H_
#define BLFS_CIPHER_FREESTYLE_SECURE_H_

#include "cipher/_freestyle.h"

/**
 * This function adheres to the standard swappable cipher interface for
 * initializing and returning (through the sc pointer) specific cipher
 * implementations. See the StrongBox documentation for more information.
 */
void sc_impl_freestyle_secure(blfs_swappable_cipher_t * sc);

#endif /* BLFS_CIPHER_FREESTYLE_SECURE_H_ */
