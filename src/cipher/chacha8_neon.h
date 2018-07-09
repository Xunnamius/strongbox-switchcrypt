#ifndef BLFS_CIPHER_CHACHA8_NEON_H_
#define BLFS_CIPHER_CHACHA8_NEON_H_

#include "cipher/_chacha_neon.h"

void sc_impl_chacha8_neon(blfs_stream_cipher_t * stream_cipher);

#endif /* BLFS_CIPHER_CHACHA8_NEON_H_ */
