#ifndef BLFS_SWAP_H_
#define BLFS_SWAP_H_

#include "constants.h"
#include "buselfs.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sodium.h>
#include <string.h>

/**
 * Accepts stream_cipher_e enum value stream_cipher, which translates into a
 * proper stream cipher context via blfs_to_stream_context() and set in the
 * buselfs_state object.
 *
 * @param buselfs_state
 * @param stream_cipher
 */
void blfs_set_stream_context(buselfs_state_t * buselfs_state, stream_cipher_e stream_cipher);

/**
 * Accepts a stream_cipher_e enum value stream_cipher and translates it into the
 * proper stream cipher context (i.e. function pointer w/ proper cipher
 * implementation).
 *
 * @param stream_cipher
 *
 * @return stream_crypt_common function pointer to related cipher implementation
 */
stream_crypt_common blfs_to_stream_context(stream_cipher_e stream_cipher);

#endif /* BLFS_SWAP_H_ */
