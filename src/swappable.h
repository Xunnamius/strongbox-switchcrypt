#ifndef BLFS_SWAP_H_
#define BLFS_SWAP_H_

#include "constants.h"

/**
 * Struct that defines the common stream cipher interface for algorithm
 * swapping. See swappable.h for details.
 */

typedef void (*sc_fn_crypt_data)(uint8_t *, const uint8_t *, uint32_t, const uint8_t *, uint64_t, uint64_t);
/**
 * Struct that defines the common stream cipher interface for algorithm
 * swapping. See swappable.h for details.
 */
// TODO: fix me!
typedef void (*sc_fn_crypt_nugget)(uint8_t *, const uint8_t *, uint32_t, const uint8_t *, uint64_t, uint64_t);

/**
 * Struct that defines the common stream cipher interface for algorithm
 * swapping. See swappable.h for details.
 */
// TODO: fix me!
typedef void (*sc_fn_read_handle)(uint8_t *, const uint8_t *, uint32_t, const uint8_t *, uint64_t, uint64_t);

/**
 * Struct that defines the common stream cipher interface for algorithm
 * swapping. See swappable.h for details.
 */
// TODO: fix me!
typedef void (*sc_fn_write_handle)(uint8_t *, const uint8_t *, uint32_t, const uint8_t *, uint64_t, uint64_t);

/**
 * A complete package representing a cipher in StrongBox
 */
typedef struct blfs_stream_cipher_t {
    const char * output_name;

    const uint64_t output_size_bytes;
    const uint64_t key_size_bytes;
    const uint64_t nonce_size_bytes;

    sc_fn_crypt_data crypt_data;
    sc_fn_crypt_nugget crypt_nugget;
    sc_fn_read_handle read_handle;
    sc_fn_write_handle write_handle;
} blfs_stream_cipher_t;

/**
 * Accepts stream_cipher_e enum value stream_cipher, which translates into a
 * proper stream cipher context used to populate set in stream_cipher_struct.
 *
 * @param stream_cipher
 */
void blfs_get_stream_cipher(blfs_stream_cipher_t * stream_cipher_struct, stream_cipher_e stream_cipher);

/**
 * Takes a string and converts it to its corresponding stream_cipher_e enum
 * item. Throws an exception if the passed string is invalid.
 *
 * @param  stream_cipher_str
 *
 * @return stream_cipher_e
 */
stream_cipher_e stream_string_to_cipher(const char * stream_cipher_str);

#endif /* BLFS_SWAP_H_ */
