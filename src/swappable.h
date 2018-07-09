#ifndef BLFS_SWAP_H_
#define BLFS_SWAP_H_

#include "constants.h"

typedef struct blfs_stream_cipher_t blfs_stream_cipher_t;

#include "ciphers.h"

// TODO: document EVERYTHING!

/**
 * Struct that defines the common stream cipher interface for algorithm
 * swapping. See swappable.h for details.
 */
typedef void (*sc_fn_crypt_data)(
    const blfs_stream_cipher_t *,
    uint64_t,
    uint64_t,
    uint64_t,
    uint64_t,
    uint64_t,
    const uint8_t *,
    const uint64_t,
    const uint8_t * const,
    uint8_t *
);

/**
 * Struct that defines the common stream cipher interface for algorithm
 * swapping. See swappable.h for details.
 */
typedef void (*sc_fn_crypt_nugget)(
    const blfs_stream_cipher_t *,
    uint64_t,
    uint64_t,
    uint64_t,
    uint64_t,
    uint64_t,
    const uint8_t *,
    const uint64_t,
    const uint8_t * const
);

/**
 * Struct that defines the common stream cipher interface for algorithm
 * swapping. See swappable.h for details.
 */
// TODO: fix me!
typedef void (*sc_fn_read_handle)(
    const blfs_stream_cipher_t *,
    uint64_t,
    uint64_t,
    uint64_t,
    uint64_t,
    uint64_t,
    const uint8_t *,
    const uint64_t,
    const uint8_t * const
);

/**
 * Struct that defines the common stream cipher interface for algorithm
 * swapping. See swappable.h for details.
 */
// TODO: fix me!
typedef void (*sc_fn_write_handle)(
    const blfs_stream_cipher_t *,
    uint64_t,
    uint64_t,
    uint64_t,
    uint64_t,
    uint64_t,
    const uint8_t *,
    const uint64_t,
    const uint8_t * const
);

/**
 * A complete package representing a cipher in StrongBox
 */
struct blfs_stream_cipher_t
{
    const char * output_name;

    const uint64_t output_size_bytes;
    const uint64_t key_size_bytes;
    const uint64_t nonce_size_bytes;

    sc_fn_crypt_data crypt_data;
    sc_fn_crypt_nugget crypt_nugget;
    sc_fn_read_handle read_handle;
    sc_fn_write_handle write_handle;
};

/**
 * Accepts stream_cipher_e enum value stream_cipher, which translates into a
 * proper stream cipher context used to populate set in stream_cipher_struct.
 *
 * @param stream_cipher
 */
void blfs_get_stream_cipher(blfs_stream_cipher_t * sc, stream_cipher_e stream_cipher);

/**
 * Takes a string and converts it to its corresponding stream_cipher_e enum
 * item. Throws an exception if the passed string is invalid.
 *
 * @param  stream_cipher_str
 *
 * @return stream_cipher_e
 */
stream_cipher_e blfs_stream_string_to_cipher(const char * stream_cipher_str);

// TODO: document me!
void blfs_swappable_crypt(blfs_stream_cipher_t * stream_cipher,
                          uint8_t * crypted_data,
                          const uint8_t * data,
                          const uint32_t data_length,
                          const uint8_t * nugget_key,
                          const uint64_t kcs_keycount,
                          const uint64_t nugget_internal_offset);

#endif /* BLFS_SWAP_H_ */
