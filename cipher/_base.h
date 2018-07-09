#ifndef BLFS_CIPHER_BASE_H_
#define BLFS_CIPHER_BASE_H_

#include "swappable.h"
#include "crypto.h"

#include <assert.h>
#include <string.h>
#include <inttypes.h>

#include <sodium.h>

/**
 * This struct represents the execution context of a generic stream cipher (sc).
 */
typedef struct sc_context_t {
    const blfs_stream_cipher_t * stream_cipher;
    uint8_t * crypted_data;
    const uint8_t * data;
    const uint32_t data_length;
    const uint8_t * nugget_key;
    const uint64_t kcs_keycount;
    const uint64_t nugget_internal_offset;
} sc_context_t;

/**
 * This is a generic implementation of using a stream cipher to crypt some
 * amount of data. Makes adding new algos much easier!
 *
 * @param sc_context
 */
void sc_generic_impl(sc_context_t * sc_context);

#endif /* BLFS_CIPHER_BASE_H_ */
