#ifndef BLFS_CIPHER__FREESTYLE_H_
#define BLFS_CIPHER__FREESTYLE_H_

#include "cipher/_base.h"
#include "freestyle.h"

/**
 * Freestyle round count version selection
 */
typedef enum {
    FREESTYLE_FAST,
    FREESTYLE_BALANCED,
    FREESTYLE_SECURE
} freestyle_variant;

void sc_generic_freestyle_read_handle(freestyle_variant variant,
                                      const blfs_stream_cipher_t * stream_cipher,
                                      uint64_t interblock_offset,
                                      uint64_t intrablock_offset,
                                      uint64_t num_blocks,
                                      uint64_t zero_str_length,
                                      uint64_t block_read_upper_bound,
                                      const uint8_t * nugget_key,
                                      const uint64_t kcs_keycount,
                                      const uint8_t * const kcs_keycount_ptr);

void sc_generic_freestyle_write_handle(freestyle_variant variant,
                                       const blfs_stream_cipher_t * stream_cipher,
                                       uint64_t interblock_offset,
                                       uint64_t intrablock_offset,
                                       uint64_t num_blocks,
                                       uint64_t zero_str_length,
                                       uint64_t block_read_upper_bound,
                                       const uint8_t * nugget_key,
                                       const uint64_t kcs_keycount,
                                       const uint8_t * const kcs_keycount_ptr);

// TODO: comment me!
void sc_impl_freestyle(blfs_stream_cipher_t * sc);

#endif /* BLFS_CIPHER__FREESTYLE_H_ */
