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

typedef struct freestyle_variant_configuration {
    uint16_t min_rounds;
    uint16_t max_rounds;
    uint16_t hash_interval;
    uint8_t pepper_bits;
} freestyle_variant_configuration;

/**
 * This function provides a generic implementation of Freestyle (read_handle).
 * Makes adding new similar algo versions much easier!
 */
int sc_generic_freestyle_read_handle(freestyle_variant variant,
                                      uint8_t * buffer,
                                      const buselfs_state_t * buselfs_state,
                                      uint_fast32_t buffer_read_length,
                                      uint_fast32_t flake_index,
                                      uint_fast32_t flake_end,
                                      uint_fast32_t first_affected_flake,
                                      uint32_t flake_size,
                                      uint_fast32_t flakes_per_nugget,
                                      uint32_t mt_offset,
                                      const uint8_t * nugget_data,
                                      const uint8_t * nugget_key,
                                      uint_fast32_t nugget_offset,
                                      uint_fast32_t nugget_internal_offset,
                                      const blfs_keycount_t * count,
                                      int first_nugget,
                                      int last_nugget);

/**
 * This function provides a generic implementation of Freestyle (write_handle).
 * Makes adding new similar algo versions much easier!
 */
int sc_generic_freestyle_write_handle(freestyle_variant variant,
                                       const uint8_t * buffer,
                                       const buselfs_state_t * buselfs_state,
                                       uint_fast32_t buffer_write_length,
                                       uint_fast32_t flake_index,
                                       uint_fast32_t flake_end,
                                       uint32_t flake_size,
                                       uint_fast32_t flakes_per_nugget,
                                       uint_fast32_t flake_internal_offset,
                                       uint32_t mt_offset,
                                       const uint8_t * nugget_key,
                                       uint_fast32_t nugget_offset,
                                       const blfs_keycount_t * count);


/**
 * This function adheres to the standard swappable cipher interface for
 * initializing and returning (through the sc pointer) specific cipher
 * implementations. See the StrongBox documentation for more information.
 */
void sc_impl_freestyle(blfs_swappable_cipher_t * sc);

#endif /* BLFS_CIPHER__FREESTYLE_H_ */
