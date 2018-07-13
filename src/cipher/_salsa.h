#ifndef BLFS_CIPHER__SALSA_H_
#define BLFS_CIPHER__SALSA_H_

#include "cipher/_base.h"
#include "libestream/salsa20.h"

/**
 * This is a generic implementation of using the SALSA stream cipher to crypt
 * some amount of data. Made adding all the SALSA20/x variants much easier!
 *
 * @param sc_context
 */
void sc_generic_salsa_crypt_data(salsa20_variant variant,
                                 const blfs_swappable_cipher_t * sc,
                                 uint64_t interblock_offset,
                                 uint64_t intrablock_offset,
                                 uint64_t num_blocks,
                                 uint64_t zero_str_length,
                                 uint64_t block_read_upper_bound,
                                 const uint8_t * nugget_key,
                                 const uint64_t kcs_keycount,
                                 const uint8_t * const kcs_keycount_ptr,
                                 uint8_t * xor_str);


/**
 * This function adheres to the standard swappable cipher interface for
 * initializing and returning (through the sc pointer) specific cipher
 * implementations. See the StrongBox documentation for more information.
 */
void sc_impl_salsa(blfs_swappable_cipher_t * sc);

#endif /* BLFS_CIPHER__SALSA_H_ */
