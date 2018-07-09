#ifndef BLFS_CIPHER__AES_H_
#define BLFS_CIPHER__AES_H_

#include "cipher/_base.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "openssl/aes.h"

/**
 * This is a generic implementation of using the AES block cipher in CTR mode to
 * crypt some amount of data. Makes adding new AES-based algo versions much
 * easier!
 *
 * @stream_cipher
 * @interblock_offset
 * @intrablock_offset
 * @num_blocks
 * @zero_str_length
 * @block_read_upper_bound
 * @nugget_key
 * @kcs_keycount
 * @kcs_keycount_ptr
 * @xor_str
 */
void sc_generic_aes_crypt_data(const blfs_stream_cipher_t * stream_cipher,
                               uint64_t interblock_offset,
                               uint64_t intrablock_offset,
                               uint64_t num_blocks,
                               uint64_t zero_str_length,
                               uint64_t block_read_upper_bound,
                               const uint8_t * nugget_key,
                               const uint64_t kcs_keycount,
                               const uint8_t * const kcs_keycount_ptr,
                               uint8_t * xor_str);

// TODO: comment me!
void sc_impl_aes(blfs_stream_cipher_t * stream_cipher);

#endif /* BLFS_CIPHER__AES_H_ */
