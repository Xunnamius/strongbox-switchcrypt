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
 * @param sc_context
 */
void sc_generic_aes_impl(const char * output_name,
                         uint64_t output_size_bytes,
                         uint64_t key_size_bytes,
                         uint64_t iv_size_bytes,
                         uint8_t * crypted_data,
                         const uint8_t * data,
                         uint32_t data_length,
                         const uint8_t * nugget_key,
                         uint64_t kcs_keycount,
                         uint64_t nugget_internal_offset);

#endif /* BLFS_CIPHER__AES_H_ */
