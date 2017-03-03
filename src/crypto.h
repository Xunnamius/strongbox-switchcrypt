#ifndef BLFS_CRYPT_H
#define BLFS_CRYPT_H

#include <stdint.h>

#include "constants.h"

/**
 * Accepts a password and a length and returns BLFS_CRYPTO_BYTES_KDF_OUT bytes
 * of key-worthy data (i.e. a master "secret").
 *
 * This function is used to invoke a KDF and derive a secure secret from a user's
 * password.
 *
 * @param passwd
 * @param passwd_length
 * @param secret
 */
void blfs_password_to_secret(const char * passwd, uint32_t passwd_length, uint8_t * secret);

/**
 * Accepts a secret of length BLFS_CRYPTO_BYTES_KDF_OUT and an uint64 and
 * returns BLFS_CRYPTO_BYTES_KDF_OUT bytes of a new secret yielded
 * deterministically via H(nonce||original-secret) where H=BLAKE2b.
 *
 * This function is used to generate chacha20 keys out of flake indices (nones)
 * and the master secret.
 *
 * @param secret
 * @param nonce
 * @param secret
 */
void blfs_secret_plus_nonce(const uint8_t * secret, uint64_t nonce, uint8_t * new_secret);

/**
 * Accepts a byte array of data of length data_length and returns crypted_data
 * of the same length which is the result of XOR-ing the output of the Chacha20
 * stream cipher using the provided key, nonce, and initial block counter
 * calculated from nugget_internal_offset.
 *
 * This function should be called within a per-nugget conceptual context.
 *
 * @param data                   
 * @param crypted_data           
 * @param data_length            
 * @param key                    
 * @param nonce                  
 * @param nugget_internal_offset 
 */
void blfs_chacha20_crypt(const uint8_t * const data,
                         uint8_t * crypted_data,
                         uint32_t data_length,
                         const uint8_t * key,
                         const uint8_t * nonce,
                         uint64_t nugget_internal_offset);

/**
 * Accepts a byte array of data of length data_length and a key of length
 * BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY and returns a poly1305 mac tag corresponding
 * to that byte array.
 *
 * The tag will be of length BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT.
 */
void blfs_poly1305_generate_tag(const uint8_t * const data, uint32_t data_length, uint8_t * key, uint8_t * tag);

/**
 * Accepts a global_version and checks it against an internal TPM/TrustZone
 * (monotonic?) value located using id.
 *
 * @param id
 * @param global_version
 */
void blfs_globalversion_verify(uint64_t id, uint64_t global_version);

/**
 * Accepts a global_version and commits it into an internal TPM/TrustZone
 * bucket located using id. If monotonic, then the only supported commit is an
 * increment of the global_version.
 *
 * @param id
 * @param global_version
 */
void blfs_globalversion_commit(uint64_t id, uint64_t global_version);

/**
 * Generates a BLFS_CRYPTO_BYTES_KDF_SALT byte salt of uniform random data.
 */
void blfs_KDF_generate_salt(uint8_t generated_salt);

#endif /* BLFS_CRYPT_H */
