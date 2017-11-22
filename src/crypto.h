#ifndef BLFS_CRYPT_H_
#define BLFS_CRYPT_H_

#include "constants.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sodium.h>
#include <string.h>

// If you're looking for the stream cipher functions, those were all moved
// to swappable.h and swappable.c

/**
 * Accepts a password, length, and salt and returns BLFS_CRYPTO_BYTES_KDF_OUT
 * bytes of key-worthy data (i.e. a master "secret").
 *
 * This function is used to invoke a KDF and derive a secure secret from a user's
 * password.
 *
 * @param secret
 * @param passwd
 * @param passwd_length
 * @param salt
 */
void blfs_password_to_secret(uint8_t * secret, const char * passwd, uint32_t passwd_length, const uint8_t * salt);

/**
 * Generates a BLFS_HEAD_HEADER_BYTES_VERIFICATION length xored_value using the
 * given secret of length BLFS_CRYPTO_BYTES_KDF_OUT and 0 as a nonce. The
 * Chacha20 function is used.
 * 
 * @param xored_value
 * @param secret
 */
void blfs_chacha20_verif(uint8_t * xored_value, const uint8_t * secret);

/**
 * Generates a BLFS_CRYPTO_BYTES_TJ_HASH_OUT length xored_tj using the given
 * secret of `length` and a BLFS_CRYPTO_BYTES_CHACHA_NONCE nonce. The Chacha20
 * based BLAKE2 function is used.
 * 
 * @param xored_value
 * @param secret
 */
void blfs_chacha20_tj_hash(uint8_t * tj_hash, const uint8_t * tj_data, uint64_t tj_data_length, const uint8_t * master_secret);

/**
 * Accepts a secret of length BLFS_CRYPTO_BYTES_KDF_OUT and a nugget_index and
 * yields a unique nugget_key of length BLFS_CRYPTO_BYTES_KDF_OUT per nugget.
 *
 * This is done by treating the first 8 bytes of secret as a uint64_t and
 * adding (via addition) nugget_index to it. The resulting
 * BLFS_CRYPTO_BYTES_KDF_OUT bytes taken as a whole are yielded
 * as nugget_key.
 *
 * XXX: Might run into endianness trouble here; might fix later.
 *
 * This function is used to deterministically generate raw unique keys to be
 * cached and used with blfs_chacha20_crypt() along with respective kcs counts.
 *
 * @param nugget_key
 * @param secret
 * @param nugget_index
 */
void blfs_nugget_key_from_data(uint8_t * nugget_key, const uint8_t * secret, uint64_t nugget_index);

/**
 * Accepts a nugget_key of length BLFS_CRYPTO_BYTES_KDF_OUT along with extra
 * data and yields new_key with BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY bytes of a new
 * nugget_key yielded deterministically.
 *
 * This is done by treating the first 8 bytes of nugget_key as a uint64_t and
 * adding (via addition) flake_index and kcs_keycount to it. The
 * resulting BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY bytes taken as a whole are yielded
 * as new_key.
 *
 * XXX: Might run into endianness trouble here; might fix later.
 *
 * This function is used to deterministically generate unique keys for
 * blfs_poly1305_generate_tag().
 *
 * @param new_key
 * @param nugget_key
 * @param flake_index
 * @param kcs_keycount
 */
void blfs_poly1305_key_from_data(uint8_t * new_key,
                                 const uint8_t * nugget_key,
                                 uint32_t flake_index,
                                 uint64_t kcs_keycount);

/**
 * Accepts a byte array of data of length data_length and a flake_key of length
 * BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY and returns a poly1305 mac tag corresponding
 * to that byte array.
 *
 * The tag will be of length BLFS_CRYPTO_BYTES_FLAKE_TAG_OUT. Used to mac flakes
 * for comparison in the Merkle Tree. Small fakes are happy flakes!
 * 
 * @param tag
 * @param data
 * @param data_length
 * @param flake_key
 */
void blfs_poly1305_generate_tag(uint8_t * tag, const uint8_t * data, uint32_t data_length, const uint8_t * flake_key);

/**
 * Accepts a global_version and checks it against an internal TPM/TrustZone
 * (monotonic?) value located using id.
 *
 * @param id
 * @param global_version
 *
 * @returns BLFS_GLOBAL_CORRECTNESS_ILLEGAL_MANIP   if verification failed in
 *                                                  an obviously malicious way
 * @returns BLFS_GLOBAL_CORRECTNESS_POTENTIAL_CRASH if verification likely
 *                                                  failed due to a benign crash
 * @returns BLFS_GLOBAL_CORRECTNESS_ALL_GOOD        if verification passes!
 */
int blfs_globalversion_verify(uint64_t id, uint64_t global_version);

/**
 * Accepts a global_version and commits it into an internal RPMB bucket located
 * using id. If monotonic, then the only supported commit is an increment of the
 * global_version or this function's behavior is undefined.
 * 
 * @param id
 * @param global_version
 */
void blfs_globalversion_commit(uint64_t id, uint64_t global_version);

/**
 * Generates a BLFS_CRYPTO_BYTES_KDF_SALT byte salt of uniform random data
 * yielded into generated_salt.
 *
 * @param generated_salt
 */
void blfs_KDF_generate_salt(uint8_t * generated_salt);

/**
 * Accepts plaintext_data of length data_length, a flake_key of length
 * BLFS_CRYPTO_BYTES_CHACHA_KEY, and a sector_tweak and yields ciphertext of
 * length data_length into encrypted_data. StrongBox wasn't made for AES-XTS, so
 * this is NOT a secure use of the mode!
 *
 * @param encrypted_data
 * @param plaintext_data
 * @param data_length
 * @param flake_key
 * @param sector_tweak
 */
void blfs_aesxts_encrypt(uint8_t * encrypted_data,
                         const uint8_t * plaintext_data,
                         uint32_t data_length,
                         const uint8_t * flake_key,
                         uint32_t sector_tweak);

/**
 * Accepts encrypted_data of length data_length, a flake_key of length
 * BLFS_CRYPTO_BYTES_CHACHA_KEY, and a sector_tweak and yields plaintext of
 * length data_length into plaintext_data. StrongBox wasn't made for AES-XTS, so
 * this is NOT a secure use of the mode!
 *
 * @param encrypted_data
 * @param plaintext_data
 * @param data_length
 * @param flake_key
 * @param sector_tweak
 */
void blfs_aesxts_decrypt(uint8_t * plaintext_data,
                         const uint8_t * encrypted_data,
                         uint32_t data_length,
                         const uint8_t * flake_key,
                         uint32_t sector_tweak);

#endif /* BLFS_CRYPT_H_ */
