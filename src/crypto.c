/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "crypto.h"

static void debug_print_hex(const uint8_t * data, size_t len)
{
    for(size_t i = 0; i < len; i++)
        fprintf(stderr, "0x%x ", data[i] & 0xFF);
    fprintf(stderr, "\n");
}

void blfs_password_to_secret(uint8_t * secret, const char * passwd, uint32_t passwd_length, const uint8_t * salt)
{
    // BLFS_CRYPTO_BYTES_KDF_OUT
    if(crypto_pwhash(secret, BLFS_CRYPTO_BYTES_KDF_OUT, passwd, passwd_length, salt,
                     crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0)
    {
        Throw(EXCEPTION_OUT_OF_MEMORY);
    }
}

void blfs_nugget_key_from_data(uint8_t * nugget_key, uint8_t * secret, uint64_t nugget_index)
{
    memcpy(nugget_key, secret, BLFS_CRYPTO_BYTES_KDF_OUT);
    uint64_t * secret8bytes = (uint64_t *) nugget_key;
    secret8bytes[0] += nugget_index;
}

void blfs_poly1305_key_from_data(uint8_t * new_key,
                                 const uint8_t * nugget_key,
                                 uint32_t flake_index,
                                 uint64_t kcs_keycount)
{
    memcpy(new_key, nugget_key, BLFS_CRYPTO_BYTES_FLAKE_TAG_KEY);
    uint64_t * nk8bytes = (uint64_t *) new_key;
    nk8bytes[0] += ((uint64_t) flake_index) + kcs_keycount;
}

void blfs_poly1305_generate_tag(uint8_t * tag, const uint8_t * data, uint32_t data_length, const uint8_t * flake_key)
{
    crypto_onetimeauth(tag, data, data_length, flake_key);
}

/*
static int chacha_crypt_actual(char * const cryptedMessage, const char * const message, u_int32_t messageLength, uint64_t absoluteOffset)
{
    int retval = -1;

    uint64_t interBlockOffset = (uint64_t) floor(absoluteOffset / CHACHA_BLOCK_SIZE);
    uint64_t intraBlockOffset = absoluteOffset % ((uint64_t) CHACHA_BLOCK_SIZE);
    uint64_t zeroStringLength = (uint64_t) (ceil((intraBlockOffset + messageLength) / CHACHA_BLOCK_SIZE) * CHACHA_BLOCK_SIZE);
    uint64_t blockReadUpperBound = intraBlockOffset + messageLength;

    if(DEBUG_LEVEL)
    {
        fprintf(stderr, " [L=%" PRIu64 " IEO=%" PRIu64 " IAO=%" PRIu64 "] (mlen=%u | {bRRdiff=%" PRIu64 "} <=> blockReadRange=(%" PRIu64 " to %" PRIu64 " - 1))\n",
                zeroStringLength, interBlockOffset, intraBlockOffset,
                messageLength, blockReadUpperBound - intraBlockOffset, intraBlockOffset, blockReadUpperBound);
    }

    assert(zeroStringLength >= messageLength);

    char * zeroString = malloc(zeroStringLength);
    char * xorString = malloc(zeroStringLength);

    memset(zeroString, '0', zeroStringLength);

    retval = crypto_stream_chacha20_xor_ic((unsigned char *) xorString, (unsigned char *) zeroString, zeroStringLength, cryptNonce, interBlockOffset, cryptKey);

    for(uint64_t i = intraBlockOffset, j = blockReadUpperBound, k = 0; i < j; ++i, ++k)
    {
        assert(k < messageLength);
        cryptedMessage[k] = message[k] ^ xorString[i];
    }

    free(zeroString);
    free(xorString);

    return retval;
}
 */

void blfs_chacha20_crypt(uint8_t * crypted_data,
                         const uint8_t * data,
                         uint32_t data_length,
                         const uint8_t * nugget_key,
                         uint64_t * kcs_keycount,
                         uint64_t nugget_internal_offset)
{
    (void) crypted_data;
    (void) data;
    (void) data_length;
    (void) nugget_key;
    (void) kcs_keycount;
    (void) nugget_internal_offset;


}

int blfs_globalversion_verify(uint64_t id, uint64_t global_version)
{
    (void) id;
    (void) global_version;

    // TODO: spin our wheels here for a bit to simulate verification

    return 0;
}

int blfs_globalversion_commit(uint64_t id, uint64_t global_version)
{
    (void) id;
    (void) global_version;

    // TODO: spin our wheels here for a bit to simulate committing
    
    return 0;
}

void blfs_KDF_generate_salt(uint8_t * generated_salt)
{
    randombytes_buf(generated_salt, BLFS_CRYPTO_BYTES_KDF_SALT);
}
