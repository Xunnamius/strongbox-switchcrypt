/*
 * <description>
 *
 * @author Bernard Dickens
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "crypto.h"

void blfs_password_to_secret(const char * passwd, uint32_t passwd_length, uint8_t * secret)
{

}

void blfs_secret_plus_nonce(const uint8_t * secret, uint64_t nonce, uint8_t * new_secret)
{

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

void blfs_chacha20_crypt(const uint8_t * const data,
                         uint8_t * crypted_data,
                         uint32_t data_length,
                         const uint8_t * key,
                         const uint8_t * nonce,
                         uint64_t nugget_internal_offset)
{

}

void blfs_poly1305_generate_tag(const uint8_t * const data, uint32_t data_length, uint8_t * key, uint8_t * tag)
{

}

void blfs_globalversion_verify(uint64_t id, uint64_t global_version)
{

}

void blfs_globalversion_commit(uint64_t id, uint64_t global_version)
{

}

void blfs_KDF_generate_salt(uint8_t generated_salt)
{

}
