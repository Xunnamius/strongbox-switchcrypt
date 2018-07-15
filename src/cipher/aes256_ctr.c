#include "cipher/aes256_ctr.h"

void sc_impl_aes256_ctr(blfs_swappable_cipher_t * sc)
{
    sc_impl_aes(sc);
    sc->crypt_data = &sc_generic_aes_crypt_data;

    sc->name = "256-bit AES in CTR mode";
    sc->enum_id = sc_aes256_ctr;

    sc->key_size_bytes = BLFS_CRYPTO_BYTES_AES256_KEY;
    sc->nonce_size_bytes = BLFS_CRYPTO_BYTES_AES256_IV;
    sc->output_size_bytes = BLFS_CRYPTO_BYTES_AES256_BLOCK;
}
