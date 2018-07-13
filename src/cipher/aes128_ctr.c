#include "cipher/aes128_ctr.h"

void sc_impl_aes128_ctr(blfs_swappable_cipher_t * sc)
{
    sc_impl_aes(sc);
    sc->crypt_data = sc_generic_aes_crypt_data;

    sc->name = "128-bit AES in CTR mode";
    sc->enum_id = sc_aes128_ctr;

    sc->key_size_bytes = BLFS_CRYPTO_BYTES_AES128_KEY;
    sc->nonce_size_bytes = BLFS_CRYPTO_BYTES_AES128_IV;
    sc->output_size_bytes = BLFS_CRYPTO_BYTES_AES128_BLOCK;
}
