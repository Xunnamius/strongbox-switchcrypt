#include "cipher/aes256_ctr.h"

void sc_impl_aes256_ctr(blfs_stream_cipher_t * sc)
{
    sc_impl_aes(sc);
    sc->crypt_data = &sc_generic_aes_crypt_data;
}
