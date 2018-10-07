#include "cipher/rabbit.h"
#include "libestream/rabbit.h"

static void crypt_data(const blfs_swappable_cipher_t * sc,
                       uint64_t interblock_offset,
                       uint64_t intrablock_offset,
                       uint64_t num_blocks,
                       uint64_t zero_str_length,
                       uint64_t block_read_upper_bound,
                       const uint8_t * nugget_key,
                       const uint64_t kcs_keycount,
                       const uint8_t * const kcs_keycount_ptr,
                       uint8_t * xor_str)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    (void) intrablock_offset;
    (void) block_read_upper_bound;
    (void) zero_str_length;
    (void) kcs_keycount;

    rabbit_state key_state;
    rabbit_state iv_state;

    uint64_t counter = interblock_offset;
    uint8_t raw_key[BLFS_CRYPTO_BYTES_RABBIT_KEY];
    // uint8_t iv[BLFS_CRYPTO_BYTES_RABBIT_IV]; // ! handled by the 8 byte keycount (predictable keycounts, is problem?)

    memcpy(raw_key, nugget_key, sizeof(raw_key)); // ! cutting off the key, bad bad not good! Need key schedule!

    rabbit_init_key(&key_state, raw_key);

    for(uint64_t i = 0; i < num_blocks; i++, counter++)
    {
        // ! NOTE THAT THIS IMPLEMENTATION IS CERTAINLY NOT SECURE (we discard keycount here for expedience)
        // ! Possible remedy: hash the keycount and the counter and use that output as IV
        (void) kcs_keycount_ptr;

        rabbit_init_iv(&iv_state, &key_state, (uint8_t *) &counter);
        rabbit_extract(&iv_state, xor_str + (i * sc->output_size_bytes));
    }

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void sc_impl_rabbit(blfs_swappable_cipher_t * sc)
{
    sc->crypt_data = &crypt_data;

    sc->name = "Rabbit";
    sc->enum_id = sc_rabbit;

    sc->key_size_bytes = BLFS_CRYPTO_BYTES_RABBIT_KEY;
    sc->nonce_size_bytes = BLFS_CRYPTO_BYTES_RABBIT_IV;
    sc->output_size_bytes = BLFS_CRYPTO_BYTES_RABBIT_BLOCK;
}
