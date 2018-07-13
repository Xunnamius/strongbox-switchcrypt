#include "cipher/_chacha_neon.h"

void sc_generic_chacha_neon_crypt_data(chacha_neon_variant variant,
                                       const blfs_swappable_cipher_t * sc,
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

    // TODO:!
    (void) intrablock_offset;
    (void) num_blocks;
    (void) block_read_upper_bound;
    (void) kcs_keycount;

    uint8_t * zero_str = calloc(zero_str_length, sizeof(*zero_str));

    if(zero_str == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    IFDEBUG(assert(BLFS_CRYPTO_BYTES_CHACHA20_KEY == BLFS_CRYPTO_BYTES_KDF_OUT));

    if(crypto_stream_chacha20_xor_ic(
            xor_str,
            zero_str,
            zero_str_length,
            kcs_keycount_ptr,
            interblock_offset,
            nugget_key) != 0)
    {
        Throw(EXCEPTION_CHACHA20_BAD_RETVAL);
    }

    free(zero_str);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void sc_impl_chacha_neon(blfs_swappable_cipher_t * sc)
{
    sc->name = "Chacha (with NEON optimizations) (partially initialized)";

    sc->key_size_bytes = 0;
    sc->nonce_size_bytes = 0;
    sc->output_size_bytes = 0;
    sc->enum_id = 0;

    sc->crypt_custom = NULL;
    sc->read_handle = NULL;
    sc->write_handle = NULL;
}
