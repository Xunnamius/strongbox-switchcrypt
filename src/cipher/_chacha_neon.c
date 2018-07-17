#include "cipher/_chacha_neon.h"
#include "chacha-opt/app/include/chacha.h"

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

    size_t rounds = (size_t) variant;

    IFDEBUG(assert(rounds == 8 || rounds == 12 || rounds == 20));

    (void) intrablock_offset;
    (void) num_blocks;
    (void) block_read_upper_bound;
    (void) kcs_keycount;

    uint8_t * zero_str = calloc(zero_str_length, sizeof(*zero_str));
    uint8_t * original_zero_str = zero_str;

    if(zero_str == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);
    
    chacha_state S;
    chacha_key key;
    chacha_iv iv;

    memcpy(key.b, nugget_key, sc->key_size_bytes);
    memcpy(iv.b, kcs_keycount_ptr, sc->nonce_size_bytes);
    
    chacha_init(&S, &key, &iv, rounds);

    chacha_state_internal * state = (chacha_state_internal *) &S;
    IFDEBUG(assert(sizeof interblock_offset == 8));
	memcpy(state->s + 32, &interblock_offset, sizeof interblock_offset);

    while(zero_str_length >= sc->output_size_bytes)
    {
        IFDEBUG(assert(zero_str_length > 0));

        size_t bytes_out = chacha_update(&S, zero_str, xor_str, zero_str_length);

        assert(bytes_out > 0);

        zero_str_length -= bytes_out;
        zero_str += bytes_out;
        xor_str += bytes_out;
    }

    if(zero_str_length)
        zero_str_length -= chacha_final(&S, xor_str);

    IFDEBUG(assert(zero_str_length == 0));

    free(original_zero_str);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void sc_impl_chacha_neon(blfs_swappable_cipher_t * sc)
{
    sc->name = "Chacha (with NEON optimizations) (partially initialized)";
}
