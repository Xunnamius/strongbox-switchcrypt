/**
 * <description>
 *
 * @author Bernard Dickens
 */

#include "swappable.h"

void blfs_set_cipher_ctx(blfs_swappable_cipher_t * sc_ctx, swappable_cipher_e sc)
{
    sc_ctx->name = "<uninitialized>";
    
    sc_ctx->enum_id = 0;
    sc_ctx->output_size_bytes = 0;
    sc_ctx->key_size_bytes = 0;
    sc_ctx->nonce_size_bytes = 0;
    sc_ctx->requested_md_bytes_per_nugget = 0;

    sc_ctx->crypt_data = NULL;
    sc_ctx->crypt_custom = NULL;
    sc_ctx->read_handle = NULL;
    sc_ctx->write_handle = NULL;
    sc_ctx->calc_handle = NULL;

    switch(sc)
    {
        case sc_default:
        case sc_chacha20:
        {
            sc_impl_chacha20(sc_ctx);
            break;
        }

        case sc_aes128_ctr:
        {
            sc_impl_aes128_ctr(sc_ctx);
            break;
        }

        case sc_aes256_ctr:
        {
            sc_impl_aes256_ctr(sc_ctx);
            break;
        }

        case sc_aes256_xts:
        {
            sc_impl_aes256_xts(sc_ctx);
            break;
        }

        case sc_salsa8:
        {
            sc_impl_salsa8(sc_ctx);
            break;
        }

        case sc_salsa12:
        {
            sc_impl_salsa12(sc_ctx);
            break;
        }

        case sc_salsa20:
        {
            sc_impl_salsa20(sc_ctx);
            break;
        }

        case sc_hc128:
        {
            sc_impl_hc128(sc_ctx);
            break;
        }

        case sc_rabbit:
        {
            sc_impl_rabbit(sc_ctx);
            break;
        }

        case sc_sosemanuk:
        {
            sc_impl_sosemanuk(sc_ctx);
            break;
        }

        case sc_chacha8_neon:
        {
            sc_impl_chacha8_neon(sc_ctx);
            break;
        }

        case sc_chacha12_neon:
        {
            sc_impl_chacha12_neon(sc_ctx);
            break;
        }

        case sc_chacha20_neon:
        {
            sc_impl_chacha20_neon(sc_ctx);
            break;
        }

        case sc_freestyle_fast:
        {
            sc_impl_freestyle_fast(sc_ctx);
            break;
        }

        case sc_freestyle_balanced:
        {
            sc_impl_freestyle_balanced(sc_ctx);
            break;
        }

        case sc_freestyle_secure:
        {
            sc_impl_freestyle_secure(sc_ctx);
            break;
        }

        case sc_not_impl:
        {
            Throw(EXCEPTION_SC_ALGO_NO_IMPL);
            break;
        }

        default:
        {
            Throw(EXCEPTION_SC_ALGO_NOT_FOUND);
            break;
        }
    }

    IFDEBUG(dzlog_info("[new cipher context loaded successfully]"));
    IFDEBUG(dzlog_info("active cipher: %s", sc_ctx->name));

    if((sc_ctx->crypt_custom && sc_ctx->crypt_data)
        || ((sc_ctx->crypt_data || sc_ctx->crypt_custom) && (sc_ctx->read_handle || sc_ctx->write_handle))
        || (sc_ctx->crypt_custom == NULL && sc_ctx->crypt_data == NULL && sc_ctx->read_handle == NULL && sc_ctx->write_handle == NULL)
        || (sc_ctx->name == NULL || sc_ctx->enum_id <= 0 || (sc != sc_default && sc_ctx->enum_id != sc))
    )
    {
        IFDEBUG(dzlog_fatal("ERROR: cipher has an invalid configuration, please report this"));
        IFDEBUG(dzlog_debug("valid configs are: `crypt_data` != NULL, `crypt_custom` != NULL, or `read_handle` AND `write_handle` != NULL"));
        Throw(EXCEPTION_SC_BAD_CIPHER);
    }
    
    IFDEBUG(dzlog_debug("(cipher has valid configuration!)"));
}

swappable_cipher_e blfs_ident_string_to_cipher(const char * sc_str)
{
    swappable_cipher_e cipher = sc_not_impl;

    if(strcmp(sc_str, "sc_default") == 0)
        cipher = sc_default;

    else if(strcmp(sc_str, "sc_aes128_ctr") == 0)
        cipher = sc_aes128_ctr;
    
    else if(strcmp(sc_str, "sc_aes256_ctr") == 0)
        cipher = sc_aes256_ctr;
    
    else if(strcmp(sc_str, "sc_aes256_xts") == 0)
        cipher = sc_aes256_xts;

    else if(strcmp(sc_str, "sc_salsa8") == 0)
        cipher = sc_salsa8;
    
    else if(strcmp(sc_str, "sc_salsa12") == 0)
        cipher = sc_salsa12;

    else if(strcmp(sc_str, "sc_salsa20") == 0)
        cipher = sc_salsa20;

    else if(strcmp(sc_str, "sc_hc128") == 0)
        cipher = sc_hc128;

    else if(strcmp(sc_str, "sc_rabbit") == 0)
        cipher = sc_rabbit;
    
    else if(strcmp(sc_str, "sc_sosemanuk") == 0)
        cipher = sc_sosemanuk;
    
    else if(strcmp(sc_str, "sc_chacha20") == 0)
        cipher = sc_chacha20;

    else if(strcmp(sc_str, "sc_chacha8_neon") == 0)
        cipher = sc_chacha8_neon;

    else if(strcmp(sc_str, "sc_chacha12_neon") == 0)
        cipher = sc_chacha12_neon;
    
    else if(strcmp(sc_str, "sc_chacha20_neon") == 0)
        cipher = sc_chacha20_neon;
    
    else if(strcmp(sc_str, "sc_freestyle_fast") == 0)
        cipher = sc_freestyle_fast;
    
    else if(strcmp(sc_str, "sc_freestyle_balanced") == 0)
        cipher = sc_freestyle_balanced;
    
    else if(strcmp(sc_str, "sc_freestyle_secure") == 0)
        cipher = sc_freestyle_secure;

    else
        Throw(EXCEPTION_STRING_TO_CIPHER_FAILED);

    return cipher;
}

void blfs_swappable_crypt(blfs_swappable_cipher_t * sc,
                          uint8_t * crypted_data,
                          const uint8_t * data,
                          const uint32_t data_length,
                          const uint8_t * nugget_key,
                          const uint64_t kcs_keycount,
                          const uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint64_t interblock_offset = nugget_internal_offset / sc->output_size_bytes;
    uint64_t intrablock_offset = nugget_internal_offset % sc->output_size_bytes;
    uint64_t num_blocks = CEIL((intrablock_offset + data_length), sc->output_size_bytes);
    uint64_t zero_str_length = num_blocks * sc->output_size_bytes;
    uint64_t block_read_upper_bound = intrablock_offset + data_length;

    IFDEBUG(dzlog_debug("data in: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(data, MIN(64U, data_length)));

    const uint8_t * const kcs_keycount_ptr = (const uint8_t *) &kcs_keycount;

    IFDEBUG(dzlog_debug("algorithm: %s (%i)", sc->name, sc->enum_id));
    IFDEBUG(dzlog_debug("keycount = %"PRIu64, kcs_keycount));
    IFDEBUG(dzlog_debug("keycount hex x2 (should match):"));
    IFDEBUG(hdzlog_debug(&(kcs_keycount), BLFS_CRYPTO_BYTES_CHACHA20_NONCE));
    IFDEBUG(hdzlog_debug(kcs_keycount_ptr, BLFS_CRYPTO_BYTES_CHACHA20_NONCE));
    IFDEBUG(dzlog_debug("data_length = %"PRIu32, data_length));
    IFDEBUG(dzlog_debug("nugget_internal_offset = %"PRIu64, nugget_internal_offset));
    IFDEBUG(dzlog_debug("interblock_offset = %"PRIu64, interblock_offset));
    IFDEBUG(dzlog_debug("intrablock_offset = %"PRIu64, intrablock_offset));
    IFDEBUG(dzlog_debug("num_blocks = %"PRIu64, num_blocks));
    IFDEBUG(dzlog_debug("zero_str_length = %"PRIu64, zero_str_length));
    IFDEBUG(dzlog_debug("block_read_upper_bound = %"PRIu64, block_read_upper_bound));
    IFDEBUG(dzlog_debug("block read range = (%"PRIu64" to %"PRIu64" - 1) <=> %"PRIu64" [total, zero indexed]",
        intrablock_offset, block_read_upper_bound, block_read_upper_bound - intrablock_offset));

    IFDEBUG(assert(zero_str_length >= data_length));

    if(sc->crypt_custom != NULL)
    {
        IFDEBUG(dzlog_debug("crypt_handle is NOT NULL!"));
        IFDEBUG(dzlog_debug(">>>> entering LAMBDA crypt handle function"));

        sc->crypt_custom(
            (void *) sc,
            interblock_offset,
            intrablock_offset,
            num_blocks,
            zero_str_length,
            block_read_upper_bound,
            nugget_key,
            kcs_keycount,
            kcs_keycount_ptr
        );

        IFDEBUG(dzlog_debug("<<<< leaving LAMBDA crypt handle function"));
    }

    else
    {
        IFDEBUG(dzlog_debug("crypt_handle is NULL"));

        // ! be sure to maintain complete control over this pointer and its memory
        uint8_t * xor_str = calloc(zero_str_length, sizeof(*xor_str));

        if(xor_str == NULL)
            Throw(EXCEPTION_ALLOC_FAILURE);

        IFDEBUG(dzlog_debug(">>>> entering LAMBDA data handle function"));

        sc->crypt_data(
            (void *) sc,
            interblock_offset,
            intrablock_offset,
            num_blocks,
            zero_str_length,
            block_read_upper_bound,
            nugget_key,
            kcs_keycount,
            kcs_keycount_ptr,
            xor_str
        );

        IFDEBUG(dzlog_debug("<<<< leaving LAMBDA data handle function"));

        for(uint64_t i = intrablock_offset, j = block_read_upper_bound, k = 0; i < j; ++i, ++k)
        {
            IFDEBUG(assert(k < data_length));
            crypted_data[k] = data[k] ^ xor_str[i];
        }

        free(xor_str);
    }

    IFDEBUG(dzlog_debug("crypted data out: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(crypted_data, MIN(64U, data_length)));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void blfs_calculate_cipher_bytes_per_nugget(blfs_swappable_cipher_t * sc_ctx, buselfs_state_t * buselfs_state)
{
    sc_ctx->requested_md_bytes_per_nugget = sc_ctx->calc_handle ? sc_ctx->calc_handle(buselfs_state) : 0;
}
