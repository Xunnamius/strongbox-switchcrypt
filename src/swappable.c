/**
 * <description>
 *
 * @author Bernard Dickens
 */

#include "swappable.h"

void blfs_get_stream_cipher(blfs_stream_cipher_t * sc, stream_cipher_e stream_cipher)
{
    switch(stream_cipher)
    {
        case sc_default:
        case sc_chacha20:
        {
            sc_impl_chacha20(sc);
            break;
        }

        case sc_aes128_ctr:
        {
            sc_impl_aes128_ctr(sc);
            break;
        }

        case sc_aes256_ctr:
        {
            sc_impl_aes256_ctr(sc);
            break;
        }

        case sc_salsa8:
        {
            sc_impl_salsa8(sc);
            break;
        }

        case sc_salsa12:
        {
            sc_impl_salsa12(sc);
            break;
        }

        case sc_salsa20:
        {
            sc_impl_salsa20(sc);
            break;
        }

        case sc_hc128:
        {
            sc_impl_hc128(sc);
            break;
        }

        case sc_rabbit:
        {
            sc_impl_rabbit(sc);
            break;
        }

        case sc_sosemanuk:
        {
            sc_impl_sosemanuk(sc);
            break;
        }

        case sc_chacha8_neon:
        {
            sc_impl_chacha8_neon(sc);
            break;
        }

        case sc_chacha12_neon:
        {
            sc_impl_chacha12_neon(sc);
            break;
        }

        case sc_chacha20_neon:
        {
            sc_impl_chacha20_neon(sc);
            break;
        }

        case sc_freestyle_fast:
        {
            sc_impl_freestyle_fast(sc);
            break;
        }

        case sc_freestyle_balanced:
        {
            sc_impl_freestyle_balanced(sc);
            break;
        }

        case sc_freestyle_secure:
        {
            sc_impl_freestyle_secure(sc);
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

    IFDEBUG(dzlog_info(":cipher stream context loaded successfully:"));
    IFDEBUG(dzlog_info("active cipher: %s", sc->name));
}

stream_cipher_e blfs_stream_string_to_cipher(const char * stream_cipher_str)
{
    stream_cipher_e cipher = sc_not_impl;

    if(strcmp(stream_cipher_str, "sc_default") == 0)
        cipher = sc_default;

    else if(strcmp(stream_cipher_str, "sc_aes128_ctr") == 0)
        cipher = sc_aes128_ctr;
    
    else if(strcmp(stream_cipher_str, "sc_aes256_ctr") == 0)
        cipher = sc_aes256_ctr;

    else if(strcmp(stream_cipher_str, "sc_salsa8") == 0)
        cipher = sc_salsa8;
    
    else if(strcmp(stream_cipher_str, "sc_salsa12") == 0)
        cipher = sc_salsa12;

    else if(strcmp(stream_cipher_str, "sc_salsa20") == 0)
        cipher = sc_salsa20;

    else if(strcmp(stream_cipher_str, "sc_hc128") == 0)
        cipher = sc_hc128;

    else if(strcmp(stream_cipher_str, "sc_rabbit") == 0)
        cipher = sc_rabbit;
    
    else if(strcmp(stream_cipher_str, "sc_sosemanuk") == 0)
        cipher = sc_sosemanuk;
    
    else if(strcmp(stream_cipher_str, "sc_chacha20") == 0)
        cipher = sc_chacha20;

    else if(strcmp(stream_cipher_str, "sc_chacha8_neon") == 0)
        cipher = sc_chacha8_neon;

    else if(strcmp(stream_cipher_str, "sc_chacha12_neon") == 0)
        cipher = sc_chacha12_neon;
    
    else if(strcmp(stream_cipher_str, "sc_chacha20_neon") == 0)
        cipher = sc_chacha20_neon;
    
    else if(strcmp(stream_cipher_str, "sc_freestyle_fast") == 0)
        cipher = sc_freestyle_fast;
    
    else if(strcmp(stream_cipher_str, "sc_freestyle_balanced") == 0)
        cipher = sc_freestyle_balanced;
    
    else if(strcmp(stream_cipher_str, "sc_freestyle_secure") == 0)
        cipher = sc_freestyle_secure;

    else
        Throw(EXCEPTION_STRING_TO_CIPHER_FAILED);

    return cipher;
}

void blfs_swappable_crypt(blfs_stream_cipher_t * stream_cipher,
                          uint8_t * crypted_data,
                          const uint8_t * data,
                          const uint32_t data_length,
                          const uint8_t * nugget_key,
                          const uint64_t kcs_keycount,
                          const uint64_t nugget_internal_offset)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint64_t interblock_offset = nugget_internal_offset / stream_cipher->output_size_bytes;
    uint64_t intrablock_offset = nugget_internal_offset % stream_cipher->output_size_bytes;
    uint64_t num_blocks = CEIL((intrablock_offset + data_length), stream_cipher->output_size_bytes);
    uint64_t zero_str_length = num_blocks * stream_cipher->output_size_bytes;
    uint64_t block_read_upper_bound = intrablock_offset + data_length;

    IFDEBUG(dzlog_debug("data in: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(data, MIN(64U, data_length)));

    const uint8_t * const kcs_keycount_ptr = (const uint8_t *) &kcs_keycount;

    IFDEBUG(dzlog_debug("%s", output_name));
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
    IFDEBUG(assert(stream_cipher->crypt_nugget != stream_cipher->crypt_data));

    if(stream_cipher->crypt_nugget != NULL)
    {
        IFDEBUG(dzlog_debug("crypt_handle is NOT NULL!"));
        IFDEBUG(dzlog_debug(">>>> entering LAMBDA crypt handle function"));

        stream_cipher->crypt_nugget(
            (void *) stream_cipher,
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

        stream_cipher->crypt_data(
            (void *) stream_cipher,
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
