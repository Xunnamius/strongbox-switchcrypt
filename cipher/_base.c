#include "_base.h"

void sc_generic_impl(sc_context_t * sc_context)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint64_t interblock_offset = sc_context->nugget_internal_offset / sc_context->output_size_bytes;
    uint64_t intrablock_offset = sc_context->nugget_internal_offset % sc_context->output_size_bytes;
    uint64_t num_blocks = CEIL((intrablock_offset + sc_context->data_length), sc_context->output_size_bytes);
    uint64_t zero_str_length = num_blocks * sc_context->output_size_bytes;
    uint64_t block_read_upper_bound = intrablock_offset + sc_context->data_length;

    IFDEBUG(dzlog_debug("data in: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(sc_context->data, MIN(64U, sc_context->data_length)));

    const uint8_t * const kcs_keycount_ptr = (const uint8_t *) &sc_context->kcs_keycount;

    IFDEBUG(dzlog_debug("%s", sc_context->output_name));
    IFDEBUG(dzlog_debug("keycount = %"PRIu64, sc_context->kcs_keycount));
    IFDEBUG(dzlog_debug("keycount hex x2 (should match):"));
    IFDEBUG(hdzlog_debug(&(sc_context->kcs_keycount), BLFS_CRYPTO_BYTES_CHACHA20_NONCE));
    IFDEBUG(hdzlog_debug(kcs_keycount_ptr, BLFS_CRYPTO_BYTES_CHACHA20_NONCE));
    IFDEBUG(dzlog_debug("data_length = %"PRIu32, sc_context->data_length));
    IFDEBUG(dzlog_debug("nugget_internal_offset = %"PRIu64, sc_context->nugget_internal_offset));
    IFDEBUG(dzlog_debug("interblock_offset = %"PRIu64, interblock_offset));
    IFDEBUG(dzlog_debug("intrablock_offset = %"PRIu64, intrablock_offset));
    IFDEBUG(dzlog_debug("num_blocks = %"PRIu64, num_blocks));
    IFDEBUG(dzlog_debug("zero_str_length = %"PRIu64, zero_str_length));
    IFDEBUG(dzlog_debug("block_read_upper_bound = %"PRIu64, block_read_upper_bound));
    IFDEBUG(dzlog_debug("block read range = (%"PRIu64" to %"PRIu64" - 1) <=> %"PRIu64" [total, zero indexed]",
        intrablock_offset, block_read_upper_bound, block_read_upper_bound - intrablock_offset));

    IFDEBUG(assert(zero_str_length >= sc_context->data_length));

    if(sc_context->crypt_handle != NULL)
    {
        IFDEBUG(dzlog_debug("sc_context->crypt_handle is NOT NULL!"));
        IFDEBUG(dzlog_debug(">>>> entering LAMBDA crypt_handle function"));

        sc_context->crypt_handle(
            (void *) sc_context,
            interblock_offset,
            intrablock_offset,
            num_blocks,
            zero_str_length,
            block_read_upper_bound,
            kcs_keycount_ptr
        );

        IFDEBUG(dzlog_debug("<<<< leaving LAMBDA crypt_handle function"));
    }

    else
    {
        IFDEBUG(dzlog_debug("sc_context->crypt_handle is NULL"));

        // ! be sure to maintain complete control over this pointer and its memory
        uint8_t * xor_str = calloc(zero_str_length, sizeof(*xor_str));

        if(xor_str == NULL)
            Throw(EXCEPTION_ALLOC_FAILURE);

        IFDEBUG(dzlog_debug(">>>> entering LAMBDA data_handle function"));

        sc_context->data_handle(
            (void *) sc_context,
            interblock_offset,
            intrablock_offset,
            num_blocks,
            zero_str_length,
            block_read_upper_bound,
            kcs_keycount_ptr,
            xor_str
        );

        IFDEBUG(dzlog_debug("<<<< leaving LAMBDA data_handle function"));

        for(uint64_t i = intrablock_offset, j = block_read_upper_bound, k = 0; i < j; ++i, ++k)
        {
            IFDEBUG(assert(k < sc_context->data_length));
            sc_context->crypted_data[k] = sc_context->data[k] ^ xor_str[i];
        }

        free(xor_str);
    }

    IFDEBUG(dzlog_debug("crypted data out: (first 64 bytes):"));
    IFDEBUG(hdzlog_debug(sc_context->crypted_data, MIN(64U, sc_context->data_length)));

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
