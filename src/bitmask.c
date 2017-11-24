/*
 * Aligned bit mask manipulation and analysis tools
 *
 * @author Bernard Dickens
 */

#include "bitmask.h"

#include <assert.h>
#include <string.h>
#include <inttypes.h>

bitmask_t * bitmask_init(uint8_t * init_mask, size_t length)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(length == 0 || SIZE_MAX / sizeof(uint8_t) < length)
        Throw(EXCEPTION_SIZE_T_OUT_OF_BOUNDS);

    bitmask_t * bitmask = (bitmask_t *) malloc(sizeof(bitmask_t));

    if(bitmask == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    bitmask->byte_length = length;
    bitmask->mask = calloc(length, sizeof(uint8_t));

    if(bitmask->mask == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    if(init_mask != NULL)
        memcpy(bitmask->mask, init_mask, length);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return bitmask;
}

void bitmask_fini(bitmask_t * bitmask)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    free(bitmask->mask);
    free(bitmask);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void bitmask_set_bit(bitmask_t * bitmask, uint_fast32_t index)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint_fast32_t mask_index = (index / 8);
    uint_fast32_t bit_index = (index % 8);

    if(bitmask->byte_length < mask_index + 1)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    IFDEBUG(uint8_t old_val_at_index = bitmask->mask[mask_index]);
    IFDEBUG(dzlog_debug(
                        "bitmask->mask[mask_index => %"PRIuFAST32"] |= 1U << (7 - %"PRIuFAST32") => 0x%x",
                        mask_index, bit_index, 1U << (7 - bit_index)));

    bitmask->mask[mask_index] |= 1U << (7 - bit_index);

    IFDEBUG(dzlog_debug("bitmask->mask[mask_index] (was 0x%x, now 0x%x)", old_val_at_index, bitmask->mask[mask_index]));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void bitmask_clear_bit(bitmask_t * bitmask, uint_fast32_t index)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint_fast32_t mask_index = (index / 8);
    uint_fast32_t bit_index = (index % 8);

    if(bitmask->byte_length < mask_index + 1)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    IFDEBUG(uint8_t old_val_at_index = bitmask->mask[mask_index]);
    IFDEBUG(dzlog_debug(
                        "bitmask->mask[mask_index => %"PRIuFAST32"] &= ~(1U << (7 - %"PRIuFAST32") => 0x%x",
                        mask_index, bit_index, ~(1U << (7 - bit_index))));

    bitmask->mask[mask_index] &= ~(1U << (7 - bit_index));

    IFDEBUG(dzlog_debug("bitmask->mask[mask_index] (was 0x%x, now 0x%x)", old_val_at_index, bitmask->mask[mask_index]));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void bitmask_toggle_bit(bitmask_t * bitmask, uint_fast32_t index)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint_fast32_t mask_index = (index / 8);
    uint_fast32_t bit_index = (index % 8);

    if(bitmask->byte_length < mask_index + 1)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    IFDEBUG(uint8_t old_val_at_index = bitmask->mask[mask_index]);
    IFDEBUG(dzlog_debug(
                       "bitmask->mask[mask_index => %"PRIuFAST32"] ^= 1U << (7 - %"PRIuFAST32") => 0x%x",
                        mask_index, bit_index, 1U << (7 - bit_index)));

    bitmask->mask[mask_index] ^= 1U << (7 - bit_index);

    IFDEBUG(dzlog_debug("bitmask->mask[mask_index] (was 0x%x, now 0x%x)", old_val_at_index, bitmask->mask[mask_index]));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void bitmask_set_mask(bitmask_t * bitmask)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    free(bitmask->mask);
    bitmask->mask = malloc(bitmask->byte_length);

    if(bitmask->mask == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    memset(bitmask->mask, 0xFF, bitmask->byte_length);

    IFDEBUG(dzlog_debug("bitmask->mask now:"));
    IFDEBUG(hdzlog_debug(bitmask->mask, bitmask->byte_length));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void bitmask_clear_mask(bitmask_t * bitmask)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    free(bitmask->mask);
    bitmask->mask = calloc(bitmask->byte_length, sizeof(uint8_t));

    if(bitmask->mask == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    IFDEBUG(dzlog_debug("bitmask->mask now:"));
    IFDEBUG(hdzlog_debug(bitmask->mask, bitmask->byte_length));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

int bitmask_is_bit_set(bitmask_t * bitmask, uint_fast32_t index)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint_fast32_t mask_index = (index / 8);
    uint_fast32_t bit_index = (index % 8);

    if(bitmask->byte_length < mask_index + 1)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    IFDEBUG(dzlog_debug("RETURN: (bitmask->mask[mask_index => %"PRIuFAST32"] >> (7 - %"PRIuFAST32")) & 1 => 0x%x",
                        mask_index, bit_index, (bitmask->mask[mask_index] >> (7 - bit_index)) & 1));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return (bitmask->mask[mask_index] >> (7 - bit_index)) & 1;
}

void bitmask_set_bits(bitmask_t * bitmask, uint_fast32_t start_index, uint_fast32_t length)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint_fast32_t mask_start_index = (start_index / 8);
    uint_fast32_t bit_start_index = (start_index % 8);

    if(bitmask->byte_length <= mask_start_index || bitmask->byte_length * 8 < start_index + length)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    if(!length)
    {
        IFDEBUG(dzlog_debug("RETURN: length = 0!"));
        return;
    }

    uint_fast64_t mask_count = (bit_start_index + length - 1) / 8;
    int_fast64_t bits_remaining = ((int_fast64_t)(length)) - (8 - bit_start_index);

    IFDEBUG(uint8_t old_val_at_index = bitmask->mask[mask_start_index]);
    IFDEBUG(dzlog_debug(
                        "bitmask->mask[mask_start_index => %"PRIuFAST32"] "
                        "|= ((1U << (8 - %"PRIuFAST32")) - 1) ^ (%"PRIuFAST64" < 0 ? ((1U << abs(%"PRIuFAST64")) - 1) : 0)) => 0x%x ^ 0x%x",
                        mask_start_index,
                        bit_start_index,
                        bits_remaining,
                        bits_remaining,
                        ((1U << (8 - bit_start_index)) - 1),
                        (bits_remaining < 0 ? ((1U << abs(bits_remaining)) - 1) : 0)));

    bitmask->mask[mask_start_index] |= ((1U << (8 - bit_start_index)) - 1) ^ (bits_remaining < 0 ? ((1U << abs(bits_remaining)) - 1) : 0);

    IFDEBUG(dzlog_debug("bitmask->mask[mask_start_index] (was 0x%x, now 0x%x)", old_val_at_index, bitmask->mask[mask_start_index]));

    for(uint_fast64_t i = 1; mask_count--; ++i, bits_remaining -= 8)
    {
        assert(bits_remaining > 0);

        IFDEBUG(uint8_t old_val_at_index_inner = bitmask->mask[i]);
        IFDEBUG(dzlog_debug(
                            "bitmask->mask[i => %"PRIuFAST64"] "
                            "|= ~((1U << (8 - (%"PRIuFAST64" < 8 ? %"PRIuFAST64" : 8))) - 1) => 0x%x",
                            i, bits_remaining, bits_remaining, ~((1U << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1)));

        bitmask->mask[i] |= ~((1U << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1);

        IFDEBUG(dzlog_debug("bitmask->mask[i] (was 0x%x, now 0x%x)", old_val_at_index_inner, bitmask->mask[i]));
    }

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void bitmask_clear_bits(bitmask_t * bitmask, uint_fast32_t start_index, uint_fast32_t length)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint_fast32_t mask_start_index = (start_index / 8);
    uint_fast32_t bit_start_index = (start_index % 8);

    if(bitmask->byte_length <= mask_start_index || bitmask->byte_length * 8 < start_index + length)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    if(!length)
    {
        IFDEBUG(dzlog_debug("RETURN: length = 0!"));
        return;
    }

    uint_fast64_t mask_count = (bit_start_index + length - 1) / 8;
    int_fast64_t bits_remaining = ((int_fast64_t)(length)) - (8 - bit_start_index);

    IFDEBUG(uint8_t old_val_at_index = bitmask->mask[mask_start_index]);
    IFDEBUG(dzlog_debug(
                        "bitmask->mask[mask_start_index => %"PRIuFAST32"] "
                        "&= ~(((1U << (8 - %"PRIuFAST32")) - 1) ^ (%"PRIuFAST64" < 0 ? ((1U << abs(%"PRIuFAST64")) - 1) : 0)) => 0x%x ^ 0x%x",
                        mask_start_index,
                        bit_start_index,
                        bits_remaining,
                        bits_remaining,
                        ~((1U << (8 - bit_start_index)) - 1),
                        (bits_remaining < 0 ? ((1U << abs(bits_remaining)) - 1) : 0)));

    bitmask->mask[mask_start_index] &= ~(((1U << (8 - bit_start_index)) - 1) ^ (bits_remaining < 0 ? ((1U << abs(bits_remaining)) - 1) : 0));

    IFDEBUG(dzlog_debug("bitmask->mask[mask_start_index] (was 0x%x, now 0x%x)", old_val_at_index, bitmask->mask[mask_start_index]));

    for(uint_fast64_t i = mask_start_index + 1; mask_count--; ++i, bits_remaining -= 8)
    {
        assert(bits_remaining > 0);

        IFDEBUG(uint8_t old_val_at_index_inner = bitmask->mask[i]);
        IFDEBUG(dzlog_debug(
                            "bitmask->mask[i => %"PRIuFAST64"] "
                            "&= (1U << (8 - (%"PRIuFAST64" < 8 ? %"PRIuFAST64" : 8))) - 1 => 0x%x",
                            i, bits_remaining, bits_remaining, (1U << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1));

        bitmask->mask[i] &= (1U << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1;

        IFDEBUG(dzlog_debug("bitmask->mask[i] (was 0x%x, now 0x%x)", old_val_at_index_inner, bitmask->mask[i]));
    }

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void bitmask_toggle_bits(bitmask_t * bitmask, uint_fast32_t start_index, uint_fast32_t length)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint_fast32_t mask_start_index = (start_index / 8);
    uint_fast32_t bit_start_index = (start_index % 8);

    if(bitmask->byte_length <= mask_start_index || bitmask->byte_length * 8 < start_index + length)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    if(!length)
    {
        IFDEBUG(dzlog_debug("RETURN: length = 0!"));
        return;
    }

    uint_fast64_t mask_count = (bit_start_index + length - 1) / 8;
    int_fast64_t bits_remaining = ((int_fast64_t)(length)) - (8 - bit_start_index);

    IFDEBUG(uint8_t old_val_at_index = bitmask->mask[mask_start_index]);
    IFDEBUG(dzlog_debug(
                        "bitmask->mask[mask_start_index => %"PRIuFAST32"] "
                        "^= ((1U << (8 - %"PRIuFAST32")) - 1) ^ (%"PRIuFAST64" < 0 ? ((1U << abs(%"PRIuFAST64")) - 1) : 0) => 0x%x ^ 0x%x",
                        mask_start_index,
                        bit_start_index,
                        bits_remaining,
                        bits_remaining,
                        ((1U << (8 - bit_start_index)) - 1),
                        (bits_remaining < 0 ? ((1U << abs(bits_remaining)) - 1) : 0)));

    bitmask->mask[mask_start_index] ^= ((1U << (8 - bit_start_index)) - 1) ^ (bits_remaining < 0 ? ((1U << abs(bits_remaining)) - 1) : 0);

    IFDEBUG(dzlog_debug("bitmask->mask[mask_start_index] (was 0x%x, now 0x%x)", old_val_at_index, bitmask->mask[mask_start_index]));

    for(uint_fast64_t i = mask_start_index + 1; mask_count--; ++i, bits_remaining -= 8)
    {
        assert(bits_remaining > 0);

        IFDEBUG(uint8_t old_val_at_index_inner = bitmask->mask[i]);
        IFDEBUG(dzlog_debug(
                            "bitmask->mask[i => %"PRIuFAST64"] "
                            "^= ~((1U << (8 - (%"PRIuFAST64" < 8 ? %"PRIuFAST64" : 8))) - 1) => 0x%x",
                            i, bits_remaining, bits_remaining, ~((1U << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1)));
        IFDEBUG(dzlog_debug("bitmask->mask[i] (was 0x%x, now 0x%x)", old_val_at_index_inner, bitmask->mask[i]));

        bitmask->mask[i] ^= ~((1U << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1);

        IFDEBUG(dzlog_debug("bitmask->mask[i] (was 0x%x, now 0x%x)", old_val_at_index_inner, bitmask->mask[i]));
    }

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

int bitmask_are_bits_set(bitmask_t * bitmask, uint_fast32_t start_index, uint_fast32_t length)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint_fast32_t mask_start_index = (start_index / 8);
    uint_fast32_t bit_start_index = (start_index % 8);

    if(bitmask->byte_length <= mask_start_index || bitmask->byte_length * 8 < start_index + length)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    if(!length)
    {
        IFDEBUG(dzlog_debug("RETURN 0 (hardcoded): length = 0!"));
        return 0;
    }

    uint_fast64_t mask_count = (bit_start_index + length - 1) / 8;
    int_fast64_t bits_remaining = ((int_fast64_t)(length)) - (8 - bit_start_index);
    uint8_t is_set = 1;

    uint8_t filter = ((uint8_t)((1U << (8 - bit_start_index)) - 1)) ^ (bits_remaining < 0 ? ((1U << abs(bits_remaining)) - 1) : 0);

    IFDEBUG(uint8_t old_val_at_index = is_set);
    IFDEBUG(dzlog_debug(
                        "is_set = is_set && !((bitmask->mask[mask_start_index => %"PRIuFAST32"] & 0x%x) ^ 0x%x) => 0x%x & 0x%x",
                        mask_start_index,
                        filter,
                        filter,
                        is_set,
                        !((bitmask->mask[mask_start_index] & filter) ^ filter)));

    is_set = is_set && !((bitmask->mask[mask_start_index] & filter) ^ filter);

    IFDEBUG(dzlog_debug("is_set (was 0x%x, now 0x%x)", old_val_at_index, bitmask->mask[mask_start_index]));

    for(uint_fast64_t i = mask_start_index + 1; is_set && mask_count--; ++i, bits_remaining -= 8)
    {
        assert(bits_remaining > 0);

        uint8_t not_filter = ~(((1U << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1));

        IFDEBUG(uint8_t old_val_at_index_inner = is_set);
        IFDEBUG(dzlog_debug(
                        "is_set = is_set && !((bitmask->mask[i => %"PRIuFAST64"] & 0x%x) ^ 0x%x) => 0x%x & 0x%x",
                        i,
                        not_filter,
                        not_filter,
                        is_set,
                        !((bitmask->mask[i] & not_filter) ^ not_filter)));
        
        is_set = is_set && !((bitmask->mask[i] & not_filter) ^ not_filter);

        IFDEBUG(dzlog_debug("is_set (was 0x%x, now 0x%x)", old_val_at_index_inner, bitmask->mask[i]));
    }

    IFDEBUG(dzlog_debug("RETURN: is_set => 0x%x", is_set));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return is_set;
}

int bitmask_any_bits_set(bitmask_t * bitmask, uint_fast32_t start_index, uint_fast32_t length)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    uint_fast32_t mask_start_index = (start_index / 8);
    uint_fast32_t bit_start_index = (start_index % 8);

    if(bitmask->byte_length <= mask_start_index || bitmask->byte_length * 8 < start_index + length)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    if(!length)
    {
        IFDEBUG(dzlog_debug("RETURN 0 (hardcoded): length = 0!"));
        return 0;
    }

    uint_fast64_t mask_count = (bit_start_index + length - 1) / 8;
    int_fast64_t bits_remaining = ((int_fast64_t)(length)) - (8 - bit_start_index);

    uint8_t filter = ((uint8_t)((1U << (8 - bit_start_index)) - 1)) ^ (bits_remaining < 0 ? ((1U << abs(bits_remaining)) - 1) : 0);

    if(filter & bitmask->mask[mask_start_index])
    {
        IFDEBUG(dzlog_debug("RETURN: is_set => 1"));
        return 1;
    }

    for(uint_fast64_t i = mask_start_index + 1; mask_count--; ++i, bits_remaining -= 8)
    {
        assert(bits_remaining > 0);

        uint8_t not_filter = ~(((1U << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1));

        if(not_filter & bitmask->mask[i])
        {
            IFDEBUG(dzlog_debug("RETURN: is_set => 1"));
            return 1;
        }
    }

    IFDEBUG(dzlog_debug("RETURN: is_set => 0"));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return 0;
}
