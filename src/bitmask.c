/*
 * Aligned bit mask manipulation and analysis tools
 *
 * @author Bernard Dickens
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "bitmask.h"

bitmask_t * bitmask_init(size_t length)
{
    if(length == 0 || SIZE_MAX / sizeof(uint_fast8_t) < length)
        Throw(EXCEPTION_SIZE_T_OUT_OF_BOUNDS);

    bitmask_t * bitmask = (bitmask_t *) malloc(sizeof(bitmask_t));

    if(bitmask == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    bitmask->byte_length = length;
    bitmask->mask = calloc(length, sizeof(char));

    if(bitmask->mask == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    return bitmask;
}

void bitmask_fini(bitmask_t * bitmask)
{
    free(bitmask->mask);
    free(bitmask);
}

void bitmask_set_bit(bitmask_t * bitmask, uint_fast32_t index)
{
    uint_fast32_t mask_index = (index / 8);
    uint_fast32_t bit_index = (index % 8);

    if(bitmask->byte_length < mask_index + 1)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    bitmask->mask[mask_index] |= 1 << (7 - bit_index);
}

void bitmask_clear_bit(bitmask_t * bitmask, uint_fast32_t index)
{
    uint_fast32_t mask_index = (index / 8);
    uint_fast32_t bit_index = (index % 8);

    if(bitmask->byte_length < mask_index + 1)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    bitmask->mask[mask_index] &= ~(1 << (7 - bit_index));
}

void bitmask_toggle_bit(bitmask_t * bitmask, uint_fast32_t index)
{
    uint_fast32_t mask_index = (index / 8);
    uint_fast32_t bit_index = (index % 8);

    if(bitmask->byte_length < mask_index + 1)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    bitmask->mask[mask_index] ^= 1 << (7 - bit_index);
}

void bitmask_set_mask(bitmask_t * bitmask)
{
    free(bitmask->mask);
    bitmask->mask = malloc(bitmask->byte_length);
    memset(bitmask->mask, 0xFF, bitmask->byte_length);
}

void bitmask_clear_mask(bitmask_t * bitmask)
{
    free(bitmask->mask);
    bitmask->mask = calloc(bitmask->byte_length, sizeof(char));
}

int bitmask_is_bit_set(bitmask_t * bitmask, uint_fast32_t index)
{
    uint_fast32_t mask_index = (index / 8);
    uint_fast32_t bit_index = (index % 8);

    if(bitmask->byte_length < mask_index + 1)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    return (bitmask->mask[mask_index] >> (7 - bit_index)) & 1;
}

void bitmask_set_bits(bitmask_t * bitmask, uint_fast32_t start_index, uint_fast32_t length)
{
    uint_fast32_t mask_start_index = (start_index / 8);
    uint_fast32_t bit_start_index = (start_index % 8);

    if(bitmask->byte_length <= mask_start_index || bitmask->byte_length * 8 < start_index + length)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    if(!length) return;

    uint_fast32_t mask_count = (bit_start_index + length - 1) / 8;
    int_fast64_t bits_remaining = length - (8 - bit_start_index);

    bitmask->mask[mask_start_index] |= ((1 << (8 - bit_start_index)) - 1) ^ (bits_remaining < 0 ? ((1 << abs(bits_remaining)) - 1) : 0);

    for(uint_fast64_t i = 1; mask_count--; ++i, bits_remaining -= 8)
    {
        assert(bits_remaining > 0);
        bitmask->mask[i] |= ~((1 << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1);
    }
}

void bitmask_clear_bits(bitmask_t * bitmask, uint_fast32_t start_index, uint_fast32_t length)
{
    uint_fast32_t mask_start_index = (start_index / 8);
    uint_fast32_t bit_start_index = (start_index % 8);

    if(bitmask->byte_length <= mask_start_index || bitmask->byte_length * 8 < start_index + length)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    if(!length) return;

    uint_fast32_t mask_count = (bit_start_index + length - 1) / 8;
    int_fast64_t bits_remaining = length - (8 - bit_start_index);

    bitmask->mask[mask_start_index] &= ~(((1 << (8 - bit_start_index)) - 1) ^ (bits_remaining < 0 ? ((1 << abs(bits_remaining)) - 1) : 0));

    for(uint_fast64_t i = mask_start_index + 1; mask_count--; ++i, bits_remaining -= 8)
    {
        assert(bits_remaining > 0);
        bitmask->mask[i] &= (1 << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1;
    }
}

void bitmask_toggle_bits(bitmask_t * bitmask, uint_fast32_t start_index, uint_fast32_t length)
{
    uint_fast32_t mask_start_index = (start_index / 8);
    uint_fast32_t bit_start_index = (start_index % 8);

    if(bitmask->byte_length <= mask_start_index || bitmask->byte_length * 8 < start_index + length)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    if(!length) return;

    uint_fast32_t mask_count = (bit_start_index + length - 1) / 8;
    int_fast64_t bits_remaining = length - (8 - bit_start_index);

    bitmask->mask[mask_start_index] ^= ((1 << (8 - bit_start_index)) - 1) ^ (bits_remaining < 0 ? ((1 << abs(bits_remaining)) - 1) : 0);

    for(uint_fast64_t i = mask_start_index + 1; mask_count--; ++i, bits_remaining -= 8)
    {
        assert(bits_remaining > 0);
        bitmask->mask[i] ^= ~((1 << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1);
    }
}

int bitmask_are_bits_set(bitmask_t * bitmask, uint_fast32_t start_index, uint_fast32_t length)
{
    uint_fast32_t mask_start_index = (start_index / 8);
    uint_fast32_t bit_start_index = (start_index % 8);

    if(bitmask->byte_length <= mask_start_index || bitmask->byte_length * 8 < start_index + length)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    if(!length) return 0;

    uint_fast32_t mask_count = (bit_start_index + length - 1) / 8;
    int_fast64_t bits_remaining = length - (8 - bit_start_index);
    uint_fast8_t is_set = 1;

    uint_fast8_t filter = ((1 << (8 - bit_start_index)) - 1) ^ (bits_remaining < 0 ? ((1 << abs(bits_remaining)) - 1) : 0);
    is_set = is_set && !((bitmask->mask[mask_start_index] & filter) ^ filter);

    for(uint_fast64_t i = mask_start_index + 1; is_set && mask_count--; ++i, bits_remaining -= 8)
    {
        assert(bits_remaining > 0);

        uint_fast8_t not_filter = ~((1 << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1);
        is_set = is_set && !((bitmask->mask[i] & not_filter) ^ not_filter);
    }

    return is_set;
}
