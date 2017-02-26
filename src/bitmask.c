/*
 * Aligned bit mask manipulation and analysis tools
 *
 * @author Bernard Dickens
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "bitmask.h"

bitmask_t * bitmask_init(unsigned int length)
{
    if(length <= 0)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    bitmask_t * bitmask = (bitmask_t *) malloc(sizeof(bitmask_t));
    bitmask->byte_length = length;
    bitmask->mask = calloc(length, sizeof(char));
    return bitmask;
}

void bitmask_fini(bitmask_t * bitmask)
{
    free(bitmask->mask);
    free(bitmask);
}

void bitmask_set_bit(bitmask_t * bitmask, unsigned int index)
{
    unsigned int mask_index = (index / 8);
    unsigned int bit_index = (index % 8);

    if(bitmask->byte_length < mask_index + 1)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    bitmask->mask[mask_index] |= 1 << (7 - bit_index);
}

void bitmask_clear_bit(bitmask_t * bitmask, unsigned int index)
{
    unsigned int mask_index = (index / 8);
    unsigned int bit_index = (index % 8);

    if(bitmask->byte_length < mask_index + 1)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    bitmask->mask[mask_index] &= ~(1 << (7 - bit_index));
}

void bitmask_toggle_bit(bitmask_t * bitmask, unsigned int index)
{
    unsigned int mask_index = (index / 8);
    unsigned int bit_index = (index % 8);

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

int bitmask_is_bit_set(bitmask_t * bitmask, unsigned int index)
{
    unsigned int mask_index = (index / 8);
    unsigned int bit_index = (index % 8);

    if(bitmask->byte_length < mask_index + 1)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    return (bitmask->mask[mask_index] >> (7 - bit_index)) & 1;
}

void bitmask_set_bits(bitmask_t * bitmask, unsigned int start_index, unsigned int length)
{
    unsigned int mask_start_index = (start_index / 8);
    unsigned int bit_start_index = (start_index % 8);

    if(bitmask->byte_length <= mask_start_index || bitmask->byte_length * 8 < start_index + length)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    if(!length) return;

    unsigned int mask_count = (bit_start_index + length - 1) / 8;
    int bits_remaining = length - (8 - bit_start_index);

    bitmask->mask[mask_start_index] |= ((1 << (8 - bit_start_index)) - 1) ^ (bits_remaining < 0 ? ((1 << abs(bits_remaining)) - 1) : 0);

    for(int i = 1; mask_count--; ++i, bits_remaining -= 8)
    {
        assert(bits_remaining > 0);
        bitmask->mask[i] |= ~((1 << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1);
    }
}

void bitmask_clear_bits(bitmask_t * bitmask, unsigned int start_index, unsigned int length)
{
    unsigned int mask_start_index = (start_index / 8);
    unsigned int bit_start_index = (start_index % 8);

    if(bitmask->byte_length <= mask_start_index || bitmask->byte_length * 8 < start_index + length)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    if(!length) return;

    unsigned int mask_count = (bit_start_index + length - 1) / 8;
    int bits_remaining = length - (8 - bit_start_index);

    bitmask->mask[mask_start_index] &= ~(((1 << (8 - bit_start_index)) - 1) ^ (bits_remaining < 0 ? ((1 << abs(bits_remaining)) - 1) : 0));

    for(int i = mask_start_index + 1; mask_count--; ++i, bits_remaining -= 8)
    {
        assert(bits_remaining > 0);
        bitmask->mask[i] &= (1 << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1;
    }
}

void bitmask_toggle_bits(bitmask_t * bitmask, unsigned int start_index, unsigned int length)
{
    unsigned int mask_start_index = (start_index / 8);
    unsigned int bit_start_index = (start_index % 8);

    if(bitmask->byte_length <= mask_start_index || bitmask->byte_length * 8 < start_index + length)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    if(!length) return;

    unsigned int mask_count = (bit_start_index + length - 1) / 8;
    int bits_remaining = length - (8 - bit_start_index);

    bitmask->mask[mask_start_index] ^= ((1 << (8 - bit_start_index)) - 1) ^ (bits_remaining < 0 ? ((1 << abs(bits_remaining)) - 1) : 0);

    for(int i = mask_start_index + 1; mask_count--; ++i, bits_remaining -= 8)
    {
        assert(bits_remaining > 0);
        bitmask->mask[i] ^= ~((1 << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1);
    }
}

int bitmask_are_bits_set(bitmask_t * bitmask, unsigned int start_index, unsigned int length)
{
    unsigned int mask_start_index = (start_index / 8);
    unsigned int bit_start_index = (start_index % 8);

    if(bitmask->byte_length <= mask_start_index || bitmask->byte_length * 8 < start_index + length)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    if(!length) return 0;

    unsigned int mask_count = (bit_start_index + length - 1) / 8;
    int bits_remaining = length - (8 - bit_start_index);
    int is_set = 1;

    char filter = ((1 << (8 - bit_start_index)) - 1) ^ (bits_remaining < 0 ? ((1 << abs(bits_remaining)) - 1) : 0);

    is_set &= !((bitmask->mask[mask_start_index] & filter) ^ filter);

    for(int i = mask_start_index + 1; is_set && mask_count--; ++i, bits_remaining -= 8)
    {
        assert(bits_remaining > 0);

        is_set &= !(
            (bitmask->mask[i] & ~((1 << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1))
            ^
            ~((1 << (8 - (bits_remaining < 8 ? bits_remaining : 8))) - 1)
        );
    }

    return is_set;
}
