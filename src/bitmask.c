#include "bitmask.h"

bitmask_t * bitmask_init(unsigned int length)
{
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
    (void) bitmask;
    (void) index;
}

void bitmask_clear_bit(bitmask_t * bitmask, unsigned int index)
{
    (void) bitmask;
    (void) index;
}

void bitmask_toggle_bit(bitmask_t * bitmask, unsigned int index)
{
    (void) bitmask;
    (void) index;
}

void bitmask_set_mask(bitmask_t * bitmask)
{
    (void) bitmask;
}

void bitmask_clear_mask(bitmask_t * bitmask)
{
    (void) bitmask;
}

void bitmask_set_bits(bitmask_t * bitmask, unsigned int start_index, unsigned int length)
{
    (void) bitmask;
    (void) start_index;
    (void) length;
}

void bitmask_clear_bits(bitmask_t * bitmask, unsigned int start_index, unsigned int length)
{
    (void) bitmask;
    (void) start_index;
    (void) length;
}

void bitmask_toggle_bits(bitmask_t * bitmask, unsigned int start_index, unsigned int length)
{
    (void) bitmask;
    (void) start_index;
    (void) length;
}

int bitmask_is_bit_set(bitmask_t * bitmask, unsigned int index)
{
    (void) bitmask;
    (void) index;
    return 0;
}

int bitmask_are_bits_set(bitmask_t * bitmask, unsigned int start_index, unsigned int length)
{
    (void) bitmask;
    (void) start_index;
    (void) length;
    return 0;
}
