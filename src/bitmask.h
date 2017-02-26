#ifndef BITMASK_H
#define BITMASK_H

#include "cexception_configured.h"

/**
* struct bitmask_t
*
* @byte_length  the length of the mask array; the length of the mask / 8
* @mask         the array of chars that make up the mask
*/
typedef struct bitmask_t
{
    unsigned int byte_length;
    char * mask;
} bitmask_t;

/**
 * Creates a bit mask of the specified length (in bytes). Do not forget to call
 * bitmask_fini() when you're done with the bitmask!
 *
 * Note that length CANNOT be <= 0.
 *
 * @param  length Positive bitmask length (in bytes); e.g. length = 2 -> 16-bit mask
 */
bitmask_t * bitmask_init(unsigned int length);

/**
 * Cleans up a bit mask and any associated objects in memory. Essentially a
 * free()-like command.
 *
 * @param bitmask
 */
void bitmask_fini(bitmask_t * bitmask);

/**
 * Set (to 1) the ith bit at the specified index in the mask.
 *
 * @param  bitmask
 * @param  index
 */
void bitmask_set_bit(bitmask_t * bitmask, unsigned int index);

/**
 * Clear (set to 0) the ith bit at the specified index in the mask.
 *
 * @param  bitmask
 * @param  index
 */
void bitmask_clear_bit(bitmask_t * bitmask, unsigned int index);

/**
 * Flip the ith bit at the specified index in the mask.
 *
 * @param  bitmask
 * @param  index
 */
void bitmask_toggle_bit(bitmask_t * bitmask, unsigned int index);

/**
 * Set every bit in the mask to 1.
 *
 * @param  bitmask
 */
void bitmask_set_mask(bitmask_t * bitmask);

/**
 * Set every bit in the mask to 0.
 *
 * @param  bitmask
 */
void bitmask_clear_mask(bitmask_t * bitmask);

/**
 * Returns 1 if the bit at the specified index is set (bit == 1). Returns 0
 * otherwise.
 *
 * @param  bitmask
 * @param  index
 *
 * @return         1 if the bit is set, otherwise 0
 */
int bitmask_is_bit_set(bitmask_t * bitmask, unsigned int index);

/**
 * Set (to 1) `length` bits in the mask starting at the specified index.
 *
 * @param  bitmask
 * @param  start_index
 * @param  length
 */
void bitmask_set_bits(bitmask_t * bitmask, unsigned int start_index, unsigned int length);

/**
 * Clear (set to 0) `length` bits in the mask starting at the specified index.
 *
 * @param  bitmask
 * @param  start_index
 * @param  length
 */
void bitmask_clear_bits(bitmask_t * bitmask, unsigned int start_index, unsigned int length);

/**
 * Flip `length` bits in the mask starting at the specified index.
 *
 * @param  bitmask
 * @param  start_index
 * @param  length
 */
void bitmask_toggle_bits(bitmask_t * bitmask, unsigned int start_index, unsigned int length);

/**
 * Returns 1 if `length` bits starting at `start_index` are set (bit == 1).
 * Returns 0 otherwise.
 *
 * @param  bitmask
 * @param  index
 *
 * @return         1 if the bit range is set, otherwise 0
 */
int bitmask_are_bits_set(bitmask_t * bitmask, unsigned int start_index, unsigned int length);

#endif /* BITMASK_H */
