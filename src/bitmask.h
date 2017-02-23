#ifndef BITMASK_H
#define BITMASK_H

/**
* struct bitmask_t
*
* @byte_length  the length of the mask array; the length of the mask / 8
* @mask         the array of chars that make up the mask
*/
typedef struct bitmask_t {
    int byte_length;
    char * mask;
};

void bitmask_init(int length);
void bitmask_fini(bitmask_t * bitmask);

int bitmask_set_bit(int index);
int bitmask_clear_bit(int index);
int bitmask_toggle_bit(int index);

void bitmask_set(int index);
void bitmask_clear(int index);

void bitmask_set_bits(int start_index, int length);
void bitmask_clear_bits(int start_index, int length);
void bitmask_toggle_bits(int start_index, int length);

int bitmask_is_bit_set(int index);
int bitmask_are_bits_set(int start_index, int length);

#endif /* BITMASK_H */
