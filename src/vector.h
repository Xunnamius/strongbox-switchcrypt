#ifndef VECTOR_H_
#define VECTOR_H_

#include "constants.h"

/**
 * Dynamically allocated "growth on demand" array.
 *
 * @data    The data elements stored in the vector
 * @size    The bytesize of the vector (as void * pouint32_ters)
 * @count   Number of elements in the vector
 */
typedef struct vector_t
{
    const void ** data;
    uint32_t size;
    uint32_t count;
} vector_t;

/**
 * Create a new vector yielded to the vector pointer parameter.
 *
 * XXX: It is advisable that you do NOT mix different types in the same vector!
 * 
 * This function is O(1).
 *
 * @param vector
 */
vector_t * vector_init();

/**
 * Destroy a vector (free all components). Note that the elements of the vector
 * will not themselves be freed. This must be done manually.
 * 
 * This function is O(1).
 *
 * @param vector
 */
void vector_fini(vector_t * vector);

/**
 * Add element to the end of vector.
 * 
 * This function is O(1).
 *
 * @param vector
 * @param element
 */
void vector_add(vector_t * vector, const void * element);

/**
 * Delete the element in vector at index.
 * 
 * Note that while the element at the specified index will be removed, the
 * element itself will not be free()'d. You'll have to do that manually.
 *
 * This function is O(n).
 *
 * @param vector
 * @param index
 */
void vector_delete(vector_t * vector, uint32_t index);

/**
 * Get the element in vector at index.
 * 
 * This function is O(1).
 *
 * @param  vector
 * @param  index
 *
 * @return        Void pointer to the requested element
 */
const void * vector_get(vector_t * vector, uint32_t index);

/**
 * Set an index in vector to element.
 * 
 * This function is O(1).
 *
 * @param vector
 * @param index
 * @param element
 */
void vector_set(vector_t * vector, uint32_t index, const void * element);

#endif
