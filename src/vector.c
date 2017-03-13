/*
 * Dynamically allocated "boundless" array-type so-called vector implementation.
 *
 * @author Bernard Dickens
 */

#include <stdlib.h>
#include <string.h>

#include "vector.h"

vector_t * vector_init()
{
    vector_t * vector = malloc(sizeof(vector_t));

    if(vector == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    vector->data = NULL;
    vector->size = 0;
    vector->count = 0;

    return vector;
}

void vector_fini(vector_t * vector)
{
    free(vector->data);
    free(vector);
}

void vector_add(vector_t * vector, const void * element)
{
    if(vector->size == 0)
    {
        vector->size = 10;
        vector->data = calloc(vector->size, sizeof(void *));

        if(vector->data == NULL)
            Throw(EXCEPTION_ALLOC_FAILURE);
    }

    if(vector->size == vector->count)
    {
        vector->size *= VECTOR_GROWTH_FACTOR;
        vector->data = realloc(vector->data, sizeof(void *) * vector->size);

        if(vector->data == NULL)
            Throw(EXCEPTION_ALLOC_FAILURE);
    }

    vector->data[vector->count] = element;
    vector->count++;
}

void vector_delete(vector_t * vector, uint32_t index)
{
    if(index >= vector->count)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    for(uint32_t i = index, j = i + 1; j < vector->count; j++, i++)
        vector->data[i] = vector->data[j];

    vector->count--;
}

const void * vector_get(vector_t * vector, uint32_t index)
{
    if(index >= vector->count)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    return vector->data[index];
}

void vector_set(vector_t * vector, uint32_t index, const void * element)
{
    if(index >= vector->count)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    vector->data[index] = element;
}
