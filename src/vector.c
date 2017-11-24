/*
 * Dynamically allocated "boundless" array-type so-called vector implementation.
 *
 * @author Bernard Dickens
 */

#include "vector.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

vector_t * vector_init()
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    vector_t * vector = malloc(sizeof(vector_t));

    if(vector == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    vector->data = NULL;
    vector->size = 0;
    vector->count = 0;

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return vector;
}

void vector_fini(vector_t * vector)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    free(vector->data);
    free(vector);

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void vector_add(vector_t * vector, const void * element)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(vector->size == 0)
    {
        vector->size = VECTOR_INIT_SIZE;
        vector->data = calloc(vector->size, sizeof(void *));

        if(vector->data == NULL)
            Throw(EXCEPTION_ALLOC_FAILURE);

        IFDEBUG(dzlog_debug("vector first time initialized"));
    }

    if(vector->size == vector->count)
    {
        vector->size *= VECTOR_GROWTH_FACTOR;
        vector->data = realloc(vector->data, sizeof(void *) * vector->size);

        if(vector->data == NULL)
            Throw(EXCEPTION_ALLOC_FAILURE);

        IFDEBUG(dzlog_debug("vector was resized; new size = %"PRIu32, vector->size));
    }

    IFDEBUG(dzlog_debug("adding new element %p to vector at count %"PRIu32, element, vector->count));

    vector->data[vector->count] = element;
    vector->count++;

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

void vector_delete(vector_t * vector, uint32_t index)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(index >= vector->count)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    IFDEBUG(const void * ptr = vector->data[index]);

    for(uint32_t i = index, j = i + 1; j < vector->count; j++, i++)
        vector->data[i] = vector->data[j];

    IFDEBUG(dzlog_debug("deleted element %p from vector at count %"PRIu32, ptr, index));

    vector->count--;

    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}

const void * vector_get(vector_t * vector, uint32_t index)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(index >= vector->count)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    IFDEBUG(dzlog_debug("getting element %p from vector at index %"PRIu32, vector->data[index], index));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
    return vector->data[index];
}

void vector_set(vector_t * vector, uint32_t index, const void * element)
{
    IFDEBUG(dzlog_debug(">>>> entering %s", __func__));

    if(index >= vector->count)
        Throw(EXCEPTION_OUT_OF_BOUNDS);

    vector->data[index] = element;

    IFDEBUG(dzlog_debug("setting element %p in vector at index %"PRIu32, element, index));
    IFDEBUG(dzlog_debug("<<<< leaving %s", __func__));
}
