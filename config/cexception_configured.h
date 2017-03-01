#ifndef _CONF_CEXCEPTION_H
#define _CONF_CEXCEPTION_H

#include <stdlib.h>
#include <zlog.h>

/////////////////////////
// Begin Configuration //
/////////////////////////

// We're assuming the program has already initialized and
// hence has called dzlog_init( ... )

// The reserved value representing NO EXCEPTION
#define CEXCEPTION_NONE (0x00)

// A special handler for unhandled exceptions
#define CEXCEPTION_NO_CATCH_HANDLER(id)                      \
{                                                            \
    dzlog_fatal("Program terminated by exception [%i]", id); \
    exit(id);                                                \
}

////////////////////////
// Exceptional Events //
////////////////////////

// Not an exception
#define EXCEPTION_NO_EXCEPTION              CEXCEPTION_NONE

// Malloc failure
#define EXCEPTION_MALLOC_FAILED             0x01

// Someone tried to walk off an array or something untoward
#define EXCEPTION_OUT_OF_BOUNDS             0x02

// Malloc/Calloc/Realloc etc went and failed on us
#define EXCEPTION_ALLOC_FAILURE             0x03

// A bad dynamic length/size was provided to some function
#define EXCEPTION_SIZE_T_OUT_OF_BOUNDS      0x04

///////////////////////
// End Configuration //
///////////////////////

#include "CException.h"

#endif // _CONF_CEXCEPTION_H
