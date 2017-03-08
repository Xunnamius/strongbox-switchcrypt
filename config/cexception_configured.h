#ifndef CONFIG_CEXCEPTION_CONFIGURED_H
#define CONFIG_CEXCEPTION_CONFIGURED_H

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
#define CEXCEPTION_NO_CATCH_HANDLER(id)                                                     \
do {                                                                                        \
    if(id == EXCEPTION_ZLOG_INIT_FAILURE)                                                   \
        printf("Fatal error: zlog init failure\n");                                         \
    else                                                                                    \
        dzlog_fatal("Fatal error: program terminated with uncaught exception [%i]", id);    \
    exit(id);                                                                               \
} while(0)

////////////////////////
// Exceptional Events //
////////////////////////

// Not an exception
#define EXCEPTION_NO_EXCEPTION                  CEXCEPTION_NONE

// Malloc failure
#define EXCEPTION_MALLOC_FAILED                 0x01U

// Someone tried to walk off an array or something untoward
#define EXCEPTION_OUT_OF_BOUNDS                 0x02U

// Malloc/Calloc/Realloc etc went and failed on us
#define EXCEPTION_ALLOC_FAILURE                 0x03U

// A bad dynamic length/size was provided to some function
#define EXCEPTION_SIZE_T_OUT_OF_BOUNDS          0x04U

// Something went wrong with zlog_init
#define EXCEPTION_ZLOG_INIT_FAILURE             0x05U

// One of our sanity checks failed
#define EXCEPTION_ASSERT_FAILURE                0x06U

// XXX: comment the rest of these
#define EXCEPTION_OUT_OF_MEMORY                 0x07U

#define EXCEPTION_SODIUM_INIT_FAILURE           0x08U

#define EXCEPTION_CHACHA20_BAD_RETVAL           0x09U

#define EXCEPTION_INVALID_FLAKESIZE             0x0AU

#define EXCEPTION_INVALID_FLAKES_PER_NUGGET     0x0BU

#define EXCEPTION_TOO_MANY_FLAKES_PER_NUGGET    0x0CU

#define EXCEPTION_OPEN_FAILURE                  0x0DU

// One of our sanity checks failed
#define EXCEPTION_OUT_OF_MEMORY             0x07U

///////////////////////
// End Configuration //
///////////////////////

#include "CException.h"

#endif // CONFIG_CEXCEPTION_CONFIGURED_H
