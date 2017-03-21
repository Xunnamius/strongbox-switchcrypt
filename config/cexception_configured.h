#ifndef CONFIG_CEXCEPTION_CONFIGURED_H_
#define CONFIG_CEXCEPTION_CONFIGURED_H_

#include <stdlib.h>
#include <stdint.h>
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

// One of our sanity checks failed
#define EXCEPTION_OUT_OF_MEMORY                 0x07U

// Sodium failed to initialize
#define EXCEPTION_SODIUM_INIT_FAILURE           0x08U

// Chacha20 returned something unexpected
#define EXCEPTION_CHACHA20_BAD_RETVAL           0x09U

// Bad flake size encountered
#define EXCEPTION_INVALID_FLAKESIZE             0x0AU

// Bad flake size encountered
#define EXCEPTION_INVALID_BACKSTORESIZE         0x16U

// Bad flakes/nugget value encountered
#define EXCEPTION_INVALID_FLAKES_PER_NUGGET     0x0BU

// Too many flakes per nugget were specified
#define EXCEPTION_TOO_MANY_FLAKES_PER_NUGGET    0x0CU

// We failed to open something, probably a file descriptor
#define EXCEPTION_OPEN_FAILURE                  0x0DU

// Bad header type
#define EXCEPTION_BAD_HEADER_TYPE               0x0EU

// A file already exists in the location at which we want to make something new
#define EXCEPTION_FILE_ALREADY_EXISTS           0x0FU

// A file we're looking for does not exist at the path specified
#define EXCEPTION_FILE_DOES_NOT_EXIST           0x10U

// Tried to open a backstore that is corrupted or otherwise not properly formatted
#define EXCEPTION_BACKSTORE_NOT_INITIALIZED     0x11U

// The backstore you're trying to load is too old. Make a new one
#define EXCEPTION_INCOMPAT_BACKSTORE_VERSION    0x12U

// An invalid operation (probably cache-related) was attempted
#define EXCEPTION_INVALID_OPERATION             0x13U

// The backstore size provided is WAY too small! Also see BLFS_MIN_SIZE_FACTOR
#define EXCEPTION_BACKSTORE_SIZE_TOO_SMALL      0x14U

// The options passed were not formatted properly, or some required options were missing
#define EXCEPTION_BAD_ARGUMENT_FORM             0x15U

///////////////////////
// End Configuration //
///////////////////////

#include "CException.h"

#endif // CONFIG_CEXCEPTION_CONFIGURED_H_
