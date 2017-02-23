#ifndef _CONF_CEXCEPTION_H
#define _CONF_CEXCEPTION_H

#include <stdlib.h>
#include <zlog.h>

// We're assuming the program has already initialized and
// hence has called dzlog_init( ... )

// The reserved value representing NO EXCEPTION
#define CEXCEPTION_NONE (0)

// A special handler for unhandled exceptions
#define CEXCEPTION_NO_CATCH_HANDLER(id)                      \
{                                                            \
    dzlog_fatal("Program terminated by exception [%i]", id); \
    exit(id);                                                \
}

#endif // _CONF_CEXCEPTION_H