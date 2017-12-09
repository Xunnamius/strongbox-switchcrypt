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
    else if(id == EXCEPTION_MUST_HALT)                                                      \
        dzlog_fatal("FATAL: execution was suddenly halted\n");                              \
    else                                                                                    \
        dzlog_fatal("Fatal error: program terminated with uncaught exception [0x%x]", id);  \
    exit(id);                                                                               \
} while(0)

////////////////////////
// Exceptional Events //
////////////////////////

// Not an exception
#define EXCEPTION_NO_EXCEPTION                          CEXCEPTION_NONE

// Someone tried to walk off an array or something untoward
#define EXCEPTION_OUT_OF_BOUNDS                         0x02U

// Malloc/Calloc/Realloc etc went and failed on us
#define EXCEPTION_ALLOC_FAILURE                         0x03U

// A bad dynamic length/size was provided to some function
#define EXCEPTION_SIZE_T_OUT_OF_BOUNDS                  0x04U

// Something went wrong with zlog_init
#define EXCEPTION_ZLOG_INIT_FAILURE                     0x05U

// One of our sanity checks failed
#define EXCEPTION_ASSERT_FAILURE                        0x06U

// One of our sanity checks failed
#define EXCEPTION_OUT_OF_MEMORY                         0x07U

// Sodium failed to initialize
#define EXCEPTION_SODIUM_INIT_FAILURE                   0x08U

// Chacha20 returned something unexpected
#define EXCEPTION_CHACHA20_BAD_RETVAL                   0x09U

// Bad flake size encountered
#define EXCEPTION_INVALID_FLAKESIZE                     0x0AU

// Bad flake size encountered
#define EXCEPTION_INVALID_BACKSTORESIZE                 0x16U

// Bad flakes/nugget value encountered
#define EXCEPTION_INVALID_FLAKES_PER_NUGGET             0x0BU

// Too many flakes per nugget were specified
#define EXCEPTION_TOO_MANY_FLAKES_PER_NUGGET            0x0CU

// We failed to open something, probably a file descriptor
#define EXCEPTION_OPEN_FAILURE                          0x0DU

// Bad header type
#define EXCEPTION_BAD_HEADER_TYPE                       0x0EU

// A file already exists in the location at which we want to make something new
#define EXCEPTION_FILE_ALREADY_EXISTS                   0x0FU

// A file we're looking for does not exist at the path specified
#define EXCEPTION_FILE_DOES_NOT_EXIST                   0x10U

// Tried to open a backstore that is corrupted or otherwise not properly formatted
#define EXCEPTION_BACKSTORE_NOT_INITIALIZED             0x11U

// The backstore you're trying to load is too old. Make a new one
#define EXCEPTION_INCOMPAT_BACKSTORE_VERSION            0x12U

// An invalid operation (probably cache-related) was attempted
#define EXCEPTION_INVALID_OPERATION                     0x13U

// The backstore size provided is WAY too small!
#define EXCEPTION_BACKSTORE_SIZE_TOO_SMALL              0x14U

// The options passed were not formatted properly, or some required options were missing
#define EXCEPTION_BAD_ARGUMENT_FORM                     0x15U

// New password verification step (during create, not open/wipe) failure
#define EXCEPTION_PASSWORD_MISMATCH                     0x17U

// Bad mode command specified during startup
#define EXCEPTION_UNKNOWN_MODE                          0x01U

// Something went wrong while trying to grab the merkle tree root hash
#define EXCEPTION_MERKLE_TREE_ROOT_FAILURE              0x18U

// Something went wrong while trying to add a node to the merkle tree
#define EXCEPTION_MERKLE_TREE_ADD_FAILURE               0x19U // probably a hash length issue

// Something went wrong while trying to update a node in the merkle tree
#define EXCEPTION_MERKLE_TREE_UPDATE_FAILURE            0x1AU

// Something went wrong while trying to verify a node in the merkle tree
#define EXCEPTION_MERKLE_TREE_VERIFY_FAILURE            0x1BU

// Something went wrong with TPM verification/bad id
#define EXCEPTION_TPM_VERSION_CHECK_FAILURE             0x1CU

// You entered the wrong password
#define EXCEPTION_BAD_PASSWORD                          0x1DU

// An integrity violation occurred while trying to initialize
#define EXCEPTION_INTEGRITY_FAILURE                     0x1EU

// A condition has occurred that has forced the software to exit immediately
#define EXCEPTION_MUST_HALT                             0x1FU

// These errors only happen when BLFS_DEBUG_LEVEL > 0; bad read/write offset/len
#define EXCEPTION_DEBUGGING_OVERFLOW                    0x20U
#define EXCEPTION_DEBUGGING_UNDERFLOW                   0x21U

// Why you call cache function when cache disabled?!?!
#define EXCEPTION_BAD_CACHE                             0x22U

// Why you call aes-xts function when aes-xts disabled?!?!
#define EXCEPTION_BAD_AESXTS                            0x23U

// OpenSSL returned something unexpected
#define EXCEPTION_AESXTS_BAD_RETVAL                     0x24U

// OpenSSL AES-XTS requires minimum data size of 16 bytes (cipher core req)
#define EXCEPTION_AESXTS_DATA_LENGTH_TOO_SMALL          0x25U

// OpenSSL AES-CTR is not amused by your antics and returned something unexpected
#define EXCEPTION_AESCTR_BAD_RETVAL                     0x26U

// Why you call aes-ctr function when aes-ctr disabled?!?!
#define EXCEPTION_BAD_AESCTR                            0x27U

// Must be root to run this program with this configuration
#define EXCEPTION_MUST_BE_ROOT                          0x28U

// Energymon subsystem failed to retrieve its default context
#define EXCEPTION_ENERGYMON_GET_DEFAULT_FAILURE         0x29U

// Energymon subsystem failed on finit
#define EXCEPTION_ENERGYMON_FINIT_FAILURE               0x2AU

// Energymon subsystem failed during metric collection
#define EXCEPTION_ENERGYMON_METRIC_COLLECTION_FAILURE   0x2BU

// Someone! attempted to re-init the Energymon subsystem (not allowed)
#define EXCEPTION_ENERGYMON_ALREADY_INITED              0x2CU

// Energymon subsystem failed on ffinish
#define EXCEPTION_ENERGYMON_FFINISH_FAILURE             0x2DU

// The requested stream cipher algorithm is not yet implemented
#define EXCEPTION_SC_ALGO_NO_IMPL                       0x2EU

// The requested stream cipher algorithm does not exist
#define EXCEPTION_SC_ALGO_NOT_FOUND                     0x2FU

// A failure occurred during an RPMB operation (in low level ioctl)
#define EXCEPTION_RPMB_IOCTL_FAILURE                    0x30U

// A failure occurred during an RPMB operation (in high level RPMB frame)
#define EXCEPTION_RPMB_OP_FAILURE                       0x31U

// Calculated mac doesn't match mac returned in RPMB frame during ioctl operation
#define EXCEPTION_RPMB_MAC_MISMATCH                     0x32U

// Calculated mac doesn't match mac returned in RPMB frame during ioctl operation
#define EXCEPTION_GLOBAL_CORRECTNESS_FAILURE            0x33U

// The TPM ID supplied via --tpm-id angered the gods
#define EXCEPTION_INVALID_TPM_ID                        0x34U

// You tried to pass an invalid cipher string to --cipher
#define EXCEPTION_STRING_TO_CIPHER_FAILED               0x35U

// No RPMB device was detected. Did you enter the correct path string and recompile?
// You can also pretend an RPMB device does exist via BLFS_MANUAL_GV_FALLBACK (see Makefile)
#define EXCEPTION_RPMB_DOES_NOT_EXIST                   0x36U

///////////////////////
// End Configuration //
///////////////////////

#include "CException.h"

#endif // CONFIG_CEXCEPTION_CONFIGURED_H_
