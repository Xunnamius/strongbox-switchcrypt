#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <sodium.h>

//////////////////
// Configurable //
//////////////////

// 0 - no debugging, log writing, or any such output
// 1 - light debugging to designated log file
// 2 - ^ and some informative messages to stdout
// 3 - ^ except it's a clusterfuck of debug messages
#define DEBUG_LEVEL 3

////////////
// Header //
////////////

#define HEAD_HEADER_TYPE_SALT 0x01
#define HEAD_HEADER_TYPE_MEM 0x02
#define HEAD_HEADER_TYPE_OPS 0x04
#define HEAD_HEADER_TYPE_VERIFICATION 0x08
#define HEAD_HEADER_TYPE_VERSION 0x10
#define HEAD_HEADER_TYPE_NUGGET_COUNT 0x20
#define HEAD_HEADER_TYPE_FLAKE_COUNT 0x40
#define HEAD_HEADER_TYPE_INITIALIZED 0x80

///////////////////
// Buffer Length //
///////////////////

// XXX: In bytes; all data values will be cast to uint64_t where appropriate,
// so do not set any of these higher than 8 or lower than 1.
#define HEAD_BUFFER_BITLENGTH_SALT              crypto_pwhash_SALTBYTES
#define HEAD_BUFFER_BITLENGTH_MEM               4 // int
#define HEAD_BUFFER_BITLENGTH_OPS               8 // uint64_t
#define HEAD_BUFFER_BITLENGTH_VERIFICATION      128
#define HEAD_BUFFER_BITLENGTH_VERSION           8 // uint64_t
#define HEAD_BUFFER_BITLENGTH_NUGGET_COUNT      8 // uint64_t
#define HEAD_BUFFER_BITLENGTH_FLAKE_COUNT       8 // uint64_t
#define HEAD_BUFFER_BITLENGTH_INITIALIZED       1 // char
#define HEAD_BUFFER_BITLENGTH_SECRET            crypto_box_SEEDBYTES

///////////////
// Backstore //
///////////////

#define BACKSTORE_DEFAULT_FILE "./blfs-%s.bkstr"
#define BACKSTORE_DEFAULT_SIZE 1 * 1024 * 1024 * 1024 // 1GB

////////////
// Crypto //
////////////

#define CHACHA_BLOCK_SIZE 64.0 // Must be double!

///////////
// Flags //
///////////

#define FLAG_TEST_MODE 0x01
#define FLAG_FORCE_CLEAN_START 0x02
#define FLAG_JOURNALING_MODE_ORDERED 0x04
#define FLAG_JOURNALING_MODE_FULL 0x08

////////////////////
// Journal Status //
////////////////////



////////////////////////
// Exceptional Events //
////////////////////////

// See: config/cexception_config.h

#endif /* CONSTANTS_H */
