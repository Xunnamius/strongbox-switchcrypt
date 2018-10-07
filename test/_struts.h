#ifndef BLFS__STRUTS_H_
#define BLFS__STRUTS_H_

#include <stdint.h>

static const uint8_t buffer_init_backstore_state[/*204*/] = {
    // HEAD
    // header section

    0xFF, 0xFF, 0xFF, 0xFF, // BLFS_HEAD_HEADER_BYTES_VERSION

    0x8f, 0xa2, 0x0d, 0x92, 0x35, 0xd6, 0xc2, 0x4c,
    0xe4, 0xbc, 0x4f, 0x47, 0xa4, 0xce, 0x69, 0xa8, // BLFS_HEAD_HEADER_BYTES_SALT

    0x9d, 0xf4, 0x3f, 0xbc, 0x00, 0x1a, 0xb1, 0xdf,
    0x42, 0xca, 0x3c, 0x32, 0xbe, 0xff, 0x35, 0xf5,
    0xe8, 0xce, 0xa6, 0xf3, 0x4c, 0xc3, 0x23, 0x1b,
    0x1b, 0xdb, 0x5c, 0xc1, 0x9c, 0xc2, 0xbc, 0x4b, // BLFS_HEAD_HEADER_BYTES_MTRH

    0x06, 0x07, 0x08, 0x09, 0x06, 0x07, 0x08, 0x09, // BLFS_HEAD_HEADER_BYTES_TPMGLOBALVER

    0xa7, 0x35, 0x05, 0xed, 0x0a, 0x2c, 0x81, 0xf9,
    0x74, 0xf9, 0xd4, 0xe7, 0x59, 0xaf, 0x92, 0xca,
    0xe7, 0x15, 0x52, 0x04, 0xed, 0xb1, 0xb5, 0x46,
    0x24, 0x18, 0x31, 0x7f, 0xfb, 0x84, 0x79, 0x1d, // BLFS_HEAD_HEADER_BYTES_VERIFICATION

    0x03, 0x00, 0x00, 0x00, // BLFS_HEAD_HEADER_BYTES_NUMNUGGETS

    0x02, 0x00, 0x00, 0x00, // BLFS_HEAD_HEADER_BYTES_FLAKESPERNUGGET

    0x08, 0x00, 0x00, 0x00, // BLFS_HEAD_HEADER_BYTES_FLAKESIZE_BYTES

    0x3C, // BLFS_HEAD_HEADER_BYTES_INITIALIZED (index: 104)

    // KCS
    // 3 nuggets * 8 bytes per count (index: 105-128)

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // TJ (index: 129-131)
    // 3 nuggets * 2 flakes each * ~1 byte to represent the nuggets' flake state

    0xF0,

    0xFF,

    0x0F,

    // MD
    // 3 nuggets * 8 bytes per struct (index: 132-155)

    0x00, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // BODY (index: 156-203)
    // 3 nuggets * 2 flakes each * each flake is 8 bytes

    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,

    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,

    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2F, 0x30, 0x31,
    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39
};

static const uint8_t test_play_data[] = {
    0xb5, 0x26, 0x11, 0xf8, 0x1c, 0x3b, 0x99, 0xe0,
    0x64, 0xe8, 0xc6, 0xf4, 0x4d, 0xba, 0x84, 0xdd,

    0xc2, 0xd5, 0xe3, 0x56, 0xab, 0xcd, 0x6a, 0xb9,
    0x26, 0xeb, 0x39, 0x2b, 0xef, 0xc5, 0x98, 0xaf,

    0x0c, 0xe2, 0x14, 0x71, 0x32, 0xe1, 0x69, 0xf4,
    0x38, 0xad, 0xdc, 0xf8, 0x64, 0xc2, 0xd1, 0x52
};

// ? For when we're using sc_default (with md_bytes_per_nugget=1) with the dummy
// ? data above (which assumes md_bytes_per_nugget=8 per the buffer init state)
static const uint8_t alternate_mtrh_data[] = {
    0x59, 0xb5, 0x49, 0x4a, 0xf5, 0x91, 0xe1, 0x4b,
    0xec, 0x8c, 0x19, 0x45, 0xa1, 0xb7, 0xa4, 0xad,
    0x72, 0xab, 0x4c, 0xe4, 0x61, 0xbf, 0x26, 0xe0,
    0x19, 0x58, 0xea, 0xc2, 0x4a, 0x88, 0x05, 0xb2
};

#endif /* BLFS__STRUTS_H_ */
