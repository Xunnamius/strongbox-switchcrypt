#ifndef BLFS_MMC_H_
#define BLFS_MMC_H_

#include "constants.h"

/**
 * Accepts an address (addr) that maps to a block in the RPMB and returns
 * the data at that block as BLFS_CRYPTO_RPMB_BLOCK bytes into data.
 * 
 * @param addr the address that maps to a block in the RPMB
 * @param data read data is put in here
 */
void rpmb_read_block(uint16_t addr, uint8_t * data);

/**
 * Accepts an address (addr) that maps to a block in the RPMB and overwrites its
 * contents with data padded to (or truncated at) BLFS_CRYPTO_RPMB_BLOCK with
 * zeroes.
 * 
 * @param addr
 * @param data
 */
void rpmb_write_block(uint16_t addr, const uint8_t * data);

/**
 * Returns the IO count for the RPMB device. Once it reaches a certain point,
 * the RPMB can be considered spent.
 * 
 * @param  dev_fd the opened RPMB device file descriptor
 * @param  cnt    the count is placed into this parameter
 * 
 * @return        0 if the operation succeeded
 */
int rpmb_read_counter(int dev_fd, unsigned int * cnt);

/**
 * An enum describing the possible RPMB operation types.
 */
enum rpmb_op_type
{
    MMC_RPMB_WRITE_KEY = 0x01,
    MMC_RPMB_READ_CNT  = 0x02,
    MMC_RPMB_WRITE     = 0x03,
    MMC_RPMB_READ      = 0x04,

    /* For internal usage only, do not use it directly */
    MMC_RPMB_READ_RESP = 0x05
};

/**
 * A structure that contains the structure of a RPMB ioctl communication frame.
 */
typedef struct rpmb_frame
{
    uint8_t  stuff[196];
    uint8_t  key_mac[32];
    uint8_t  data[256];
    uint8_t  nonce[16];
    uint32_t write_counter;
    uint16_t addr;
    uint16_t block_count;
    uint16_t result;
    uint16_t req_resp;
} rpmb_frame;

#endif /* BLFS_MMC_H_ */
