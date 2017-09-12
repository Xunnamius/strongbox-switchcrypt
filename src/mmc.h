#ifndef BLFS_MMC_H_
#define BLFS_MMC_H_

#include "constants.h"

/**
 * [rpmb_read_block description]
 * @param addr [description]
 * @param data [description]
 */
void rpmb_read_block(uint16_t addr, uint8_t * data);

/**
 * [rpmb_write_block description]
 * @param addr [description]
 * @param data [description]
 */
void rpmb_write_block(uint16_t addr, uint8_t * data);

/**
 * [rpmb_read_counter description]
 * @param  dev_fd [description]
 * @param  cnt    [description]
 * @return        [description]
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
