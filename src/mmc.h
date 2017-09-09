#ifndef BLFS_MMC_H_
#define BLFS_MMC_H_

#include "constants.h"

void rpmb_read_block(uint16_t addr, uint8_t * data);
void rpmb_write_block(uint16_t addr, uint8_t * data);

enum rpmb_op_type
{
    MMC_RPMB_WRITE_KEY = 0x01,
    MMC_RPMB_READ_CNT  = 0x02,
    MMC_RPMB_WRITE     = 0x03,
    MMC_RPMB_READ      = 0x04,

    /* For internal usage only, do not use it directly */
    MMC_RPMB_READ_RESP = 0x05
};

typedef struct rpmb_frame
{
    u_int8_t  stuff[196];
    u_int8_t  key_mac[32];
    u_int8_t  data[256];
    u_int8_t  nonce[16];
    u_int32_t write_counter;
    u_int16_t addr;
    u_int16_t block_count;
    u_int16_t result;
    u_int16_t req_resp;
} rpmb_frame;

#endif /* BLFS_MMC_H_ */
