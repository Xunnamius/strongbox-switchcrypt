/*
 * <description>
 *
 * @author Bernard Dickens
 * @author SanDisk Corp
 */

#include "mmc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>
#include <linux/fs.h>

/**
 * [sb_rpmb_read_block description]
 * @param addr [description]
 * @param data [description]
 */
void sb_rpmb_read_block(uint16_t addr, uint8_t * data)
{
    int i, ret, dev_fd = -1;
    unsigned char key[BLFS_CRYPTO_RPMB_KEY] = BLFS_RPMB_KEY;
    uint16_t blocks_cnt = 1;

    rpmb_frame * frame_out_p;
    rpmb_frame frame_in = { .req_resp = htobe16(MMC_RPMB_READ) };

    errno = 0;
    dev_fd = open(BLFS_RPMB_DEVICE, O_RDWR);

    if(dev_fd < 0 && errno)
    {
        perror("RPMB device "BLFS_RPMB_DEVICE" not found");
        exit(1);
    }

    /* Get block address */
    frame_in.addr = htobe16(addr);

    /* Get blocks count */
    frame_out_p = calloc(sizeof(*frame_out_p), blocks_cnt);

    if(!frame_out_p)
    {
        printf("Can't allocate memory for RPMB outer frames\n");
        exit(1);
    }

    /* Execute RPMB op */
    ret = do_rpmb_op(dev_fd, &frame_in, frame_out_p, blocks_cnt);

    if(ret != 0)
    {
        perror("RPMB ioctl failed");
        exit(1);
    }

    /* Check RPMB response */
    if(frame_out_p[blocks_cnt - 1].result != 0)
    {
        printf("RPMB operation failed, retcode 0x%04x\n", be16toh(frame_out_p[blocks_cnt - 1].result));
        exit(1);
    }

    /* Verify data against key */
    unsigned char mac[32];
    hmac_sha256_ctx ctx; // XXX
    rpmb_frame * frame_out = NULL;
    // XXX: <--- VV
    hmac_sha256_init(&ctx, key, sizeof(key));

    for(i = 0; i < blocks_cnt; i++)
    {
        frame_out = &frame_out_p[i];
        hmac_sha256_update(&ctx, frame_out->data, sizeof(*frame_out) - offsetof(rpmb_frame, data));
    }

    hmac_sha256_final(&ctx, mac, sizeof(mac)); // XXX

    /* Impossible */
    assert(frame_out); // XXX

    /* Compare calculated MAC and MAC from last frame */
    if(memcmp(mac, frame_out->key_mac, sizeof(mac)))
    {
        printf("RPMB MAC missmatch\n");
        exit(1);
    }

    /* Output */
    frame_out = &frame_out_p[i];
    assert(sizeof(frame_out->data) == BLFS_CRYPTO_RPMB_BLOCK);
    memcpy(data, frame_out->data, BLFS_CRYPTO_RPMB_BLOCK);

    free(frame_out_p);
    close(dev_fd);
}

/**
 * [sb_rpmb_write_block description]
 * @param addr [description]
 * @param data [description]
 */
void sb_rpmb_write_block(uint16_t addr, uint8_t * data)
{
    int ret, dev_fd;
    unsigned char key[BLFS_CRYPTO_RPMB_KEY] = BLFS_RPMB_KEY;
    unsigned int cnt;

    rpmb_frame frame_out;
    rpmb_frame frame_in = {
        .req_resp    = htobe16(MMC_RPMB_WRITE),
        .block_count = htobe16(1)
    };

    dev_fd = open(BLFS_RPMB_DEVICE, O_RDWR);

    if(dev_fd < 0)
    {
        perror("RPMB device not found");
        exit(1);
    }

    ret = rpmb_read_counter(dev_fd, &cnt);

    /* Check RPMB response */
    if(ret != 0)
    {
        printf("RPMB read counter operation failed, retcode 0x%04x\n", ret);
        exit(1);
    }

    frame_in.write_counter = htobe32(cnt);

    /* Get block address */
    frame_in.addr = htobe16(addr);

    /* Read 256b data */
    memcpy(frame_in.data, data, BLFS_CRYPTO_RPMB_BLOCK);

    /* Calculate HMAC SHA256 */
    hmac_sha256(key, sizeof(key), // XXX
                frame_in.data, sizeof(frame_in) - offsetof(rpmb_frame, data),
                frame_in.key_mac, sizeof(frame_in.key_mac));

    /* Execute RPMB op */
    ret = do_rpmb_op(dev_fd, &frame_in, &frame_out, 1);

    if(ret != 0)
    {
        perror("RPMB ioctl failed");
        exit(1);
    }

    /* Check RPMB response */
    if(frame_out.result != 0)
    {
        printf("RPMB operation failed, retcode 0x%04x\n", be16toh(frame_out.result));
        exit(1);
    }

    close(dev_fd);
}

/* Performs RPMB operation.
 *
 * @fd: RPMB device on which we should perform ioctl command
 * @frame_in: input RPMB frame, should be properly inited
 * @frame_out: output (result) RPMB frame. Caller is responsible for checking
 *             result and req_resp for output frame.
 * @out_cnt: count of outer frames. Used only for multiple blocks reading,
 *           in the other cases -EINVAL will be returned.
 */
static int do_rpmb_op(int fd,
                      const struct rpmb_frame *frame_in,
                      struct rpmb_frame *frame_out,
                      unsigned int out_cnt)
{
    int err;
    u_int16_t rpmb_type;

    struct mmc_ioc_cmd ioc = {
        .arg        = 0x0,
        .blksz      = 512,
        .blocks     = 1,
        .write_flag = 1,
        .opcode     = MMC_WRITE_MULTIPLE_BLOCK,
        .flags      = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC,
        .data_ptr   = (uintptr_t)frame_in
    };

    if (!frame_in || !frame_out || !out_cnt)
        return -EINVAL;

    rpmb_type = be16toh(frame_in->req_resp);

    switch(rpmb_type) {
    case MMC_RPMB_WRITE:
    case MMC_RPMB_WRITE_KEY:
        if (out_cnt != 1) {
            err = -EINVAL;
            goto out;
        }

        /* Write request */
        ioc.write_flag |= (1<<31);
        err = ioctl(fd, MMC_IOC_CMD, &ioc);
        if (err < 0) {
            err = -errno;
            goto out;
        }

        /* Result request */
        memset(frame_out, 0, sizeof(*frame_out));
        frame_out->req_resp = htobe16(MMC_RPMB_READ_RESP);
        ioc.write_flag = 1;
        ioc.data_ptr = (uintptr_t)frame_out;
        err = ioctl(fd, MMC_IOC_CMD, &ioc);
        if (err < 0) {
            err = -errno;
            goto out;
        }

        /* Get response */
        ioc.write_flag = 0;
        ioc.opcode = MMC_READ_MULTIPLE_BLOCK;
        err = ioctl(fd, MMC_IOC_CMD, &ioc);
        if (err < 0) {
            err = -errno;
            goto out;
        }

        break;
    case MMC_RPMB_READ_CNT:
        if (out_cnt != 1) {
            err = -EINVAL;
            goto out;
        }
        /* fall through */

    case MMC_RPMB_READ:
        /* Request */
        err = ioctl(fd, MMC_IOC_CMD, &ioc);
        if (err < 0) {
            err = -errno;
            goto out;
        }

        /* Get response */
        ioc.write_flag = 0;
        ioc.opcode   = MMC_READ_MULTIPLE_BLOCK;
        ioc.blocks   = out_cnt;
        ioc.data_ptr = (uintptr_t)frame_out;
        err = ioctl(fd, MMC_IOC_CMD, &ioc);
        if (err < 0) {
            err = -errno;
            goto out;
        }

        break;
    default:
        err = -EINVAL;
        goto out;
    }

out:
    return err;
}
