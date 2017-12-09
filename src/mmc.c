/*
 * <description>
 *
 * @author Bernard Dickens
 * @author SanDisk Corp
 */

#include "./mmc.h"
#include "../vendor/mmc.h"

#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <sodium.h>

/**
 * Performans an RPMB operation.
 * 
 * @param  fd        device on which we should perform ioctl command
 * @param  frame_in  input RPMB frame; should be properly initialized output
 *                   (result) RPMB frame. Caller is responsible for checking.
 * @param  frame_out result and req_resp for output frame.
 * @param  out_cnt   count of outer frames. Used only for reading multiple
 *                   blocks. In the other cases, -EINVAL will be returned.
 * 
 * @return           0 if no error occurred
 */
static int do_rpmb_op(int fd, const rpmb_frame * frame_in, rpmb_frame * frame_out, unsigned int out_cnt)
{
    int err;
    uint16_t rpmb_type;

    struct mmc_ioc_cmd ioc = {
        .arg        = 0x0,
        .blksz      = 512,
        .blocks     = 1,
        .write_flag = 1,
        .opcode     = MMC_WRITE_MULTIPLE_BLOCK,
        .flags      = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC,
        .data_ptr   = (uintptr_t) frame_in
    };

    if(!frame_in || !frame_out || !out_cnt)
        return -EINVAL;

    rpmb_type = be16toh(frame_in->req_resp);

    switch(rpmb_type)
    {
        case MMC_RPMB_WRITE:
        case MMC_RPMB_WRITE_KEY:
            if(out_cnt != 1)
            {
                err = -EINVAL;
                goto out;
            }

            /* Write request */
            ioc.write_flag |= (1U << 31);
            err = ioctl(fd, MMC_IOC_CMD, &ioc);

            if(err < 0)
            {
                err = -errno;
                goto out;
            }

            /* Result request */
            memset(frame_out, 0, sizeof(*frame_out));
            frame_out->req_resp = htobe16(MMC_RPMB_READ_RESP);
            ioc.write_flag = 1;
            ioc.data_ptr = (uintptr_t) frame_out;
            err = ioctl(fd, MMC_IOC_CMD, &ioc);

            if(err < 0)
            {
                err = -errno;
                goto out;
            }

            /* Get response */
            ioc.write_flag = 0;
            ioc.opcode = MMC_READ_MULTIPLE_BLOCK;
            err = ioctl(fd, MMC_IOC_CMD, &ioc);

            if(err < 0)
            {
                err = -errno;
                goto out;
            }

            break;

        case MMC_RPMB_READ_CNT:
            if(out_cnt != 1)
            {
                err = -EINVAL;
                goto out;
            }

            /* fall through */

        case MMC_RPMB_READ:
            /* Request */
            err = ioctl(fd, MMC_IOC_CMD, &ioc);

            if(err < 0)
            {
                err = -errno;
                goto out;
            }

            /* Get response */
            ioc.write_flag = 0;
            ioc.opcode   = MMC_READ_MULTIPLE_BLOCK;
            ioc.blocks   = out_cnt;
            ioc.data_ptr = (uintptr_t) frame_out;
            err = ioctl(fd, MMC_IOC_CMD, &ioc);

            if(err < 0)
            {
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

void rpmb_read_block(uint16_t blk_addr, uint8_t * data_out)
{
    int ret, dev_fd = -1;
    uint8_t key[BLFS_CRYPTO_RPMB_KEY] = BLFS_RPMB_KEY;
    uint16_t blocks_cnt = 1;

    rpmb_frame * frame_out_p;
    rpmb_frame frame_in = { .req_resp = htobe16(MMC_RPMB_READ) };

    errno = 0;
    dev_fd = open(BLFS_RPMB_DEVICE, O_RDWR);

    if(dev_fd < 0)
    {
        IFDEBUG(dzlog_warn("RPMB device "BLFS_RPMB_DEVICE" not found: %s", strerror(errno)));
        Throw(EXCEPTION_RPMB_DOES_NOT_EXIST);
    }

    /* Get block address */
    frame_in.addr = htobe16(blk_addr);

    /* Get blocks count */
    frame_out_p = calloc(sizeof(*frame_out_p), blocks_cnt);

    if(frame_out_p == NULL)
        Throw(EXCEPTION_ALLOC_FAILURE);

    /* Execute RPMB op */
    ret = do_rpmb_op(dev_fd, &frame_in, frame_out_p, blocks_cnt);

    if(ret != 0)
        Throw(EXCEPTION_RPMB_IOCTL_FAILURE);

    /* Check RPMB response */
    if(frame_out_p[blocks_cnt - 1].result != 0)
    {
        IFDEBUG(dzlog_warn("RPMB operation failed, retcode 0x%04x\n", be16toh(frame_out_p[blocks_cnt - 1].result)));
        Throw(EXCEPTION_RPMB_OP_FAILURE);
    }

    /* Verify data against key */
    uint8_t mac[BLFS_CRYPTO_RPMB_MAC_OUT];
    rpmb_frame * frame_out = &frame_out_p[0];

    crypto_auth_hmacsha256(mac, frame_out->data, sizeof(*frame_out) - offsetof(struct rpmb_frame, data), key);

    /* Compare calculated MAC and MAC from last frame */
    if(memcmp(mac, frame_out->key_mac, sizeof(mac)))
        Throw(EXCEPTION_RPMB_MAC_MISMATCH);

    /* Output */
    frame_out = &frame_out_p[0];
    assert(sizeof(frame_out->data) == BLFS_CRYPTO_RPMB_BLOCK);
    memcpy(data_out, frame_out->data, BLFS_CRYPTO_RPMB_BLOCK);

    free(frame_out_p);
    close(dev_fd);
}

void rpmb_write_block(uint16_t blk_addr, const uint8_t * data)
{
    int ret, dev_fd;
    uint8_t key[BLFS_CRYPTO_RPMB_KEY] = BLFS_RPMB_KEY;
    unsigned int cnt;

    rpmb_frame frame_out;
    rpmb_frame frame_in = {
        .req_resp    = htobe16(MMC_RPMB_WRITE),
        .block_count = htobe16(1)
    };

    errno = 0;
    dev_fd = open(BLFS_RPMB_DEVICE, O_RDWR);

    if(dev_fd < 0)
    {
        IFDEBUG(dzlog_warn("RPMB device "BLFS_RPMB_DEVICE" not found: %s", strerror(errno)));
        Throw(EXCEPTION_RPMB_DOES_NOT_EXIST);
    }

    ret = rpmb_read_counter(dev_fd, &cnt);

    /* Check RPMB response */
    if(ret != 0)
    {
        IFDEBUG(dzlog_warn("RPMB read counter operation failed mysteriously"));
        Throw(EXCEPTION_RPMB_OP_FAILURE);
    }

    frame_in.write_counter = htobe32(cnt);

    /* Get block address */
    frame_in.addr = htobe16(blk_addr);

    /* Read 256b data */
    memcpy(frame_in.data, data, BLFS_CRYPTO_RPMB_BLOCK);

    /* Calculate HMAC SHA256 */
    crypto_auth_hmacsha256(frame_in.key_mac, frame_in.data, sizeof(frame_in) - offsetof(rpmb_frame, data), key);

    /* Execute RPMB op */
    ret = do_rpmb_op(dev_fd, &frame_in, &frame_out, 1);

    if(ret != 0)
        Throw(EXCEPTION_RPMB_IOCTL_FAILURE);

    /* Check RPMB response */
    if(frame_out.result != 0)
    {
        IFDEBUG(dzlog_warn("RPMB operation failed, retcode 0x%04x\n", be16toh(frame_out.result)));
        Throw(EXCEPTION_RPMB_OP_FAILURE);
    }

    close(dev_fd);
}

int rpmb_read_counter(int dev_fd, unsigned int * cnt)
{
    int ret;
    rpmb_frame frame_in = {
        .req_resp = htobe16(MMC_RPMB_READ_CNT)
    }, frame_out;

    /* Execute RPMB op */
    ret = do_rpmb_op(dev_fd, &frame_in, &frame_out, 1);

    if(ret != 0)
        Throw(EXCEPTION_RPMB_OP_FAILURE);

    /* Check RPMB response */
    if(frame_out.result != 0)
        return be16toh(frame_out.result);

    *cnt = be32toh(frame_out.write_counter);

    return 0;
}
